use crate::error::RegistryError;
use axum::http::StatusCode;
#[cfg(feature = "redis")]
use redis::Script;
#[cfg(feature = "s3")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "s3")]
use std::sync::Arc;
#[cfg(any(feature = "redis", feature = "s3"))]
use std::time::Duration;
#[cfg(feature = "s3")]
use tokio::sync::Mutex;
#[cfg(any(feature = "redis", feature = "s3"))]
use tokio::task::JoinHandle;
#[cfg(any(feature = "redis", feature = "s3"))]
use tracing::{debug, warn};
#[cfg(any(feature = "redis", feature = "s3"))]
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
struct StateCoordinationConfig {
    backend: String,
    redis_url: Option<String>,
    lock_key: String,
    lease_ms: u64,
    acquire_timeout_ms: u64,
    poll_interval_ms: u64,
    fail_open: bool,
    s3_bucket: Option<String>,
    s3_region: String,
    s3_endpoint: Option<String>,
    s3_access_key_id: Option<String>,
    s3_secret_access_key: Option<String>,
    s3_prefix: String,
    s3_force_path_style: bool,
}

impl Default for StateCoordinationConfig {
    fn default() -> Self {
        Self {
            backend: "none".to_string(),
            redis_url: None,
            lock_key: "rustaccio:state:lock".to_string(),
            lease_ms: 5_000,
            acquire_timeout_ms: 15_000,
            poll_interval_ms: 100,
            fail_open: false,
            s3_bucket: None,
            s3_region: "us-east-1".to_string(),
            s3_endpoint: None,
            s3_access_key_id: None,
            s3_secret_access_key: None,
            s3_prefix: "rustaccio/state-locks/".to_string(),
            s3_force_path_style: false,
        }
    }
}

impl StateCoordinationConfig {
    fn from_env() -> Self {
        Self {
            backend: env_value("RUSTACCIO_STATE_COORDINATION_BACKEND")
                .unwrap_or_else(|| "none".to_string()),
            redis_url: env_value("RUSTACCIO_STATE_COORDINATION_REDIS_URL"),
            lock_key: env_value("RUSTACCIO_STATE_COORDINATION_LOCK_KEY")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "rustaccio:state:lock".to_string()),
            lease_ms: parse_u64_env("RUSTACCIO_STATE_COORDINATION_LEASE_MS", 5_000)
                .clamp(1_000, 300_000),
            acquire_timeout_ms: parse_u64_env(
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                15_000,
            )
            .clamp(1_000, 600_000),
            poll_interval_ms: parse_u64_env("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", 100)
                .clamp(10, 5_000),
            fail_open: parse_bool_env("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", false),
            s3_bucket: env_value("RUSTACCIO_STATE_COORDINATION_S3_BUCKET")
                .filter(|value| !value.trim().is_empty()),
            s3_region: env_value("RUSTACCIO_STATE_COORDINATION_S3_REGION")
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "us-east-1".to_string()),
            s3_endpoint: env_value("RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT")
                .filter(|value| !value.trim().is_empty()),
            s3_access_key_id: env_value("RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID")
                .filter(|value| !value.trim().is_empty()),
            s3_secret_access_key: env_value("RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY")
                .filter(|value| !value.trim().is_empty()),
            s3_prefix: normalize_s3_prefix(
                env_value("RUSTACCIO_STATE_COORDINATION_S3_PREFIX")
                    .as_deref()
                    .unwrap_or("rustaccio/state-locks/"),
            ),
            s3_force_path_style: parse_bool_env(
                "RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE",
                false,
            ),
        }
    }
}

pub enum StateWriteCoordinator {
    None,
    #[cfg(feature = "redis")]
    Redis(RedisStateWriteCoordinator),
    #[cfg(feature = "s3")]
    S3(S3StateWriteCoordinator),
}

impl StateWriteCoordinator {
    pub async fn from_env() -> Result<Self, RegistryError> {
        let cfg = StateCoordinationConfig::from_env();
        match cfg.backend.as_str() {
            "none" | "" => Ok(Self::None),
            "redis" => {
                #[cfg(feature = "redis")]
                {
                    let Some(redis_url) = cfg.redis_url.clone() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "RUSTACCIO_STATE_COORDINATION_REDIS_URL is required when RUSTACCIO_STATE_COORDINATION_BACKEND=redis",
                        ));
                    };
                    Ok(Self::Redis(RedisStateWriteCoordinator::new(
                        redis_url,
                        cfg.lock_key,
                        cfg.lease_ms,
                        cfg.acquire_timeout_ms,
                        cfg.poll_interval_ms,
                        cfg.fail_open,
                    )?))
                }
                #[cfg(not(feature = "redis"))]
                {
                    Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "RUSTACCIO_STATE_COORDINATION_BACKEND=redis requires rustaccio build with `redis` feature",
                    ))
                }
            }
            "s3" => {
                #[cfg(feature = "s3")]
                {
                    let Some(bucket) = cfg.s3_bucket.clone() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "RUSTACCIO_STATE_COORDINATION_S3_BUCKET is required when RUSTACCIO_STATE_COORDINATION_BACKEND=s3",
                        ));
                    };
                    Ok(Self::S3(
                        S3StateWriteCoordinator::new(
                            bucket,
                            cfg.s3_region.clone(),
                            cfg.s3_endpoint.clone(),
                            cfg.s3_access_key_id.clone(),
                            cfg.s3_secret_access_key.clone(),
                            cfg.s3_prefix.clone(),
                            cfg.s3_force_path_style,
                            cfg.lease_ms,
                            cfg.acquire_timeout_ms,
                            cfg.poll_interval_ms,
                            cfg.fail_open,
                        )
                        .await?,
                    ))
                }
                #[cfg(not(feature = "s3"))]
                {
                    Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "RUSTACCIO_STATE_COORDINATION_BACKEND=s3 requires rustaccio build with `s3` feature",
                    ))
                }
            }
            other => Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unsupported RUSTACCIO_STATE_COORDINATION_BACKEND: {other}"),
            )),
        }
    }

    pub async fn run_exclusive<T, F, Fut>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, RegistryError>>,
    {
        self.run_exclusive_scoped("global", operation_name, operation)
            .await
    }

    pub async fn run_exclusive_scoped<T, F, Fut>(
        &self,
        #[cfg_attr(not(any(feature = "redis", feature = "s3")), allow(unused_variables))]
        scope: &str,
        #[cfg_attr(not(any(feature = "redis", feature = "s3")), allow(unused_variables))]
        operation_name: &str,
        operation: F,
    ) -> Result<T, RegistryError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, RegistryError>>,
    {
        match self {
            Self::None => operation().await,
            #[cfg(feature = "redis")]
            Self::Redis(coordinator) => {
                let lease = coordinator.acquire(scope, operation_name).await?;
                let result = operation().await;
                if let Err(err) = coordinator.release(lease).await {
                    warn!(
                        error = ?err,
                        scope,
                        operation = operation_name,
                        "failed to release state lock"
                    );
                }
                result
            }
            #[cfg(feature = "s3")]
            Self::S3(coordinator) => {
                let lease = coordinator.acquire(scope, operation_name).await?;
                let result = operation().await;
                if let Err(err) = coordinator.release(lease).await {
                    warn!(
                        error = ?err,
                        scope,
                        operation = operation_name,
                        "failed to release state lock"
                    );
                }
                result
            }
        }
    }
}

#[cfg(feature = "redis")]
#[derive(Debug, Clone)]
pub struct RedisStateWriteCoordinator {
    client: redis::Client,
    lock_key: String,
    lease_ms: u64,
    acquire_timeout_ms: u64,
    poll_interval_ms: u64,
    fail_open: bool,
}

#[cfg(feature = "redis")]
struct RedisStateLease {
    lock_key: String,
    token: String,
    renew_stop_tx: tokio::sync::watch::Sender<bool>,
    renew_task: JoinHandle<()>,
}

#[cfg(feature = "redis")]
impl RedisStateWriteCoordinator {
    fn new(
        redis_url: String,
        lock_key: String,
        lease_ms: u64,
        acquire_timeout_ms: u64,
        poll_interval_ms: u64,
        fail_open: bool,
    ) -> Result<Self, RegistryError> {
        let client = redis::Client::open(redis_url).map_err(|_| {
            RegistryError::http(StatusCode::INTERNAL_SERVER_ERROR, "invalid redis url")
        })?;
        Ok(Self {
            client,
            lock_key,
            lease_ms,
            acquire_timeout_ms,
            poll_interval_ms,
            fail_open,
        })
    }

    fn scoped_lock_key(&self, scope: &str) -> String {
        format!("{}:{}", self.lock_key, sanitize_scope(scope))
    }

    async fn acquire(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<RedisStateLease>, RegistryError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.acquire_timeout_ms);
        loop {
            match self.try_acquire_once(scope, operation_name).await {
                Ok(Some(lease)) => return Ok(Some(lease)),
                Ok(None) => {}
                Err(err) if self.fail_open => {
                    warn!(
                        error = ?err,
                        scope,
                        operation = operation_name,
                        "state coordination backend unavailable; continuing without lock (fail-open)"
                    );
                    return Ok(None);
                }
                Err(err) => return Err(err),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(RegistryError::http(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "state coordination lock timeout",
                ));
            }
            tokio::time::sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }
    }

    async fn try_acquire_once(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<RedisStateLease>, RegistryError> {
        let lock_key = self.scoped_lock_key(scope);
        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                )
            })?;
        let token = Uuid::new_v4().to_string();
        let result = redis::cmd("SET")
            .arg(&lock_key)
            .arg(&token)
            .arg("NX")
            .arg("PX")
            .arg(self.lease_ms as i64)
            .query_async::<Option<String>>(&mut conn)
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                )
            })?;

        if result.is_none() {
            return Ok(None);
        }

        let (renew_stop_tx, mut renew_stop_rx) = tokio::sync::watch::channel(false);
        let client = self.client.clone();
        let renew_lock_key = lock_key.clone();
        let renew_token = token.clone();
        let lease_ms = self.lease_ms;
        let renew_interval_ms = (lease_ms / 3).max(250);
        let operation = operation_name.to_string();
        let scope_owned = scope.to_string();
        let renew_task = tokio::spawn(async move {
            let script = Script::new(
                r#"
                if redis.call('GET', KEYS[1]) == ARGV[1] then
                  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
                else
                  return 0
                end
                "#,
            );
            loop {
                tokio::select! {
                    _ = renew_stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(renew_interval_ms)) => {
                        let mut conn = match client.get_multiplexed_async_connection().await {
                            Ok(conn) => conn,
                            Err(err) => {
                                warn!(error=?err, scope = scope_owned.as_str(), operation = operation.as_str(), "failed to renew state lock connection");
                                continue;
                            }
                        };
                        let renewed: Result<i64, _> = script
                            .key(&renew_lock_key)
                            .arg(&renew_token)
                            .arg(lease_ms as i64)
                            .invoke_async(&mut conn)
                            .await;
                        if let Ok(0) = renewed {
                            warn!(scope = scope_owned.as_str(), operation = operation.as_str(), "state lock token no longer owns lock during renewal");
                            break;
                        }
                    }
                }
            }
        });

        debug!(
            scope,
            operation = operation_name,
            lock_key = lock_key.as_str(),
            "acquired state coordination lock"
        );
        Ok(Some(RedisStateLease {
            lock_key,
            token,
            renew_stop_tx,
            renew_task,
        }))
    }

    async fn release(&self, lease: Option<RedisStateLease>) -> Result<(), RegistryError> {
        let Some(lease) = lease else {
            return Ok(());
        };

        let _ = lease.renew_stop_tx.send(true);
        let _ = lease.renew_task.await;

        let mut conn = self
            .client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                )
            })?;
        let script = Script::new(
            r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
              return redis.call('DEL', KEYS[1])
            else
              return 0
            end
            "#,
        );
        let _: i64 = script
            .key(&lease.lock_key)
            .arg(&lease.token)
            .invoke_async(&mut conn)
            .await
            .map_err(|_| {
                RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                )
            })?;
        Ok(())
    }
}

#[cfg(feature = "s3")]
#[derive(Debug, Clone)]
pub struct S3StateWriteCoordinator {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
    lease_ms: u64,
    acquire_timeout_ms: u64,
    poll_interval_ms: u64,
    fail_open: bool,
}

#[cfg(feature = "s3")]
struct S3StateLease {
    key: String,
    token: String,
    etag: Arc<Mutex<Option<String>>>,
    renew_stop_tx: tokio::sync::watch::Sender<bool>,
    renew_task: JoinHandle<()>,
}

#[cfg(feature = "s3")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct S3LockPayload {
    token: String,
    lease_until_ms: i64,
    operation: String,
}

#[cfg(feature = "s3")]
impl S3StateWriteCoordinator {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        prefix: String,
        force_path_style: bool,
        lease_ms: u64,
        acquire_timeout_ms: u64,
        poll_interval_ms: u64,
        fail_open: bool,
    ) -> Result<Self, RegistryError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region));

        if let (Some(access_key), Some(secret_key)) = (access_key_id, secret_access_key) {
            loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "rustaccio-state-coordination",
            ));
        }

        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(endpoint) = endpoint {
            builder = builder.endpoint_url(endpoint);
        }
        if force_path_style {
            builder = builder.force_path_style(true);
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket,
            prefix: normalize_s3_prefix(&prefix),
            lease_ms,
            acquire_timeout_ms,
            poll_interval_ms,
            fail_open,
        })
    }

    fn scoped_lock_key(&self, scope: &str) -> String {
        format!("{}{}.lock", self.prefix, sanitize_scope(scope))
    }

    fn build_payload(&self, token: String, operation_name: &str) -> S3LockPayload {
        S3LockPayload {
            token,
            lease_until_ms: now_ms() + self.lease_ms as i64,
            operation: operation_name.to_string(),
        }
    }

    fn payload_bytes(payload: &S3LockPayload) -> Result<Vec<u8>, RegistryError> {
        serde_json::to_vec(payload).map_err(|_| RegistryError::Internal)
    }

    async fn acquire(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<S3StateLease>, RegistryError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.acquire_timeout_ms);
        loop {
            match self.try_acquire_once(scope, operation_name).await {
                Ok(Some(lease)) => return Ok(Some(lease)),
                Ok(None) => {}
                Err(err) if self.fail_open => {
                    warn!(
                        error = ?err,
                        scope,
                        operation = operation_name,
                        "state coordination backend unavailable; continuing without lock (fail-open)"
                    );
                    return Ok(None);
                }
                Err(err) => return Err(err),
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(RegistryError::http(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "state coordination lock timeout",
                ));
            }
            tokio::time::sleep(Duration::from_millis(self.poll_interval_ms)).await;
        }
    }

    async fn try_acquire_once(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<S3StateLease>, RegistryError> {
        let key = self.scoped_lock_key(scope);
        let token = Uuid::new_v4().to_string();
        let payload = self.build_payload(token.clone(), operation_name);
        let payload_bytes = Self::payload_bytes(&payload)?;

        let create_result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .if_none_match("*")
            .body(aws_sdk_s3::primitives::ByteStream::from(
                payload_bytes.clone(),
            ))
            .send()
            .await;

        if let Ok(output) = create_result {
            return Ok(Some(self.spawn_lease(
                scope,
                operation_name,
                key,
                token,
                output.e_tag().map(str::to_string),
            )));
        }

        let err = create_result.expect_err("handled success branch");
        if !s3_is_precondition_failed(&err) {
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            ));
        }

        let Some((current, current_etag)) = self.read_lock_payload(&key).await? else {
            return Ok(None);
        };
        if current.lease_until_ms > now_ms() {
            return Ok(None);
        }

        let mut takeover = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(aws_sdk_s3::primitives::ByteStream::from(payload_bytes));
        if let Some(etag) = current_etag.as_deref() {
            takeover = takeover.if_match(etag);
        }
        match takeover.send().await {
            Ok(output) => Ok(Some(self.spawn_lease(
                scope,
                operation_name,
                key,
                token,
                output.e_tag().map(str::to_string),
            ))),
            Err(err) if s3_is_precondition_failed(&err) => Ok(None),
            Err(_) => Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            )),
        }
    }

    fn spawn_lease(
        &self,
        scope: &str,
        operation_name: &str,
        key: String,
        token: String,
        etag: Option<String>,
    ) -> S3StateLease {
        let (renew_stop_tx, mut renew_stop_rx) = tokio::sync::watch::channel(false);
        let coordinator = self.clone();
        let key_for_task = key.clone();
        let token_for_task = token.clone();
        let etag_cell = Arc::new(Mutex::new(etag));
        let etag_for_task = etag_cell.clone();
        let renew_interval_ms = (self.lease_ms / 3).max(250);
        let scope_owned = scope.to_string();
        let operation_owned = operation_name.to_string();
        let renew_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = renew_stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(renew_interval_ms)) => {
                        if let Err(err) = coordinator.renew_once(&key_for_task, &token_for_task, &etag_for_task, &operation_owned).await {
                            warn!(error = ?err, scope = scope_owned.as_str(), operation = operation_owned.as_str(), "failed to renew s3 state lock");
                            break;
                        }
                    }
                }
            }
        });

        debug!(
            scope,
            operation = operation_name,
            lock_key = key.as_str(),
            "acquired state coordination lock"
        );

        S3StateLease {
            key,
            token,
            etag: etag_cell,
            renew_stop_tx,
            renew_task,
        }
    }

    async fn renew_once(
        &self,
        key: &str,
        token: &str,
        etag: &Arc<Mutex<Option<String>>>,
        operation_name: &str,
    ) -> Result<(), RegistryError> {
        let Some((payload, current_etag)) = self.read_lock_payload(key).await? else {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                "state coordination lock disappeared",
            ));
        };
        if payload.token != token {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                "state coordination lock ownership lost",
            ));
        }

        let next = self.build_payload(token.to_string(), operation_name);
        let mut request = self.client.put_object().bucket(&self.bucket).key(key).body(
            aws_sdk_s3::primitives::ByteStream::from(Self::payload_bytes(&next)?),
        );
        if let Some(etag_value) = current_etag.as_deref() {
            request = request.if_match(etag_value);
        }
        match request.send().await {
            Ok(output) => {
                let mut guard = etag.lock().await;
                *guard = output.e_tag().map(str::to_string);
                Ok(())
            }
            Err(err) if s3_is_precondition_failed(&err) => Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                "state coordination lock ownership lost",
            )),
            Err(_) => Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            )),
        }
    }

    async fn release(&self, lease: Option<S3StateLease>) -> Result<(), RegistryError> {
        let Some(lease) = lease else {
            return Ok(());
        };
        let _ = lease.renew_stop_tx.send(true);
        let _ = lease.renew_task.await;

        let Some((current, current_etag)) = self.read_lock_payload(&lease.key).await? else {
            return Ok(());
        };
        if current.token != lease.token {
            return Ok(());
        }

        let _last_seen_etag = lease.etag.lock().await.clone();
        let release_payload = S3LockPayload {
            token: lease.token,
            lease_until_ms: now_ms() - 1,
            operation: "released".to_string(),
        };
        let mut request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&lease.key)
            .body(aws_sdk_s3::primitives::ByteStream::from(
                Self::payload_bytes(&release_payload)?,
            ));
        if let Some(etag) = current_etag.as_deref() {
            request = request.if_match(etag);
        }
        match request.send().await {
            Ok(_) => Ok(()),
            Err(err) if s3_is_precondition_failed(&err) => Ok(()),
            Err(_) => Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            )),
        }
    }

    async fn read_lock_payload(
        &self,
        key: &str,
    ) -> Result<Option<(S3LockPayload, Option<String>)>, RegistryError> {
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) if s3_is_not_found(&err) => return Ok(None),
            Err(_) => {
                return Err(RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                ));
            }
        };

        let etag = response.e_tag().map(str::to_string);
        let bytes = response.body.collect().await.map_err(|_| {
            RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            )
        })?;
        let payload = serde_json::from_slice::<S3LockPayload>(&bytes.to_vec()).map_err(|_| {
            RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination lock payload invalid",
            )
        })?;
        Ok(Some((payload, etag)))
    }
}

#[cfg(feature = "s3")]
fn s3_is_not_found(
    err: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> bool {
    use aws_sdk_s3::error::ProvideErrorMetadata;
    matches!(
        err.as_service_error().and_then(|service| service.code()),
        Some("NoSuchKey" | "NotFound")
    )
}

#[cfg(feature = "s3")]
fn s3_is_precondition_failed<E>(err: &aws_sdk_s3::error::SdkError<E>) -> bool
where
    E: aws_sdk_s3::error::ProvideErrorMetadata,
{
    let Some(service_error) = err.as_service_error() else {
        return false;
    };
    matches!(
        service_error.code(),
        Some("PreconditionFailed" | "ConditionalRequestConflict")
    )
}

#[cfg(any(feature = "redis", feature = "s3"))]
fn sanitize_scope(scope: &str) -> String {
    scope
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect::<String>()
}

fn normalize_s3_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

#[cfg(feature = "s3")]
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

fn parse_u64_env(key: &str, default: u64) -> u64 {
    env_value(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    env_value(key)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}
