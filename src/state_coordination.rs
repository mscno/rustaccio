use crate::error::RegistryError;
use axum::http::StatusCode;
#[cfg(feature = "redis")]
use redis::Script;
#[cfg(feature = "redis")]
use std::time::Duration;
#[cfg(feature = "redis")]
use tokio::task::JoinHandle;
#[cfg(feature = "redis")]
use tracing::{debug, warn};
#[cfg(feature = "redis")]
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
        }
    }
}

pub enum StateWriteCoordinator {
    None,
    #[cfg(feature = "redis")]
    Redis(RedisStateWriteCoordinator),
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
            other => Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("unsupported RUSTACCIO_STATE_COORDINATION_BACKEND: {other}"),
            )),
        }
    }

    pub async fn run_exclusive<T, F, Fut>(
        &self,
        #[cfg_attr(not(feature = "redis"), allow(unused_variables))] operation_name: &str,
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
                let lease = coordinator.acquire(operation_name).await?;
                let result = operation().await;
                if let Err(err) = coordinator.release(lease).await {
                    warn!(error = ?err, operation = operation_name, "failed to release state lock");
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

    async fn acquire(
        &self,
        operation_name: &str,
    ) -> Result<Option<RedisStateLease>, RegistryError> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.acquire_timeout_ms);
        loop {
            match self.try_acquire_once(operation_name).await {
                Ok(Some(lease)) => return Ok(Some(lease)),
                Ok(None) => {}
                Err(err) if self.fail_open => {
                    warn!(
                        error = ?err,
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
        operation_name: &str,
    ) -> Result<Option<RedisStateLease>, RegistryError> {
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
            .arg(&self.lock_key)
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
        let lock_key = self.lock_key.clone();
        let renew_token = token.clone();
        let lease_ms = self.lease_ms;
        let renew_interval_ms = (lease_ms / 3).max(250);
        let operation = operation_name.to_string();
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
                                warn!(error=?err, operation = operation.as_str(), "failed to renew state lock connection");
                                continue;
                            }
                        };
                        let renewed: Result<i64, _> = script
                            .key(&lock_key)
                            .arg(&renew_token)
                            .arg(lease_ms as i64)
                            .invoke_async(&mut conn)
                            .await;
                        if let Ok(0) = renewed {
                            warn!(operation = operation.as_str(), "state lock token no longer owns lock during renewal");
                            break;
                        }
                    }
                }
            }
        });

        debug!(
            operation = operation_name,
            lock_key = self.lock_key.as_str(),
            "acquired state coordination lock"
        );
        Ok(Some(RedisStateLease {
            lock_key: self.lock_key.clone(),
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
