//! S3 lock backend: a lease object guarded by conditional writes.
//!
//! Acquire creates the lock object with `If-None-Match: *` (atomic create). If
//! it already exists but the lease has expired, it is taken over with
//! `If-Match: <etag>` (compare-and-swap). A background task renews the lease;
//! release writes an expired payload (also under `If-Match`).

use super::{LockBackend, LockGuard, now_ms, sanitize_scope};
use crate::error::RegistryError;
use async_trait::async_trait;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(super) struct S3LockBackend {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
    lease_ms: u64,
}

struct S3LockGuard {
    coordinator: S3LockBackend,
    key: String,
    token: String,
    renew_stop_tx: tokio::sync::watch::Sender<bool>,
    renew_task: JoinHandle<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct S3LockPayload {
    token: String,
    lease_until_ms: i64,
    operation: String,
}

impl S3LockBackend {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        prefix: String,
        force_path_style: bool,
        lease_ms: u64,
    ) -> Result<Self, RegistryError> {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region));

        let endpoint_is_http = endpoint
            .as_deref()
            .map(|value| {
                value
                    .trim_start()
                    .to_ascii_lowercase()
                    .starts_with("http://")
            })
            .unwrap_or(false);
        if endpoint_is_http {
            let http_client = aws_smithy_http_client::Builder::new().build_http();
            loader = loader.http_client(http_client);
        }

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
            prefix: super::normalize_s3_prefix(&prefix),
            lease_ms,
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

    fn spawn_lease(
        &self,
        scope: &str,
        operation_name: &str,
        key: String,
        token: String,
    ) -> Box<dyn LockGuard> {
        let (renew_stop_tx, mut renew_stop_rx) = tokio::sync::watch::channel(false);
        let coordinator = self.clone();
        let key_for_task = key.clone();
        let token_for_task = token.clone();
        let renew_interval_ms = (self.lease_ms / 3).max(250);
        let scope_owned = scope.to_string();
        let operation_owned = operation_name.to_string();
        let renew_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = renew_stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(renew_interval_ms)) => {
                        if let Err(err) = coordinator.renew_once(&key_for_task, &token_for_task, &operation_owned).await {
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

        Box::new(S3LockGuard {
            coordinator: self.clone(),
            key,
            token,
            renew_stop_tx,
            renew_task,
        })
    }

    async fn renew_once(
        &self,
        key: &str,
        token: &str,
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
            Ok(_) => Ok(()),
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

#[async_trait]
impl LockBackend for S3LockBackend {
    async fn try_acquire(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<Box<dyn LockGuard>>, RegistryError> {
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

        if create_result.is_ok() {
            return Ok(Some(self.spawn_lease(scope, operation_name, key, token)));
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
            Ok(_) => Ok(Some(self.spawn_lease(scope, operation_name, key, token))),
            Err(err) if s3_is_precondition_failed(&err) => Ok(None),
            Err(_) => Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "state coordination backend unavailable",
            )),
        }
    }
}

#[async_trait]
impl LockGuard for S3LockGuard {
    async fn release(self: Box<Self>) {
        let _ = self.renew_stop_tx.send(true);
        let _ = self.renew_task.await;

        match self.coordinator.read_lock_payload(&self.key).await {
            Ok(Some((current, current_etag))) => {
                if current.token != self.token {
                    return;
                }
                let release_payload = S3LockPayload {
                    token: self.token.clone(),
                    lease_until_ms: now_ms() - 1,
                    operation: "released".to_string(),
                };
                let payload_bytes = match S3LockBackend::payload_bytes(&release_payload) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        warn!(error = ?err, lock_key = self.key.as_str(), "failed to encode s3 lock release payload");
                        return;
                    }
                };
                let mut request = self
                    .coordinator
                    .client
                    .put_object()
                    .bucket(&self.coordinator.bucket)
                    .key(&self.key)
                    .body(aws_sdk_s3::primitives::ByteStream::from(payload_bytes));
                if let Some(etag) = current_etag.as_deref() {
                    request = request.if_match(etag);
                }
                if let Err(err) = request.send().await
                    && !s3_is_precondition_failed(&err)
                {
                    warn!(error = ?err, lock_key = self.key.as_str(), "failed to release s3 state lock");
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!(error = ?err, lock_key = self.key.as_str(), "failed to read s3 state lock during release");
            }
        }
    }
}

fn s3_is_not_found(
    err: &aws_sdk_s3::error::SdkError<aws_sdk_s3::operation::get_object::GetObjectError>,
) -> bool {
    use aws_sdk_s3::error::ProvideErrorMetadata;
    matches!(
        err.as_service_error().and_then(|service| service.code()),
        Some("NoSuchKey" | "NotFound")
    )
}

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
