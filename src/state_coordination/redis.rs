//! Redis lock backend: `SET key token NX PX lease` with Lua-guarded renew and
//! release (single-node lock, not Redlock). A background task renews the lease.

use super::{LockBackend, LockGuard, sanitize_scope};
use crate::error::RegistryError;
use async_trait::async_trait;
use axum::http::StatusCode;
use redis::Script;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(super) struct RedisLockBackend {
    client: redis::Client,
    lock_key: String,
    lease_ms: u64,
}

struct RedisLockGuard {
    client: redis::Client,
    lock_key: String,
    token: String,
    renew_stop_tx: tokio::sync::watch::Sender<bool>,
    renew_task: JoinHandle<()>,
}

impl RedisLockBackend {
    pub(super) fn new(
        redis_url: String,
        lock_key: String,
        lease_ms: u64,
    ) -> Result<Self, RegistryError> {
        let client = redis::Client::open(redis_url).map_err(|_| {
            RegistryError::http(StatusCode::INTERNAL_SERVER_ERROR, "invalid redis url")
        })?;
        Ok(Self {
            client,
            lock_key,
            lease_ms,
        })
    }

    fn scoped_lock_key(&self, scope: &str) -> String {
        format!("{}:{}", self.lock_key, sanitize_scope(scope))
    }
}

#[async_trait]
impl LockBackend for RedisLockBackend {
    async fn try_acquire(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<Box<dyn LockGuard>>, RegistryError> {
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
        Ok(Some(Box::new(RedisLockGuard {
            client: self.client.clone(),
            lock_key,
            token,
            renew_stop_tx,
            renew_task,
        })))
    }
}

#[async_trait]
impl LockGuard for RedisLockGuard {
    async fn release(self: Box<Self>) {
        let _ = self.renew_stop_tx.send(true);
        let _ = self.renew_task.await;

        let mut conn = match self.client.get_multiplexed_async_connection().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!(error = ?err, lock_key = self.lock_key.as_str(), "failed to connect to release redis state lock");
                return;
            }
        };
        let script = Script::new(
            r#"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
              return redis.call('DEL', KEYS[1])
            else
              return 0
            end
            "#,
        );
        if let Err(err) = script
            .key(&self.lock_key)
            .arg(&self.token)
            .invoke_async::<i64>(&mut conn)
            .await
        {
            warn!(error = ?err, lock_key = self.lock_key.as_str(), "failed to release redis state lock");
        }
    }
}
