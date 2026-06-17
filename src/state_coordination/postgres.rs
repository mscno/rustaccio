//! Postgres lock backend: a session-scoped `pg_advisory_lock`.
//!
//! Each acquire opens a dedicated connection and takes a non-blocking
//! `pg_try_advisory_lock(<scope-hash>)`. Because advisory locks are bound to the
//! session, the lock is held for as long as the guard owns the connection and is
//! released automatically if the process crashes (the session closes). No lease
//! or renewal is required. Release calls `pg_advisory_unlock` and drops the
//! connection.

use super::LockBackend;
use super::LockGuard;
use crate::error::RegistryError;
use async_trait::async_trait;
use axum::http::StatusCode;
use tokio::task::JoinHandle;
use tokio_postgres::NoTls;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub(super) struct PostgresLockBackend {
    url: String,
}

struct PostgresLockGuard {
    client: tokio_postgres::Client,
    connection_task: JoinHandle<()>,
    lock_id: i64,
    lock_key: String,
}

impl PostgresLockBackend {
    pub(super) fn new(url: String) -> Self {
        Self { url }
    }
}

#[async_trait]
impl LockBackend for PostgresLockBackend {
    async fn try_acquire(
        &self,
        scope: &str,
        operation_name: &str,
    ) -> Result<Option<Box<dyn LockGuard>>, RegistryError> {
        let (client, connection) =
            tokio_postgres::connect(&self.url, NoTls)
                .await
                .map_err(|_| {
                    RegistryError::http(
                        StatusCode::BAD_GATEWAY,
                        "state coordination backend unavailable",
                    )
                })?;
        let connection_task = tokio::spawn(async move {
            if let Err(err) = connection.await {
                debug!(error = ?err, "postgres state lock connection terminated");
            }
        });

        let lock_id = advisory_lock_id(scope);
        let acquired: bool = match client
            .query_one("SELECT pg_try_advisory_lock($1)", &[&lock_id])
            .await
        {
            Ok(row) => row.get(0),
            Err(_) => {
                connection_task.abort();
                return Err(RegistryError::http(
                    StatusCode::BAD_GATEWAY,
                    "state coordination backend unavailable",
                ));
            }
        };

        if !acquired {
            // Held by another session; drop our connection and let the caller retry.
            drop(client);
            connection_task.abort();
            return Ok(None);
        }

        let lock_key = format!("pg_advisory:{lock_id}");
        debug!(
            scope,
            operation = operation_name,
            lock_key = lock_key.as_str(),
            "acquired state coordination lock"
        );
        Ok(Some(Box::new(PostgresLockGuard {
            client,
            connection_task,
            lock_id,
            lock_key,
        })))
    }
}

#[async_trait]
impl LockGuard for PostgresLockGuard {
    async fn release(self: Box<Self>) {
        // Explicit unlock; even if this fails, dropping the connection ends the
        // session and Postgres releases the advisory lock.
        if let Err(err) = self
            .client
            .query("SELECT pg_advisory_unlock($1)", &[&self.lock_id])
            .await
        {
            warn!(error = ?err, lock_key = self.lock_key.as_str(), "failed to release postgres state lock");
        }
        drop(self.client);
        self.connection_task.abort();
    }
}

/// Map a scope string to a stable 64-bit advisory-lock id.
///
/// Uses FNV-1a so the id is identical across processes and rustc versions — all
/// instances must agree on the id for the same scope. (A 64-bit space makes
/// cross-scope collisions vanishingly unlikely; a collision would only cause two
/// unrelated scopes to serialize, never a correctness issue.)
fn advisory_lock_id(scope: &str) -> i64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in scope.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash as i64
}

#[cfg(test)]
mod tests {
    use super::advisory_lock_id;

    #[test]
    fn advisory_lock_id_is_stable_and_distinct() {
        // Stable for a given scope (must match across instances).
        assert_eq!(
            advisory_lock_id("package:left-pad"),
            advisory_lock_id("package:left-pad")
        );
        // Different scopes generally map to different ids.
        assert_ne!(advisory_lock_id("package:a"), advisory_lock_id("package:b"));
    }
}
