#![cfg(feature = "postgres")]

//! Integration test for the Postgres `pg_advisory_lock` state-coordination
//! backend. Exercises the public `StateWriteCoordinator` directly (no managed
//! profile harness needed), verifying per-scope mutual exclusion across holders.

use rustaccio::{error::RegistryError, state_coordination::StateWriteCoordinator};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn env_lock() -> &'static tokio::sync::Mutex<()> {
    ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

fn postgres_it_url() -> String {
    std::env::var("RUSTACCIO_POSTGRES_IT_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/rustaccio".to_string())
}

async fn coordinator() -> StateWriteCoordinator {
    let url = postgres_it_url();
    unsafe {
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_BACKEND", "postgres");
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_POSTGRES_URL", &url);
        // Keep the contention check fast (clamped minimum is 1000ms).
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS", "1000");
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", "50");
        std::env::set_var("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", "false");
    }
    StateWriteCoordinator::from_env()
        .await
        .expect("build postgres coordinator")
}

#[tokio::test]
#[ignore = "requires local Postgres (`just governance-up`)"]
async fn postgres_advisory_lock_serializes_same_scope() {
    let _guard = env_lock().lock().await;
    let coordinator = Arc::new(coordinator().await);
    let scope = format!("pg-lock-it:{}", Uuid::new_v4().as_simple());

    // Holder acquires the lock and keeps it until told to release.
    let (acquired_tx, acquired_rx) = oneshot::channel::<()>();
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let holder_coordinator = coordinator.clone();
    let holder_scope = scope.clone();
    let holder = tokio::spawn(async move {
        holder_coordinator
            .run_exclusive_scoped(&holder_scope, "hold", || async move {
                acquired_tx.send(()).expect("signal acquired");
                release_rx.await.expect("await release");
                Ok::<(), RegistryError>(())
            })
            .await
    });

    acquired_rx.await.expect("holder acquired lock");

    // A second attempt on the SAME scope must fail to acquire within the timeout.
    let contended = coordinator
        .run_exclusive_scoped(&scope, "contend", || async { Ok::<(), RegistryError>(()) })
        .await;
    assert!(
        contended.is_err(),
        "same-scope acquire should time out while the lock is held"
    );

    // A DIFFERENT scope is unaffected and proceeds immediately.
    let other_scope = format!("{scope}:other");
    coordinator
        .run_exclusive_scoped(&other_scope, "independent", || async {
            Ok::<(), RegistryError>(())
        })
        .await
        .expect("different scope should not be blocked");

    // Release the holder, then the same scope becomes acquirable again.
    release_tx.send(()).expect("send release");
    holder
        .await
        .expect("holder task joined")
        .expect("holder operation ok");

    // Give Postgres a moment to drop the holder's session lock.
    tokio::time::sleep(Duration::from_millis(100)).await;
    coordinator
        .run_exclusive_scoped(&scope, "after-release", || async {
            Ok::<(), RegistryError>(())
        })
        .await
        .expect("same scope acquirable after release");
}
