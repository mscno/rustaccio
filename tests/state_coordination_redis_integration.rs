#![cfg(feature = "redis")]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use redis::aio::MultiplexedConnection;
use rustaccio::{
    config::{Config, TarballStorageBackend, TarballStorageConfig},
    runtime,
};
use serde_json::json;
use std::{collections::HashMap, future::Future, sync::OnceLock, time::Duration};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

mod common;

static ENV_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn base_config(data_dir: std::path::PathBuf) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![rustaccio::acl::PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        publish_check_owners: false,
        max_body_size: 50 * 1024 * 1024,
        audit_enabled: true,
        url_prefix: "/".to_string(),
        trust_proxy: false,
        keep_alive_timeout_secs: None,
        log_level: "info".to_string(),
        auth_plugin: None,
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    }
}

fn env_lock() -> &'static tokio::sync::Mutex<()> {
    ENV_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn with_env<T, F>(vars: &[(&str, Option<&str>)], run: F) -> T
where
    F: Future<Output = T>,
{
    let _guard = env_lock().lock().await;
    let previous = vars
        .iter()
        .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
        .collect::<Vec<_>>();

    for (key, value) in vars {
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    let result = run.await;

    for (key, value) in previous {
        unsafe {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }
    result
}

fn redis_it_url() -> String {
    std::env::var("RUSTACCIO_REDIS_IT_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:56379/".to_string())
}

async fn app_with_env(cfg: &Config) -> axum::Router {
    let state = runtime::build_state(cfg, None).await.expect("state");
    rustaccio::app::build_router(state)
}

async fn redis_connection(redis_url: &str) -> MultiplexedConnection {
    let client = redis::Client::open(redis_url).expect("redis url");
    client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection")
}

async fn wait_for_redis(redis_url: &str) {
    for _ in 0..80 {
        if let Ok(client) = redis::Client::open(redis_url)
            && let Ok(mut conn) = client.get_multiplexed_async_connection().await
        {
            let ping = redis::cmd("PING").query_async::<String>(&mut conn).await;
            if ping.is_ok() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("redis endpoint was not reachable in time");
}

fn publish_manifest(name: &str) -> serde_json::Value {
    json!({
        "_id": name,
        "name": name,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": name,
                "version": "1.0.0",
                "dist": { "tarball": format!("http://localhost:4873/{name}/-/{name}-1.0.0.tgz") }
            }
        },
        "_attachments": {
            format!("{name}-1.0.0.tgz"): {
                "content_type": "application/octet-stream",
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"abc"),
                "length": 3
            }
        }
    })
}

/// Perform an authenticated package publish, which exercises a coordinated
/// state-write. The bearer token is treated as the username by the mock auth
/// service.
async fn publish_package(app: &axum::Router, token: &str, package: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/{package}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&publish_manifest(package)).expect("payload"),
        ))
        .expect("request");
    app.clone().oneshot(req).await.expect("response").status()
}

#[tokio::test]
#[ignore = "requires managed profile integration harness; local profile forbids redis state coordination"]
async fn state_coordination_fail_open_allows_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("redis")),
            (
                "RUSTACCIO_STATE_COORDINATION_REDIS_URL",
                Some("redis://127.0.0.1:1/"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("true")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-open-{}", Uuid::new_v4().as_simple());
            let pkg = format!("state-open-pkg-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::CREATED
            );
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires managed profile integration harness; local profile forbids redis state coordination"]
async fn state_coordination_fail_closed_rejects_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("redis")),
            (
                "RUSTACCIO_STATE_COORDINATION_REDIS_URL",
                Some("redis://127.0.0.1:1/"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-closed-{}", Uuid::new_v4().as_simple());
            let pkg = format!("state-closed-pkg-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::BAD_GATEWAY
            );
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires local Redis (`just governance-up`)"]
async fn state_coordination_redis_lock_timeout_when_key_is_held() {
    let redis_url = redis_it_url();
    wait_for_redis(&redis_url).await;
    let lock_key = format!("rustaccio:test:state-lock:{}", Uuid::new_v4().as_simple());
    let scoped_lock_key = format!("{lock_key}:state");

    let mut conn = redis_connection(&redis_url).await;
    let _: Option<String> = redis::cmd("SET")
        .arg(&scoped_lock_key)
        .arg("held")
        .arg("NX")
        .arg("PX")
        .arg(10_000)
        .query_async(&mut conn)
        .await
        .expect("set lock");

    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("redis")),
            (
                "RUSTACCIO_STATE_COORDINATION_REDIS_URL",
                Some(redis_url.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_LOCK_KEY",
                Some(lock_key.as_str()),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("400"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", Some("50")),
        ],
        async {
            let auth = common::start_token_echo_auth().await;
            let dir = TempDir::new().expect("dir");
            let mut cfg = base_config(dir.path().to_path_buf());
            cfg.auth_plugin = Some(common::external_auth_plugin(&auth.uri()));
            let app = app_with_env(&cfg).await;
            let user = format!("state-lock-{}", Uuid::new_v4().as_simple());
            let pkg = format!("state-lock-pkg-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                publish_package(&app, &user, &pkg).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
        },
    )
    .await;
}
