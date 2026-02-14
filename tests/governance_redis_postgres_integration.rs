#![cfg(all(feature = "redis", feature = "postgres"))]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use redis::aio::MultiplexedConnection;
use rustaccio::{
    config::{AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig},
    runtime,
};
use serde_json::json;
use std::{collections::HashMap, future::Future, sync::OnceLock, time::Duration};
use tempfile::TempDir;
use tokio_postgres::NoTls;
use tower::ServiceExt;
use uuid::Uuid;

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
        web_login: false,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        max_body_size: 50 * 1024 * 1024,
        audit_enabled: true,
        url_prefix: "/".to_string(),
        trust_proxy: false,
        keep_alive_timeout_secs: None,
        log_level: "info".to_string(),
        auth_plugin: AuthPluginConfig {
            backend: AuthBackend::Local,
            external_mode: false,
            http: None,
        },
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

fn postgres_it_url() -> String {
    std::env::var("RUSTACCIO_POSTGRES_IT_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/rustaccio".to_string())
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

async fn reset_redis(redis_url: &str) {
    let mut conn = redis_connection(redis_url).await;
    redis::cmd("FLUSHDB")
        .query_async::<String>(&mut conn)
        .await
        .expect("flush redis");
}

async fn postgres_client(postgres_url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(postgres_url, NoTls)
        .await
        .expect("postgres connect");
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            panic!("postgres connection failed: {err}");
        }
    });
    client
}

async fn wait_for_postgres(postgres_url: &str) {
    for _ in 0..80 {
        if let Ok((client, connection)) = tokio_postgres::connect(postgres_url, NoTls).await {
            tokio::spawn(async move {
                let _ = connection.await;
            });
            if client.simple_query("SELECT 1").await.is_ok() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("postgres endpoint was not reachable in time");
}

async fn reset_postgres(postgres_url: &str) {
    let client = postgres_client(postgres_url).await;
    client
        .batch_execute(
            "DROP TABLE IF EXISTS rustaccio_quota_usage;
             DROP TABLE IF EXISTS rustaccio_schema_migrations;",
        )
        .await
        .expect("reset postgres");
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

async fn create_user(app: &axum::Router, username: &str, password: &str) -> String {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/-/user/org.couchdb.user:{username}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name": username, "password": password})).expect("payload"),
        ))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = resp
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    serde_json::from_slice::<serde_json::Value>(&body)
        .expect("json")
        .get("token")
        .and_then(serde_json::Value::as_str)
        .expect("token")
        .to_string()
}

#[tokio::test]
#[ignore = "requires local Redis (`just governance-up`)"]
async fn redis_rate_limiter_enforces_limit() {
    let redis_url = redis_it_url();
    wait_for_redis(&redis_url).await;
    reset_redis(&redis_url).await;

    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("redis")),
            ("RUSTACCIO_RATE_LIMIT_REDIS_URL", Some(redis_url.as_str())),
            ("RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW", Some("2")),
            ("RUSTACCIO_RATE_LIMIT_WINDOW_SECS", Some("60")),
            ("RUSTACCIO_RATE_LIMIT_FAIL_OPEN", Some("false")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_METRICS_BACKEND", Some("none")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            for index in 0..3 {
                let req = Request::builder()
                    .method(Method::GET)
                    .uri("/-/ping")
                    .body(Body::empty())
                    .expect("request");
                let resp = app.clone().oneshot(req).await.expect("response");
                if index < 2 {
                    assert_eq!(resp.status(), StatusCode::OK);
                } else {
                    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                }
            }
        },
    )
    .await;
}

#[tokio::test]
async fn redis_rate_limiter_fail_open_allows_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("redis")),
            (
                "RUSTACCIO_RATE_LIMIT_REDIS_URL",
                Some("redis://127.0.0.1:1/"),
            ),
            ("RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW", Some("1")),
            ("RUSTACCIO_RATE_LIMIT_WINDOW_SECS", Some("60")),
            ("RUSTACCIO_RATE_LIMIT_FAIL_OPEN", Some("true")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_METRICS_BACKEND", Some("none")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            for _ in 0..2 {
                let req = Request::builder()
                    .method(Method::GET)
                    .uri("/-/ping")
                    .body(Body::empty())
                    .expect("request");
                let resp = app.clone().oneshot(req).await.expect("response");
                assert_eq!(resp.status(), StatusCode::OK);
            }
        },
    )
    .await;
}

#[tokio::test]
async fn redis_rate_limiter_fail_closed_rejects_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("redis")),
            (
                "RUSTACCIO_RATE_LIMIT_REDIS_URL",
                Some("redis://127.0.0.1:1/"),
            ),
            ("RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW", Some("1")),
            ("RUSTACCIO_RATE_LIMIT_WINDOW_SECS", Some("60")),
            ("RUSTACCIO_RATE_LIMIT_FAIL_OPEN", Some("false")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_METRICS_BACKEND", Some("none")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            let req = Request::builder()
                .method(Method::GET)
                .uri("/-/ping")
                .body(Body::empty())
                .expect("request");
            let resp = app.clone().oneshot(req).await.expect("response");
            assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires local Postgres (`just governance-up`)"]
async fn postgres_quota_migrations_and_limits_are_enforced() {
    let postgres_url = postgres_it_url();
    wait_for_postgres(&postgres_url).await;
    reset_postgres(&postgres_url).await;

    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("postgres")),
            ("RUSTACCIO_QUOTA_POSTGRES_URL", Some(postgres_url.as_str())),
            ("RUSTACCIO_QUOTA_PUBLISHES_PER_DAY", Some("1")),
            ("RUSTACCIO_QUOTA_REQUESTS_PER_DAY", Some("0")),
            ("RUSTACCIO_QUOTA_DOWNLOADS_PER_DAY", Some("0")),
            ("RUSTACCIO_QUOTA_FAIL_OPEN", Some("false")),
            ("RUSTACCIO_METRICS_BACKEND", Some("none")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            let db = postgres_client(&postgres_url).await;
            let migration_count: i64 = db
                .query_one(
                    "SELECT COUNT(*) FROM rustaccio_schema_migrations WHERE name = $1",
                    &[&"0001_quota_usage_table"],
                )
                .await
                .expect("migration row")
                .get(0);
            assert_eq!(migration_count, 1);

            let table_exists: bool = db
                .query_one(
                    "SELECT to_regclass('public.rustaccio_quota_usage') IS NOT NULL",
                    &[],
                )
                .await
                .expect("table check")
                .get(0);
            assert!(table_exists);

            let user = format!("pg-it-{}", Uuid::new_v4().as_simple());
            let token = create_user(&app, &user, "secret").await;
            for (idx, pkg) in ["pg-it-pkg-one", "pg-it-pkg-two"].iter().enumerate() {
                let req = Request::builder()
                    .method(Method::PUT)
                    .uri(format!("/{pkg}"))
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&publish_manifest(pkg)).expect("payload"),
                    ))
                    .expect("request");
                let resp = app.clone().oneshot(req).await.expect("response");
                if idx == 0 {
                    assert_eq!(resp.status(), StatusCode::CREATED);
                } else {
                    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                }
            }

            let state = runtime::build_state(&cfg, None)
                .await
                .expect("second state");
            drop(state);
            let migration_count_after_second_boot: i64 = db
                .query_one(
                    "SELECT COUNT(*) FROM rustaccio_schema_migrations WHERE name = $1",
                    &[&"0001_quota_usage_table"],
                )
                .await
                .expect("migration row")
                .get(0);
            assert_eq!(migration_count_after_second_boot, 1);
        },
    )
    .await;
}
