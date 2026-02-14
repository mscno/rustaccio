#![cfg(feature = "s3")]

use aws_sdk_s3::{
    Client as S3Client,
    config::{Builder as S3ConfigBuilder, Credentials, Region},
    error::ProvideErrorMetadata,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use rustaccio::{
    config::{AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig},
    runtime,
};
use serde_json::json;
use std::{collections::HashMap, future::Future, sync::OnceLock, time::Duration};
use tempfile::TempDir;
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

fn it_endpoint() -> String {
    std::env::var("RUSTACCIO_S3_IT_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9002".to_string())
}

fn it_region() -> String {
    std::env::var("RUSTACCIO_S3_IT_REGION").unwrap_or_else(|_| "us-east-1".to_string())
}

fn it_bucket() -> String {
    std::env::var("RUSTACCIO_S3_IT_BUCKET").unwrap_or_else(|_| "rustaccio-it".to_string())
}

fn it_access_key() -> String {
    std::env::var("RUSTACCIO_S3_IT_ACCESS_KEY").unwrap_or_else(|_| "minioadmin".to_string())
}

fn it_secret_key() -> String {
    std::env::var("RUSTACCIO_S3_IT_SECRET_KEY").unwrap_or_else(|_| "minioadmin".to_string())
}

async fn s3_client(endpoint: &str, region: &str, access_key: &str, secret_key: &str) -> S3Client {
    let shared = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region.to_string()))
        .credentials_provider(Credentials::new(
            access_key.to_string(),
            secret_key.to_string(),
            None,
            None,
            "rustaccio-it",
        ))
        .load()
        .await;

    let conf = S3ConfigBuilder::from(&shared)
        .endpoint_url(endpoint)
        .force_path_style(true)
        .build();
    S3Client::from_conf(conf)
}

async fn wait_for_s3(client: &S3Client) {
    for _ in 0..80 {
        if client.list_buckets().send().await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("S3 endpoint was not reachable in time");
}

async fn ensure_bucket(client: &S3Client, bucket: &str) {
    match client.create_bucket().bucket(bucket).send().await {
        Ok(_) => {}
        Err(err) => {
            let code = err
                .as_service_error()
                .and_then(|service_err| service_err.code())
                .unwrap_or_default();
            if code != "BucketAlreadyOwnedByYou" && code != "BucketAlreadyExists" {
                panic!("failed to create bucket `{bucket}`: {err}");
            }
        }
    }
}

async fn app_with_env(cfg: &Config) -> axum::Router {
    let state = runtime::build_state(cfg, None).await.expect("state");
    rustaccio::app::build_router(state)
}

async fn create_user(app: &axum::Router, username: &str) -> StatusCode {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/-/user/org.couchdb.user:{username}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name": username, "password": "secret"})).expect("payload"),
        ))
        .expect("request");
    app.clone().oneshot(req).await.expect("response").status()
}

#[tokio::test]
async fn state_coordination_s3_fail_open_allows_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            ("RUSTACCIO_STATE_COORDINATION_S3_BUCKET", Some("unused")),
            ("RUSTACCIO_STATE_COORDINATION_S3_REGION", Some("us-east-1")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some("http://127.0.0.1:1"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("true")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;
            let user = format!("state-open-{}", Uuid::new_v4().as_simple());
            assert_eq!(create_user(&app, &user).await, StatusCode::CREATED);
        },
    )
    .await;
}

#[tokio::test]
async fn state_coordination_s3_fail_closed_rejects_writes_when_backend_is_down() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            ("RUSTACCIO_STATE_COORDINATION_S3_BUCKET", Some("unused")),
            ("RUSTACCIO_STATE_COORDINATION_S3_REGION", Some("us-east-1")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some("http://127.0.0.1:1"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("500"),
            ),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;
            let user = format!("state-closed-{}", Uuid::new_v4().as_simple());
            assert_eq!(create_user(&app, &user).await, StatusCode::BAD_GATEWAY);
        },
    )
    .await;
}

#[tokio::test]
#[ignore = "requires local MinIO (`just minio-up`)"]
async fn state_coordination_s3_lock_timeout_when_key_is_held() {
    let endpoint = it_endpoint();
    let region = it_region();
    let bucket = it_bucket();
    let access_key = it_access_key();
    let secret_key = it_secret_key();
    let client = s3_client(&endpoint, &region, &access_key, &secret_key).await;
    wait_for_s3(&client).await;
    ensure_bucket(&client, &bucket).await;

    let prefix = format!("rustaccio-it-locks/{}/", Uuid::new_v4().as_simple());
    let held_key = format!("{prefix}state.lock");
    let lease_until_ms = chrono::Utc::now().timestamp_millis() + 10_000;
    let payload = json!({
        "token": "held-token",
        "lease_until_ms": lease_until_ms,
        "operation": "held",
    });
    client
        .put_object()
        .bucket(&bucket)
        .key(&held_key)
        .body(aws_sdk_s3::primitives::ByteStream::from(
            serde_json::to_vec(&payload).expect("payload"),
        ))
        .send()
        .await
        .expect("set held lock");

    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_STATE_COORDINATION_BACKEND", Some("s3")),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_BUCKET",
                Some(bucket.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_REGION",
                Some(region.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ENDPOINT",
                Some(endpoint.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_ACCESS_KEY_ID",
                Some(access_key.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_SECRET_ACCESS_KEY",
                Some(secret_key.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_PREFIX",
                Some(prefix.as_str()),
            ),
            (
                "RUSTACCIO_STATE_COORDINATION_S3_FORCE_PATH_STYLE",
                Some("true"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_FAIL_OPEN", Some("false")),
            (
                "RUSTACCIO_STATE_COORDINATION_ACQUIRE_TIMEOUT_MS",
                Some("400"),
            ),
            ("RUSTACCIO_STATE_COORDINATION_POLL_INTERVAL_MS", Some("50")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;
            let user = format!("state-lock-{}", Uuid::new_v4().as_simple());
            assert_eq!(
                create_user(&app, &user).await,
                StatusCode::SERVICE_UNAVAILABLE
            );
        },
    )
    .await;
}
