use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use rustaccio::{
    config::{AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig},
    runtime,
};
use serde_json::json;
use std::{collections::HashMap, future::Future, sync::OnceLock};
use tempfile::TempDir;
use tower::ServiceExt;

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

async fn app_with_env(cfg: &Config) -> axum::Router {
    let state = runtime::build_state(cfg, None).await.expect("state");
    rustaccio::app::build_router(state)
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

#[tokio::test]
async fn memory_rate_limiter_is_opt_in() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("memory")),
            ("RUSTACCIO_RATE_LIMIT_REQUESTS_PER_WINDOW", Some("2")),
            ("RUSTACCIO_RATE_LIMIT_WINDOW_SECS", Some("60")),
            ("RUSTACCIO_QUOTA_BACKEND", None),
            ("RUSTACCIO_METRICS_BACKEND", None),
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
async fn memory_quota_limits_publishes_when_enabled() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("memory")),
            ("RUSTACCIO_QUOTA_PUBLISHES_PER_DAY", Some("1")),
            ("RUSTACCIO_QUOTA_REQUESTS_PER_DAY", Some("0")),
            ("RUSTACCIO_QUOTA_DOWNLOADS_PER_DAY", Some("0")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            let create = Request::builder()
                .method(Method::PUT)
                .uri("/-/user/org.couchdb.user:alice")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&json!({"name":"alice","password":"secret"}))
                        .expect("payload"),
                ))
                .expect("request");
            let create_resp = app.clone().oneshot(create).await.expect("response");
            assert_eq!(create_resp.status(), StatusCode::CREATED);
            let create_body = create_resp
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes();
            let token = serde_json::from_slice::<serde_json::Value>(&create_body)
                .expect("json")
                .get("token")
                .and_then(serde_json::Value::as_str)
                .expect("token")
                .to_string();

            let publish1 = Request::builder()
                .method(Method::PUT)
                .uri("/one")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&publish_manifest("one")).expect("payload"),
                ))
                .expect("request");
            let resp = app.clone().oneshot(publish1).await.expect("response");
            assert_eq!(resp.status(), StatusCode::CREATED);

            let publish2 = Request::builder()
                .method(Method::PUT)
                .uri("/two")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::to_vec(&publish_manifest("two")).expect("payload"),
                ))
                .expect("request");
            let resp = app.clone().oneshot(publish2).await.expect("response");
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        },
    )
    .await;
}

#[tokio::test]
async fn metrics_endpoint_exports_governance_counters() {
    with_env(
        &[
            ("RUSTACCIO_RATE_LIMIT_BACKEND", Some("none")),
            ("RUSTACCIO_QUOTA_BACKEND", Some("none")),
            ("RUSTACCIO_METRICS_BACKEND", Some("prometheus")),
            ("RUSTACCIO_METRICS_PATH", Some("/-/metrics")),
            ("RUSTACCIO_METRICS_REQUIRE_ADMIN", Some("false")),
        ],
        async {
            let dir = TempDir::new().expect("dir");
            let cfg = base_config(dir.path().to_path_buf());
            let app = app_with_env(&cfg).await;

            let ping = Request::builder()
                .method(Method::GET)
                .uri("/-/ping")
                .body(Body::empty())
                .expect("request");
            let ping_resp = app.clone().oneshot(ping).await.expect("response");
            assert_eq!(ping_resp.status(), StatusCode::OK);

            let metrics = Request::builder()
                .method(Method::GET)
                .uri("/-/metrics")
                .body(Body::empty())
                .expect("request");
            let metrics_resp = app.clone().oneshot(metrics).await.expect("response");
            assert_eq!(metrics_resp.status(), StatusCode::OK);
            let body = metrics_resp
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes();
            let text = String::from_utf8(body.to_vec()).expect("utf8");
            assert!(text.contains("rustaccio_governance_requests_total"));
        },
    )
    .await;
}
