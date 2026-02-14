use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use rustaccio::{
    acl::{Acl, PackageRule},
    app::{AppState, build_router},
    config::{AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig},
    policy::{DefaultPolicyEngine, HttpPolicyConfig},
    storage::Store,
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn base_config(data_dir: PathBuf, rules: Vec<PackageRule>) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: rules,
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

fn manifest(pkg: &str) -> Value {
    let tarball = format!("{pkg}-1.0.0.tgz");
    json!({
        "_id": pkg,
        "name": pkg,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg,
                "version": "1.0.0",
                "dist": { "tarball": format!("http://localhost:4873/{pkg}/-/{tarball}") }
            }
        },
        "_attachments": {
            tarball: {
                "content_type": "application/octet-stream",
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"abc"),
                "length": 3
            }
        }
    })
}

async fn seeded_app(
    cfg: Config,
    policy_cfg: Option<HttpPolicyConfig>,
    package_name: &str,
) -> (axum::Router, String) {
    let store = Arc::new(Store::open(&cfg).await.expect("store"));
    let token = store
        .create_user("alice", "secret")
        .await
        .expect("create user");
    store
        .publish_manifest(package_name, manifest(package_name), "alice")
        .await
        .expect("seed package");

    let acl = Acl::new(cfg.acl_rules.clone());
    let policy = match policy_cfg {
        Some(policy_cfg) => Arc::new(
            DefaultPolicyEngine::new_with_http(store.clone(), acl.clone(), policy_cfg)
                .expect("policy engine"),
        ),
        None => Arc::new(DefaultPolicyEngine::new(store.clone(), acl.clone())),
    };

    let app = build_router(AppState {
        store,
        acl,
        policy,
        uplinks: HashMap::new(),
        web_enabled: cfg.web_enabled,
        web_title: cfg.web_title,
        web_login_enabled: cfg.web_login,
        publish_check_owners: cfg.publish_check_owners,
        max_body_size: cfg.max_body_size,
        audit_enabled: cfg.audit_enabled,
        url_prefix: cfg.url_prefix,
        trust_proxy: cfg.trust_proxy,
        auth_external_mode: cfg.auth_plugin.external_mode,
    });
    (app, token)
}

async fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    app.clone().oneshot(req).await.expect("response")
}

fn auth_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn external_policy_deny_overrides_open_acl() {
    let policy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"allowed": false})))
        .mount(&policy)
        .await;

    let dir = TempDir::new().expect("dir");
    let cfg = base_config(dir.path().to_path_buf(), vec![PackageRule::open("**")]);
    let policy_cfg = HttpPolicyConfig {
        base_url: policy.uri(),
        decision_endpoint: "/authorize".to_string(),
        timeout_ms: 1_000,
        cache_ttl_ms: 0,
        fail_open: false,
    };
    let (app, token) = seeded_app(cfg, Some(policy_cfg), "deny-by-policy").await;

    let resp = send(&app, auth_get("/deny-by-policy", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn external_policy_allow_overrides_acl_deny() {
    let policy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"allowed": true})))
        .mount(&policy)
        .await;

    let dir = TempDir::new().expect("dir");
    let cfg = base_config(
        dir.path().to_path_buf(),
        vec![PackageRule {
            pattern: "**".to_string(),
            access: vec!["nobody".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: None,
            uplinks_look: true,
        }],
    );
    let policy_cfg = HttpPolicyConfig {
        base_url: policy.uri(),
        decision_endpoint: "/authorize".to_string(),
        timeout_ms: 1_000,
        cache_ttl_ms: 0,
        fail_open: false,
    };
    let (app, token) = seeded_app(cfg, Some(policy_cfg), "allow-by-policy").await;

    let resp = send(&app, auth_get("/allow-by-policy", &token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn external_policy_fail_open_falls_back_to_acl() {
    let dir = TempDir::new().expect("dir");
    let cfg = base_config(dir.path().to_path_buf(), vec![PackageRule::open("**")]);
    let policy_cfg = HttpPolicyConfig {
        base_url: "http://127.0.0.1:9".to_string(),
        decision_endpoint: "/authorize".to_string(),
        timeout_ms: 250,
        cache_ttl_ms: 0,
        fail_open: true,
    };
    let (app, token) = seeded_app(cfg, Some(policy_cfg), "fail-open").await;

    let resp = send(&app, auth_get("/fail-open", &token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn external_policy_fail_closed_returns_bad_gateway() {
    let dir = TempDir::new().expect("dir");
    let cfg = base_config(dir.path().to_path_buf(), vec![PackageRule::open("**")]);
    let policy_cfg = HttpPolicyConfig {
        base_url: "http://127.0.0.1:9".to_string(),
        decision_endpoint: "/authorize".to_string(),
        timeout_ms: 250,
        cache_ttl_ms: 0,
        fail_open: false,
    };
    let (app, token) = seeded_app(cfg, Some(policy_cfg), "fail-closed").await;

    let resp = send(&app, auth_get("/fail-closed", &token)).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn external_policy_cache_reuses_decision() {
    let policy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"allowed": true})))
        .mount(&policy)
        .await;

    let dir = TempDir::new().expect("dir");
    let cfg = base_config(
        dir.path().to_path_buf(),
        vec![PackageRule {
            pattern: "**".to_string(),
            access: vec!["nobody".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: None,
            uplinks_look: true,
        }],
    );
    let policy_cfg = HttpPolicyConfig {
        base_url: policy.uri(),
        decision_endpoint: "/authorize".to_string(),
        timeout_ms: 1_000,
        cache_ttl_ms: 60_000,
        fail_open: false,
    };
    let (app, token) = seeded_app(cfg, Some(policy_cfg), "cache-hit").await;

    let resp = send(&app, auth_get("/cache-hit", &token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(&app, auth_get("/cache-hit", &token)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let requests = policy.received_requests().await.expect("received requests");
    let decision_calls = requests
        .iter()
        .filter(|request| request.url.path() == "/authorize")
        .count();
    assert_eq!(decision_calls, 1);
}
