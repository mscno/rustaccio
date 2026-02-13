use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use rustaccio::{
    acl::PackageRule,
    app::build_router,
    auth::AuthHook,
    config::{
        AuthBackend, AuthPluginConfig, Config, HttpAuthPluginConfig, TarballStorageBackend,
        TarballStorageConfig,
    },
    models::AuthIdentity,
    runtime,
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[derive(Debug)]
struct GroupOnlyHook;

#[async_trait]
impl AuthHook for GroupOnlyHook {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, rustaccio::error::RegistryError> {
        Ok(Some(AuthIdentity {
            username: None,
            groups: vec!["dev-team".to_string()],
        }))
    }
}

fn base_config(data_dir: PathBuf) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        web_login: true,
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

async fn app_with_config(cfg: &Config, hook: Option<Arc<dyn AuthHook>>) -> axum::Router {
    let state = runtime::build_state(cfg, hook).await.expect("state");
    build_router(state)
}

async fn send(app: &axum::Router, req: Request<Body>) -> axum::http::Response<Body> {
    app.clone().oneshot(req).await.expect("response")
}

async fn json_body(resp: axum::http::Response<Body>) -> Value {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("json")
}

fn manifest(pkg: &str) -> Value {
    let tar = format!("{pkg}-1.0.0.tgz");
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"abc");
    json!({
        "_id": pkg,
        "name": pkg,
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": pkg,
                "version": "1.0.0",
                "dist": { "tarball": format!("http://localhost:4873/{pkg}/-/{tar}") }
            }
        },
        "_attachments": {
            tar: {
                "content_type": "application/octet-stream",
                "data": data_b64,
                "length": 3
            }
        }
    })
}

#[tokio::test]
async fn external_auth_mode_disables_local_auth_routes() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.auth_plugin.external_mode = true;
    let app = app_with_config(&cfg, None).await;

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:alice")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"alice","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/v1/login")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/npm/v1/user")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn max_body_size_is_enforced_for_json_endpoints() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.max_body_size = 16;
    let app = app_with_config(&cfg, None).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"root","dependencies":{"left-pad":"1.3.0"}}))
                .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn trust_proxy_controls_base_url_for_login_links() {
    let dir = TempDir::new().expect("dir");
    let cfg_untrusted = base_config(dir.path().join("untrusted"));
    let app_untrusted = app_with_config(&cfg_untrusted, None).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/v1/login")
        .header(header::HOST, "registry.internal:4873")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "registry.example.com")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app_untrusted, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let login_url = body
        .get("loginUrl")
        .and_then(Value::as_str)
        .expect("loginUrl");
    assert!(login_url.starts_with("http://registry.internal:4873/"));

    let mut cfg_trusted = base_config(dir.path().join("trusted"));
    cfg_trusted.trust_proxy = true;
    let app_trusted = app_with_config(&cfg_trusted, None).await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/v1/login")
        .header(header::HOST, "registry.internal:4873")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-host", "registry.example.com")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app_trusted, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let login_url = body
        .get("loginUrl")
        .and_then(Value::as_str)
        .expect("loginUrl");
    assert!(login_url.starts_with("https://registry.example.com/"));
}

#[tokio::test]
async fn group_only_identity_can_satisfy_acl_publish() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.auth_plugin = AuthPluginConfig {
        backend: AuthBackend::Http,
        external_mode: false,
        http: Some(HttpAuthPluginConfig {
            base_url: "http://unused".to_string(),
            add_user_endpoint: "/adduser".to_string(),
            login_endpoint: "/authenticate".to_string(),
            change_password_endpoint: "/change-password".to_string(),
            request_auth_endpoint: Some("/request-auth".to_string()),
            allow_access_endpoint: None,
            allow_publish_endpoint: None,
            allow_unpublish_endpoint: None,
            timeout_ms: 1_000,
        }),
    };
    cfg.acl_rules = vec![PackageRule {
        pattern: "**".to_string(),
        access: vec!["dev-team".to_string()],
        publish: vec!["dev-team".to_string()],
        unpublish: vec!["dev-team".to_string()],
        proxy: None,
        uplinks_look: true,
    }];
    let app = app_with_config(&cfg, Some(Arc::new(GroupOnlyHook))).await;

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/group-pkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&manifest("group-pkg")).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn external_request_auth_not_found_surfaces_as_bad_gateway() {
    let auth = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/request-auth"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"error":"not found"})))
        .mount(&auth)
        .await;

    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.auth_plugin = AuthPluginConfig {
        backend: AuthBackend::Http,
        external_mode: false,
        http: Some(HttpAuthPluginConfig {
            base_url: auth.uri(),
            add_user_endpoint: "/adduser".to_string(),
            login_endpoint: "/authenticate".to_string(),
            change_password_endpoint: "/change-password".to_string(),
            request_auth_endpoint: Some("/request-auth".to_string()),
            allow_access_endpoint: None,
            allow_publish_endpoint: None,
            allow_unpublish_endpoint: None,
            timeout_ms: 1_000,
        }),
    };
    let app = app_with_config(&cfg, None).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/@geoman-io/leaflet-geoman-free")
        .header(header::AUTHORIZATION, "Bearer deadbeef")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = json_body(resp).await;
    assert_eq!(
        body["error"].as_str(),
        Some("external request auth endpoint not found: /request-auth")
    );
}

#[tokio::test]
async fn audit_endpoints_are_disabled_when_audit_flag_is_false() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.audit_enabled = false;
    let app = app_with_config(&cfg, None).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits/quick")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/advisories/bulk")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn web_routes_are_hidden_when_web_is_disabled() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = base_config(dir.path().to_path_buf());
    cfg.web_enabled = false;
    let app = app_with_config(&cfg, None).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/web/static/app.js")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/web/login")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
