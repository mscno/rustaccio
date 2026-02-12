use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use rustaccio::{
    acl::{Acl, PackageRule},
    app::{AppState, build_router},
    config::{
        AuthBackend, AuthPluginConfig, Config, HttpAuthPluginConfig, TarballStorageBackend,
        TarballStorageConfig,
    },
    storage::Store,
    upstream::Upstream,
};
use serde_json::{Value, json};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn test_app(data_dir: PathBuf, upstream: Option<String>) -> axum::Router {
    test_app_with_rules(data_dir, upstream, vec![PackageRule::open("**")]).await
}

async fn test_app_with_rules(
    data_dir: PathBuf,
    upstream: Option<String>,
    rules: Vec<PackageRule>,
) -> axum::Router {
    test_app_with_rules_and_options(data_dir, upstream, rules, true, false).await
}

async fn test_app_with_rules_and_web_login(
    data_dir: PathBuf,
    upstream: Option<String>,
    rules: Vec<PackageRule>,
    web_login: bool,
) -> axum::Router {
    test_app_with_rules_and_options(data_dir, upstream, rules, web_login, false).await
}

async fn test_app_with_rules_and_options(
    data_dir: PathBuf,
    upstream: Option<String>,
    rules: Vec<PackageRule>,
    web_login: bool,
    publish_check_owners: bool,
) -> axum::Router {
    let mut uplinks = HashMap::new();
    if let Some(url) = upstream.clone() {
        uplinks.insert("default".to_string(), url);
    }

    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        upstream_registry: upstream,
        uplinks,
        acl_rules: rules,
        web_login,
        publish_check_owners,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        auth_plugin: AuthPluginConfig {
            backend: AuthBackend::Local,
            http: None,
        },
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    };
    let store = Arc::new(Store::open(&cfg).await.expect("store"));
    let upstream_clients = cfg
        .uplinks
        .iter()
        .map(|(name, url)| (name.clone(), Upstream::new(url.clone())))
        .collect::<HashMap<_, _>>();
    build_router(AppState {
        store,
        acl: Acl::new(cfg.acl_rules.clone()),
        uplinks: upstream_clients,
        web_login_enabled: cfg.web_login,
        publish_check_owners: cfg.publish_check_owners,
    })
}

async fn test_app_with_explicit_uplinks(
    data_dir: PathBuf,
    uplinks: HashMap<String, String>,
    rules: Vec<PackageRule>,
    web_login: bool,
) -> axum::Router {
    test_app_with_explicit_uplinks_and_options(data_dir, uplinks, rules, web_login, false).await
}

async fn test_app_with_explicit_uplinks_and_options(
    data_dir: PathBuf,
    uplinks: HashMap<String, String>,
    rules: Vec<PackageRule>,
    web_login: bool,
    publish_check_owners: bool,
) -> axum::Router {
    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        upstream_registry: uplinks.values().next().cloned(),
        uplinks,
        acl_rules: rules,
        web_login,
        publish_check_owners,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        auth_plugin: AuthPluginConfig {
            backend: AuthBackend::Local,
            http: None,
        },
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    };
    let store = Arc::new(Store::open(&cfg).await.expect("store"));
    let upstream_clients = cfg
        .uplinks
        .iter()
        .map(|(name, url)| (name.clone(), Upstream::new(url.clone())))
        .collect::<HashMap<_, _>>();
    build_router(AppState {
        store,
        acl: Acl::new(cfg.acl_rules.clone()),
        uplinks: upstream_clients,
        web_login_enabled: cfg.web_login,
        publish_check_owners: cfg.publish_check_owners,
    })
}

async fn test_app_with_http_auth_plugin(data_dir: PathBuf, auth_base_url: String) -> axum::Router {
    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir,
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_login: true,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        auth_plugin: AuthPluginConfig {
            backend: AuthBackend::Http,
            http: Some(HttpAuthPluginConfig {
                base_url: auth_base_url,
                add_user_endpoint: "/adduser".to_string(),
                login_endpoint: "/authenticate".to_string(),
                change_password_endpoint: "/change-password".to_string(),
                timeout_ms: 2_000,
            }),
        },
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    };
    let store = Arc::new(Store::open(&cfg).await.expect("store"));
    build_router(AppState {
        store,
        acl: Acl::new(cfg.acl_rules.clone()),
        uplinks: HashMap::new(),
        web_login_enabled: cfg.web_login,
        publish_check_owners: cfg.publish_check_owners,
    })
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

async fn bytes_body(resp: axum::http::Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes()
        .to_vec()
}

fn pkg_manifest(pkg: &str, version: &str, tarball_filename: &str, data: &[u8]) -> Value {
    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
    json!({
        "_id": pkg,
        "name": pkg,
        "dist-tags": {
            "latest": version
        },
        "versions": {
            version: {
                "name": pkg,
                "version": version,
                "description": "package generated",
                "keywords": [],
                "author": {
                    "name": "User NPM",
                    "email": "user@domain.com"
                },
                "dist": {
                    "tarball": format!("http://localhost:5555/{pkg}/-/{tarball_filename}"),
                    "shasum": "2c03764f651a9f016ca0b7620421457b619151b9"
                },
                "readme": "# test"
            }
        },
        "readme": "# test",
        "_attachments": {
            tarball_filename: {
                "content_type": "application/octet-stream",
                "data": data_b64,
                "length": data.len()
            }
        },
        "_uplinks": {},
        "_distfiles": {},
        "_rev": ""
    })
}

async fn create_user(app: &axum::Router, name: &str, password: &str) -> String {
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/-/user/org.couchdb.user:{name}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "name": name, "password": password })).expect("payload"),
        ))
        .expect("request");
    let resp = send(app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    body.get("token")
        .and_then(Value::as_str)
        .expect("token")
        .to_string()
}

#[tokio::test]
async fn user_and_whoami_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "test", "secret").await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/whoami")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json; charset=utf-8")
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.get("username").and_then(Value::as_str), Some("test"));
}

#[tokio::test]
async fn http_auth_plugin_user_login_and_password_flows() {
    let auth = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/adduser"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "ok": true })))
        .mount(&auth)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&auth)
        .await;

    Mock::given(method("POST"))
        .and(path("/change-password"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "ok": true })))
        .mount(&auth)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app_with_http_auth_plugin(dir.path().to_path_buf(), auth.uri()).await;

    let token = create_user(&app, "pluguser", "secret").await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/whoami")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["username"].as_str(), Some("pluguser"));

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:pluguser")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"pluguser","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "password": { "new": "newsecret", "old": "secret" }}))
                .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn http_auth_plugin_errors_are_propagated() {
    let auth = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/adduser"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "ok": true })))
        .mount(&auth)
        .await;

    Mock::given(method("POST"))
        .and(path("/authenticate"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "error": "plugin denied" })))
        .mount(&auth)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app_with_http_auth_plugin(dir.path().to_path_buf(), auth.uri()).await;
    let token = create_user(&app, "plugdeny", "secret").await;

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:plugdeny")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"plugdeny","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    assert_eq!(body["error"].as_str(), Some("plugin denied"));
}

#[tokio::test]
async fn ping_and_whoami_invalid_token_paths() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let _token = create_user(&app, "tester", "secret").await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/ping")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body, json!({}));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/whoami")
        .header(header::AUTHORIZATION, "Bearer invalid-token")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn publish_get_and_tarball_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "alice", "secret").await;
    let manifest = pkg_manifest("foo", "1.0.0", "foo-1.0.0.tgz", b"hello tarball");

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo")
        .header(header::HOST, "localhost:4873")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.get("name").and_then(Value::as_str), Some("foo"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo?write=true")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo?write=true")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo/1.0.0")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.get("version").and_then(Value::as_str), Some("1.0.0"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo/latest")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.get("version").and_then(Value::as_str), Some("1.0.0"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo/9.9.9")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = json_body(resp).await;
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("this version doesn't exist: 9.9.9")
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo/-/foo-1.0.0.tgz")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(bytes_body(resp).await, b"hello tarball");

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo/-/foo-9.9.9.tgz")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/octet-stream; charset=utf-8")
    );
}

#[tokio::test]
async fn head_routes_for_package_version_and_tarball() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "head-user", "secret").await;

    let manifest = pkg_manifest("headpkg", "1.0.0", "headpkg-1.0.0.tgz", b"head");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/headpkg")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    for uri in [
        "/headpkg",
        "/headpkg/1.0.0",
        "/headpkg/latest",
        "/headpkg/-/headpkg-1.0.0.tgz",
    ] {
        let req = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let resp = send(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(bytes_body(resp).await.is_empty());
    }
}

#[tokio::test]
async fn dist_tag_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "bob", "secret").await;

    let v1 = pkg_manifest("foo", "1.0.0", "foo-1.0.0.tgz", b"v1");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&v1).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let mut v2 = pkg_manifest("foo", "1.0.1", "foo-1.0.1.tgz", b"v2");
    v2["dist-tags"] = json!({"latest": "1.0.1"});
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&v2).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo/beta")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(b"\"1.0.1\"".to_vec()))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/package/foo/dist-tags")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body.get("beta").and_then(Value::as_str), Some("1.0.1"));

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/-/package/foo/dist-tags/beta")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo/test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(b"{}".to_vec()))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn token_profile_and_search_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "carol", "secret").await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(
                &json!({"password": "secret", "readonly": false, "cidr_whitelist": []}),
            )
            .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let token_key = body
        .get("key")
        .and_then(Value::as_str)
        .expect("key")
        .to_string();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/npm/v1/tokens")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list = json_body(resp).await;
    assert_eq!(list["objects"].as_array().map(Vec::len), Some(1));

    let req = Request::builder()
        .method(Method::DELETE)
        .uri(format!("/-/npm/v1/tokens/token/{token_key}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/npm/v1/user")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "password": { "new": "_" }})).expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "password": { "new": "newpassword", "old": "secret" }}))
                .expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "password": "newpassword", "cidr_whitelist": [] }))
                .expect("payload"),
        ))
        .expect("request");
    assert_eq!(
        send(&app, req).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/tokens")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(
                &json!({ "password": "wrong", "readonly": false, "cidr_whitelist": [] }),
            )
            .expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::UNAUTHORIZED);

    let manifest = pkg_manifest("bar", "1.0.0", "bar-1.0.0.tgz", b"bar");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/bar")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/v1/search?text=bar&size=2000&from=0&quality=1&popularity=0.1&maintenance=0.1")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["objects"].as_array().map(Vec::len).unwrap_or(0) >= 1);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/v1/search?text=bar&size=1&from=1")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["objects"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn upstream_proxy_manifest_and_tarball_flow() {
    let upstream = MockServer::start().await;

    let upstream_manifest = json!({
        "_id": "proxy-pkg",
        "name": "proxy-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "proxy-pkg",
                "version": "1.0.0",
                "description": "proxy",
                "keywords": [],
                "author": {"name": "Upstream", "email": "up@stream"},
                "dist": {
                    "tarball": format!("{}/proxy-pkg/-/proxy-pkg-1.0.0.tgz", upstream.uri())
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/proxy-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(upstream_manifest))
        .mount(&upstream)
        .await;

    Mock::given(method("GET"))
        .and(path("/proxy-pkg/-/proxy-pkg-1.0.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"upstream tgz".to_vec()))
        .mount(&upstream)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), Some(upstream.uri())).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/proxy-pkg")
        .header(header::HOST, "localhost:4873")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let tarball = body["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap_or_default();
    assert!(tarball.contains("/proxy-pkg/-/proxy-pkg-1.0.0.tgz"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/proxy-pkg/-/proxy-pkg-1.0.0.tgz")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(bytes_body(resp).await, b"upstream tgz");
}

#[tokio::test]
async fn upstream_info_like_response_contains_dependencies() {
    let upstream = MockServer::start().await;

    let upstream_manifest = json!({
        "_id": "verdaccio",
        "name": "verdaccio",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "verdaccio",
                "version": "1.0.0",
                "dependencies": { "foo": "^1.0.0" },
                "dist": {
                    "tarball": format!("{}/verdaccio/-/verdaccio-1.0.0.tgz", upstream.uri())
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/verdaccio"))
        .respond_with(ResponseTemplate::new(200).set_body_json(upstream_manifest))
        .mount(&upstream)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), Some(upstream.uri())).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/verdaccio/latest")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["name"].as_str(), Some("verdaccio"));
    assert!(body["dependencies"].get("foo").is_some());
}

#[tokio::test]
async fn upstream_publish_patch_and_dist_tags_flow() {
    let upstream = MockServer::start().await;

    let upstream_manifest = json!({
        "_id": "remote-pkg",
        "name": "remote-pkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "remote-pkg",
                "version": "1.0.0",
                "description": "remote",
                "keywords": [],
                "author": {"name": "Upstream", "email": "up@stream"},
                "dist": {
                    "tarball": format!("{}/remote-pkg/-/remote-pkg-1.0.0.tgz", upstream.uri())
                }
            }
        }
    });

    Mock::given(method("GET"))
        .and(path("/remote-pkg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(upstream_manifest))
        .mount(&upstream)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), Some(upstream.uri())).await;
    let token = create_user(&app, "patcher", "secret").await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/package/remote-pkg/dist-tags")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["latest"].as_str(), Some("1.0.0"));

    let patch_manifest = pkg_manifest(
        "remote-pkg",
        "1.0.1-patch",
        "remote-pkg-1.0.1-patch.tgz",
        b"patch",
    );
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/remote-pkg")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&patch_manifest).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["ok"].as_str(), Some("package changed"));
}

#[tokio::test]
async fn upstream_security_audit_endpoints_proxy() {
    let upstream = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/advisories/bulk"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "debug": {
                "name": "debug",
                "severity": "low",
            }
        })))
        .mount(&upstream)
        .await;

    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/audits/quick"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "actions": [],
            "advisories": {},
            "muted": [],
            "metadata": {
                "vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 0,
                    "critical": 0
                },
                "dependencies": 1,
                "devDependencies": 0,
                "optionalDependencies": 0,
                "totalDependencies": 1
            }
        })))
        .mount(&upstream)
        .await;

    Mock::given(method("POST"))
        .and(path("/-/npm/v1/security/audits"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auditReportVersion": 2,
            "vulnerabilities": {},
            "metadata": {
                "vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 0,
                    "critical": 0
                },
                "dependencies": 1,
                "devDependencies": 0,
                "optionalDependencies": 0,
                "totalDependencies": 1
            }
        })))
        .mount(&upstream)
        .await;

    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), Some(upstream.uri())).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/advisories/bulk")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"debug":["2.6.9"]})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["debug"]["severity"].as_str(), Some("low"));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits/quick")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"root","dependencies":{}})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["metadata"]["totalDependencies"].as_u64(), Some(1));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"root","dependencies":{}})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["auditReportVersion"].as_u64(), Some(2));
}

#[tokio::test]
async fn security_audit_endpoints_fallback_without_uplink() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/advisories/bulk")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body, json!({}));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits/quick")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["actions"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        body["metadata"]["vulnerabilities"]["high"].as_u64(),
        Some(0)
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/security/audits")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["auditReportVersion"].as_u64(), Some(2));
    assert!(body.get("vulnerabilities").is_some());
}

#[tokio::test]
async fn publish_validation_and_user_login_edges() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "dora", "secret").await;

    let mut bad_manifest = pkg_manifest("badpkg", "1.0.0", "badpkg-1.0.0.tgz", b"bad");
    bad_manifest["_attachments"] = json!({});
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/badpkg")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&bad_manifest).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("unsupported registry call")
    );

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:dora")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"dora","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert!(body.get("token").and_then(Value::as_str).is_some());

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:dora")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"dora","password":"wrong"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:yeti")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"dora","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("username does not match logged in user")
    );
}

#[tokio::test]
async fn login_session_edge_cases() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/v1/done/not-a-valid-session")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(
        body.get("error").and_then(Value::as_str),
        Some("session id is invalid")
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/v1/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{}".to_vec()))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let done = body
        .get("doneUrl")
        .and_then(Value::as_str)
        .expect("doneUrl");
    let session_id = done
        .split("/-/v1/done/")
        .last()
        .expect("session suffix")
        .to_string();

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/-/v1/done/{session_id}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    assert_eq!(
        resp.headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()),
        Some("5")
    );

    let _token = create_user(&app, "session-user", "password").await;
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("/-/v1/login_cli/{session_id}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"username":"session-user","password":"password"}))
                .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/-/v1/done/{session_id}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_endpoints_disabled_without_web_login_flag() {
    let dir = TempDir::new().expect("dir");
    let app = test_app_with_rules_and_web_login(
        dir.path().to_path_buf(),
        None,
        vec![PackageRule::open("**")],
        false,
    )
    .await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/v1/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{}".to_vec()))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn owner_and_star_flows() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "owner", "secret").await;

    for (name, tarball, data) in [
        ("foo", "foo-1.0.0.tgz", b"foo".as_slice()),
        ("pkg-1", "pkg-1-1.0.0.tgz", b"pkg1".as_slice()),
        ("pkg-2", "pkg-2-1.0.0.tgz", b"pkg2".as_slice()),
    ] {
        let manifest = pkg_manifest(name, "1.0.0", tarball, data);
        let req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/{name}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
            .expect("request");
        assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/foo")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    let body = json_body(resp).await;
    let rev = body
        .get("_rev")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let maintainers = body
        .get("maintainers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(maintainers.len(), 1);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "_rev": rev,
                "_id": "foo",
                "maintainers": [
                    {"name":"owner","email":""},
                    {"name":"tester","email":"test@verdaccio.org"}
                ]
            }))
            .expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "_rev": "1-rustaccio",
                "_id": "foo",
                "maintainers": [{"name":"attacker","email":"a@x"}]
            }))
            .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    for pkg in ["foo", "pkg-1", "pkg-2"] {
        let req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/{pkg}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "_rev": "1-rustaccio",
                    "_id": pkg,
                    "users": {"owner": true}
                }))
                .expect("payload"),
            ))
            .expect("request");
        assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/_view/starredByUser?key=%22owner%22")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    let rows = body["rows"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 3);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/foo")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "_rev": "1-rustaccio",
                "_id": "foo",
                "users": {"owner": false}
            }))
            .expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/_view/starredByUser?key=%22owner%22")
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    let rows = body["rows"].as_array().cloned().unwrap_or_default();
    assert_eq!(rows.len(), 2);
}

#[tokio::test]
async fn scoped_and_encoded_package_routes() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "scopeuser", "secret").await;

    let manifest = pkg_manifest("@scope/foo", "1.0.0", "foo-1.0.0.tgz", b"scoped");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/%40scope%2Ffoo")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    for uri in ["/@scope/foo", "/%40scope%2Ffoo"] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::ACCEPT, "application/vnd.npm.install-v1+json")
            .body(Body::empty())
            .expect("request");
        let resp = send(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/vnd.npm.install-v1+json; charset=utf-8")
        );
        let body = json_body(resp).await;
        assert_eq!(body["name"].as_str(), Some("@scope/foo"));
        assert!(body.get("users").is_none());
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/%40scope%2Ffoo/latest")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["version"].as_str(), Some("1.0.0"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/%40scope%2Ffoo/-/foo-1.0.0.tgz")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(bytes_body(resp).await, b"scoped");
}

#[tokio::test]
async fn user_and_publish_error_paths() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "eve", "secret").await;

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:eve")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"eve","password":"secret"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/-/user/org.couchdb.user:newuser")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"name":"newuser","password":"12"})).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/all")
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/-/user/token/someSecretToken")
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);

    let manifest = pkg_manifest("dead", "1.0.0", "dead-1.0.0.tgz", b"dead");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/dead")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/ghost/-rev/abc")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/dead/-/dead-9.9.9.tgz/-rev/abc")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/dead")
        .header(header::AUTHORIZATION, "Bearer invalid-token")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    assert_eq!(
        body["error"].as_str(),
        Some("authorization required to access package dead")
    );
}

#[tokio::test]
async fn profile_user_and_star_error_edges() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;

    let token = create_user(&app, "edgeuser", "secret").await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/user/org.couchdb.user:edgeuser")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["ok"], json!(false));

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/-/user/token/someSecretToken")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["ok"].as_str(), Some("Logged out"));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "tfa": "_" })).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "password": { "new": "foobar", "old": null } }))
                .expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/-/npm/v1/user")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(
            serde_json::to_vec(&json!({ "another": "_" })).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/_view/starredByUser?key_xxxxx=other")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unpublish_and_search_shape_edges() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "unpublisher", "secret").await;

    let manifest = pkg_manifest("zap", "1.0.0", "zap-1.0.0.tgz", b"zap");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/zap")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/zap/-/zap-1.0.0.tgz/-rev/revision")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["ok"].as_str(), Some("tarball removed"));

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/zap/-rev/revision")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = json_body(resp).await;
    assert_eq!(body["ok"].as_str(), Some("package removed"));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/v1/search?text=zap&size=20&from=0")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body.get("time").and_then(Value::as_str).is_some());
    assert!(body.get("objects").and_then(Value::as_array).is_some());
    assert!(body.get("total").and_then(Value::as_u64).is_some());
}

#[tokio::test]
async fn deprecate_and_undeprecate_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "deprecator", "secret").await;

    let manifest = pkg_manifest("deprecable", "1.0.0", "deprecable-1.0.0.tgz", b"dep");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/deprecable")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/deprecable")
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    let rev = body["_rev"].as_str().unwrap_or_default().to_string();
    let dist_tags = body["dist-tags"].clone();
    let users = body["users"].clone();
    let maintainers = body["maintainers"].clone();
    let time = body["time"].clone();

    let deprecate_body = json!({
        "_id": "deprecable",
        "name": "deprecable",
        "_rev": rev,
        "dist-tags": dist_tags,
        "users": users,
        "maintainers": maintainers,
        "time": time,
        "versions": {
            "1.0.0": {
                "deprecated": "some deprecation message"
            }
        }
    });
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/deprecable")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&deprecate_body).expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/deprecable/1.0.0")
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    assert_eq!(
        body["deprecated"].as_str(),
        Some("some deprecation message")
    );

    let undeprecate_body = json!({
        "_id": "deprecable",
        "name": "deprecable",
        "versions": {
            "1.0.0": {
                "deprecated": ""
            }
        }
    });
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/deprecable")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&undeprecate_body).expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/deprecable/1.0.0")
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    assert!(body.get("deprecated").is_none());
}

#[tokio::test]
async fn unpublish_specific_version_via_put_rev_flow() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "unpub-put", "secret").await;

    for (version, filename, data) in [
        ("1.0.0", "put-unpub-1.0.0.tgz", b"v1".as_slice()),
        ("1.1.0", "put-unpub-1.1.0.tgz", b"v2".as_slice()),
    ] {
        let mut manifest = pkg_manifest("put-unpub", version, filename, data);
        if version == "1.1.0" {
            manifest["dist-tags"] = json!({"latest":"1.1.0"});
        }
        let req = Request::builder()
            .method(Method::PUT)
            .uri("/put-unpub")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
            .expect("request");
        assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri("/put-unpub?write=true")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    let rev = body["_rev"].as_str().unwrap_or_default().to_string();

    let unpublish_body = json!({
        "_id": "put-unpub",
        "name": "put-unpub",
        "_rev": rev,
        "dist-tags": { "latest": "1.1.0" },
        "versions": {
            "1.1.0": body["versions"]["1.1.0"].clone()
        },
        "users": body["users"].clone(),
        "maintainers": body["maintainers"].clone(),
        "time": body["time"].clone(),
        "readme": body["readme"].clone()
    });

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/put-unpub/-rev/any-rev")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&unpublish_body).expect("payload"),
        ))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/put-unpub/1.0.0")
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/put-unpub/1.1.0")
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn metadata_only_update_cannot_add_new_version_without_attachment() {
    let dir = TempDir::new().expect("dir");
    let app = test_app(dir.path().to_path_buf(), None).await;
    let token = create_user(&app, "meta-guard", "secret").await;

    let manifest = pkg_manifest("meta-guard", "1.0.0", "meta-guard-1.0.0.tgz", b"meta");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/meta-guard")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let body = json!({
        "_id": "meta-guard",
        "name": "meta-guard",
        "versions": {
            "1.0.0": {},
            "1.0.1": {}
        },
        "dist-tags": {
            "latest": "1.0.1"
        }
    });
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/meta-guard/-rev/some-rev")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(body["error"].as_str(), Some("unsupported registry call"));
}

#[tokio::test]
async fn acl_authenticated_access_filters_package_and_search() {
    let dir = TempDir::new().expect("dir");
    let rules = vec![
        PackageRule {
            pattern: "vue".to_string(),
            access: vec!["$authenticated".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: None,
        },
        PackageRule {
            pattern: "**".to_string(),
            access: vec!["$all".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: None,
        },
    ];
    let app = test_app_with_rules(dir.path().to_path_buf(), None, rules).await;
    let token = create_user(&app, "acl-user", "secret").await;

    let manifest = pkg_manifest("vue", "1.0.0", "vue-1.0.0.tgz", b"vue");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/vue")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/vue")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = json_body(resp).await;
    assert_eq!(
        body["error"].as_str(),
        Some("authorization required to access package vue")
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/v1/search?text=vue&size=20&from=0")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["objects"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn acl_user_specific_publish_permission() {
    let dir = TempDir::new().expect("dir");
    let rules = vec![
        PackageRule {
            pattern: "private-*".to_string(),
            access: vec!["$all".to_string()],
            publish: vec!["jota".to_string()],
            unpublish: vec!["jota".to_string()],
            proxy: None,
        },
        PackageRule::open("**"),
    ];
    let app = test_app_with_rules(dir.path().to_path_buf(), None, rules).await;
    let jota_token = create_user(&app, "jota", "secret").await;
    let other_token = create_user(&app, "other", "secret").await;

    let manifest = pkg_manifest("private-auth", "1.0.0", "private-auth-1.0.0.tgz", b"pkg");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/private-auth")
        .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/private-auth")
        .header(header::AUTHORIZATION, format!("Bearer {jota_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn acl_anonymous_publish_allowed() {
    let dir = TempDir::new().expect("dir");
    let rules = vec![PackageRule {
        pattern: "**".to_string(),
        access: vec!["$all".to_string()],
        publish: vec!["$anonymous".to_string()],
        unpublish: vec!["$anonymous".to_string()],
        proxy: None,
    }];
    let app = test_app_with_rules(dir.path().to_path_buf(), None, rules).await;

    let manifest = pkg_manifest("anonpkg", "1.0.0", "anonpkg-1.0.0.tgz", b"anon");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/anonpkg")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/anonpkg")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn acl_proxy_rule_selects_named_uplink() {
    let uplink_a = MockServer::start().await;
    let uplink_b = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/special"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&uplink_a)
        .await;
    Mock::given(method("GET"))
        .and(path("/special"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "_id": "special",
            "name": "special",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "special",
                    "version": "1.0.0",
                    "description": "from-b",
                    "dist": { "tarball": format!("{}/special/-/special-1.0.0.tgz", uplink_b.uri()) }
                }
            }
        })))
        .mount(&uplink_b)
        .await;

    let dir = TempDir::new().expect("dir");
    let mut uplinks = HashMap::new();
    uplinks.insert("a".to_string(), uplink_a.uri());
    uplinks.insert("b".to_string(), uplink_b.uri());

    let rules = vec![
        PackageRule {
            pattern: "special".to_string(),
            access: vec!["$all".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: Some("b".to_string()),
        },
        PackageRule {
            pattern: "**".to_string(),
            access: vec!["$all".to_string()],
            publish: vec!["$authenticated".to_string()],
            unpublish: vec!["$authenticated".to_string()],
            proxy: Some("a".to_string()),
        },
    ];

    let app = test_app_with_explicit_uplinks(dir.path().to_path_buf(), uplinks, rules, true).await;
    let req = Request::builder()
        .method(Method::GET)
        .uri("/special")
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["name"].as_str(), Some("special"));
}

#[tokio::test]
async fn publish_check_owners_blocks_non_owner_mutations() {
    let dir = TempDir::new().expect("dir");
    let app = test_app_with_rules_and_options(
        dir.path().to_path_buf(),
        None,
        vec![PackageRule::open("**")],
        true,
        true,
    )
    .await;
    let owner_token = create_user(&app, "owner-check", "secret").await;
    let other_token = create_user(&app, "other-check", "secret").await;

    let manifest = pkg_manifest("guarded", "1.0.0", "guarded-1.0.0.tgz", b"guarded");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/guarded")
        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/guarded?write=true")
        .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
        .body(Body::empty())
        .expect("request");
    let resp = send(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = json_body(resp).await;
    assert_eq!(
        body["error"].as_str(),
        Some("only owners are allowed to change package")
    );

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/guarded/beta")
        .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"\"1.0.0\"".to_vec()))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/guarded/-rev/revision")
        .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn publish_check_owners_allows_owner_mutations() {
    let dir = TempDir::new().expect("dir");
    let app = test_app_with_rules_and_options(
        dir.path().to_path_buf(),
        None,
        vec![PackageRule::open("**")],
        true,
        true,
    )
    .await;
    let owner_token = create_user(&app, "owner-pass", "secret").await;

    let manifest = pkg_manifest("ownedpkg", "1.0.0", "ownedpkg-1.0.0.tgz", b"owned");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/ownedpkg")
        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/ownedpkg/beta")
        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"\"1.0.0\"".to_vec()))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/-/package/ownedpkg/dist-tags/beta")
        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn publish_check_owners_disabled_allows_non_owner_mutations() {
    let dir = TempDir::new().expect("dir");
    let app = test_app_with_rules_and_options(
        dir.path().to_path_buf(),
        None,
        vec![PackageRule::open("**")],
        true,
        false,
    )
    .await;
    let owner_token = create_user(&app, "owner-free", "secret").await;
    let other_token = create_user(&app, "other-free", "secret").await;

    let manifest = pkg_manifest("freepkg", "1.0.0", "freepkg-1.0.0.tgz", b"free");
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/freepkg")
        .header(header::AUTHORIZATION, format!("Bearer {owner_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/freepkg/beta")
        .header(header::AUTHORIZATION, format!("Bearer {other_token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"\"1.0.0\"".to_vec()))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
}
