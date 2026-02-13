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
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tempfile::TempDir;
use tower::ServiceExt;

#[derive(Debug)]
struct EmbeddedHook;

#[async_trait]
impl AuthHook for EmbeddedHook {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, rustaccio::error::RegistryError> {
        Ok(Some(AuthIdentity {
            username: Some("geo-admin".to_string()),
            groups: vec!["geo-admin".to_string()],
        }))
    }
}

#[derive(Debug)]
struct DenyPublishHook;

#[async_trait]
impl AuthHook for DenyPublishHook {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, rustaccio::error::RegistryError> {
        Ok(Some(AuthIdentity {
            username: Some("geo-admin".to_string()),
            groups: vec!["geo-admin".to_string()],
        }))
    }

    async fn allow_publish(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, rustaccio::error::RegistryError> {
        Ok(Some(false))
    }
}

#[derive(Debug)]
struct AllowPublishHook;

#[async_trait]
impl AuthHook for AllowPublishHook {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, rustaccio::error::RegistryError> {
        Ok(Some(AuthIdentity {
            username: Some("geo-admin".to_string()),
            groups: vec!["geo-admin".to_string()],
        }))
    }

    async fn allow_publish(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, rustaccio::error::RegistryError> {
        Ok(Some(true))
    }
}

#[derive(Debug)]
struct DenyAccessHook;

#[async_trait]
impl AuthHook for DenyAccessHook {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, rustaccio::error::RegistryError> {
        Ok(Some(AuthIdentity {
            username: Some("geo-admin".to_string()),
            groups: vec!["geo-admin".to_string()],
        }))
    }

    async fn allow_publish(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, rustaccio::error::RegistryError> {
        Ok(Some(true))
    }

    async fn allow_access(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, rustaccio::error::RegistryError> {
        Ok(Some(false))
    }
}
#[tokio::test]
async fn embedded_auth_hook_can_drive_acl_permissions() {
    let dir = TempDir::new().expect("dir");
    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir: dir.path().to_path_buf(),
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule {
            pattern: "**".to_string(),
            access: vec!["geo-admin".to_string()],
            publish: vec!["geo-admin".to_string()],
            unpublish: vec!["geo-admin".to_string()],
            proxy: None,
        }],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        web_login: false,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        max_body_size: 10 * 1024 * 1024,
        audit_enabled: true,
        url_prefix: "/".to_string(),
        trust_proxy: false,
        keep_alive_timeout_secs: None,
        log_level: "info".to_string(),
        auth_plugin: AuthPluginConfig {
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
        },
        tarball_storage: TarballStorageConfig {
            backend: TarballStorageBackend::Local,
            s3: None,
        },
    };

    let state = runtime::build_state(&cfg, Some(Arc::new(EmbeddedHook)))
        .await
        .expect("state");
    let app = build_router(state);

    let manifest = json!({
        "_id": "hookpkg",
        "name": "hookpkg",
        "dist-tags": { "latest": "1.0.0" },
        "versions": {
            "1.0.0": {
                "name": "hookpkg",
                "version": "1.0.0",
                "dist": { "tarball": "http://localhost:4873/hookpkg/-/hookpkg-1.0.0.tgz" }
            }
        },
        "_attachments": {
            "hookpkg-1.0.0.tgz": {
                "content_type": "application/octet-stream",
                "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"abc"),
                "length": 3
            }
        }
    });

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/hookpkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/-/whoami")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .body(Body::empty())
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(
        body.get("username").and_then(|v| v.as_str()),
        Some("geo-admin")
    );
}
#[tokio::test]
async fn embedded_allow_publish_can_deny_even_if_acl_allows() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir: dir.path().to_path_buf(),
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        web_login: false,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        max_body_size: 10 * 1024 * 1024,
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
    };
    cfg.acl_rules[0].publish = vec!["$all".to_string()];

    let state = runtime::build_state(&cfg, Some(Arc::new(DenyPublishHook)))
        .await
        .expect("state");
    let app = build_router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/deny-pkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&base_manifest("deny-pkg")).expect("payload"),
        ))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn embedded_allow_publish_can_allow_even_if_acl_denies() {
    let dir = TempDir::new().expect("dir");
    let mut cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir: dir.path().to_path_buf(),
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        web_login: false,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        max_body_size: 10 * 1024 * 1024,
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
    };
    cfg.acl_rules[0].publish = vec!["nobody".to_string()];

    let state = runtime::build_state(&cfg, Some(Arc::new(AllowPublishHook)))
        .await
        .expect("state");
    let app = build_router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/allow-pkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&base_manifest("allow-pkg")).expect("payload"),
        ))
        .expect("request");
    let resp = app.oneshot(req).await.expect("response");
    assert_eq!(resp.status(), StatusCode::CREATED);
}

fn base_manifest(name: &str) -> serde_json::Value {
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
async fn embedded_allow_access_can_deny_even_if_acl_allows() {
    let dir = TempDir::new().expect("dir");
    let cfg = Config {
        bind: "127.0.0.1:0".parse().expect("bind"),
        data_dir: dir.path().to_path_buf(),
        listen: vec!["127.0.0.1:0".to_string()],
        upstream_registry: None,
        uplinks: HashMap::new(),
        acl_rules: vec![PackageRule::open("**")],
        web_enabled: true,
        web_title: "Rustaccio".to_string(),
        web_login: false,
        publish_check_owners: false,
        password_min_length: 3,
        login_session_ttl_seconds: 120,
        max_body_size: 10 * 1024 * 1024,
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
    };

    let state = runtime::build_state(&cfg, Some(Arc::new(DenyAccessHook)))
        .await
        .expect("state");
    let app = build_router(state);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/access-deny-pkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&base_manifest("access-deny-pkg")).expect("payload"),
        ))
        .expect("request");
    assert_eq!(
        app.clone().oneshot(req).await.expect("response").status(),
        StatusCode::CREATED
    );

    let req = Request::builder()
        .method(Method::GET)
        .uri("/access-deny-pkg")
        .header(header::AUTHORIZATION, "Bearer embedded-token")
        .body(Body::empty())
        .expect("request");
    assert_eq!(
        app.oneshot(req).await.expect("response").status(),
        StatusCode::UNAUTHORIZED
    );
}
