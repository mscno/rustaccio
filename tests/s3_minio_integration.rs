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
use http_body_util::BodyExt;
use rustaccio::{
    acl::PackageRule,
    app::build_router,
    config::{
        AuthBackend, AuthPluginConfig, Config, S3TarballStorageConfig, TarballStorageBackend,
        TarballStorageConfig,
    },
    runtime,
};
use serde_json::{Value, json};
use std::{collections::HashMap, time::Duration};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;

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
                "dist": {
                    "tarball": format!("http://localhost:5555/{pkg}/-/{tarball_filename}")
                }
            }
        },
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

fn s3_it_config(
    data_dir: std::path::PathBuf,
    endpoint: String,
    bucket: String,
    prefix: String,
) -> Config {
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
            backend: TarballStorageBackend::S3,
            s3: Some(S3TarballStorageConfig {
                bucket,
                region: it_region(),
                endpoint: Some(endpoint),
                access_key_id: Some(it_access_key()),
                secret_access_key: Some(it_secret_key()),
                prefix,
                force_path_style: true,
            }),
        },
    }
}

async fn list_keys(client: &S3Client, bucket: &str, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut continuation = None;

    loop {
        let mut req = client.list_objects_v2().bucket(bucket).prefix(prefix);
        if let Some(token) = continuation.clone() {
            req = req.continuation_token(token);
        }
        let resp = req.send().await.expect("list objects");
        for object in resp.contents() {
            if let Some(key) = object.key() {
                out.push(key.to_string());
            }
        }
        if resp.is_truncated.unwrap_or(false) {
            continuation = resp.next_continuation_token;
        } else {
            break;
        }
    }

    out
}

#[tokio::test]
#[ignore = "requires local MinIO (`just minio-up`)"]
async fn minio_backend_publish_and_put_rev_unpublish_flow() {
    let endpoint = it_endpoint();
    let region = it_region();
    let bucket = it_bucket();
    let access_key = it_access_key();
    let secret_key = it_secret_key();

    let s3 = s3_client(&endpoint, &region, &access_key, &secret_key).await;
    wait_for_s3(&s3).await;
    ensure_bucket(&s3, &bucket).await;

    let package = "minio-it-pkg";
    let prefix = format!("rustaccio-it-{}/", Uuid::new_v4().as_simple());

    let dir = TempDir::new().expect("temp dir");
    let cfg = s3_it_config(
        dir.path().to_path_buf(),
        endpoint.clone(),
        bucket.clone(),
        prefix.clone(),
    );
    let state = runtime::build_state(&cfg, None).await.expect("state");
    let app = build_router(state);

    let token = create_user(&app, "minio-it-user", "secret").await;

    for (version, filename, data) in [
        ("1.0.0", "minio-it-pkg-1.0.0.tgz", b"v1".as_slice()),
        ("1.1.0", "minio-it-pkg-1.1.0.tgz", b"v2".as_slice()),
    ] {
        let mut manifest = pkg_manifest(package, version, filename, data);
        if version == "1.1.0" {
            manifest["dist-tags"] = json!({"latest":"1.1.0"});
        }
        let req = Request::builder()
            .method(Method::PUT)
            .uri(format!("/{package}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&manifest).expect("payload")))
            .expect("request");
        assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);
    }

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/{package}?write=true"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let body = json_body(send(&app, req).await).await;
    let rev = body["_rev"].as_str().unwrap_or_default().to_string();
    let unpublish_body = json!({
        "_id": package,
        "name": package,
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
        .uri(format!("/{package}/-rev/any-rev"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&unpublish_body).expect("payload"),
        ))
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::CREATED);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/{package}/-/minio-it-pkg-1.0.0.tgz"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::NOT_FOUND);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/{package}/-/minio-it-pkg-1.1.0.tgz"))
        .body(Body::empty())
        .expect("request");
    assert_eq!(send(&app, req).await.status(), StatusCode::OK);

    let sidecar_key = format!("{prefix}{package}/package.json");
    let sidecar_resp = s3
        .get_object()
        .bucket(&bucket)
        .key(sidecar_key)
        .send()
        .await
        .expect("sidecar object");
    let sidecar_bytes = sidecar_resp
        .body
        .collect()
        .await
        .expect("collect sidecar")
        .into_bytes();
    let sidecar: Value = serde_json::from_slice(&sidecar_bytes).expect("parse sidecar");
    assert!(sidecar["versions"].get("1.0.0").is_none());
    assert!(sidecar["versions"].get("1.1.0").is_some());
    assert!(
        sidecar["_attachments"]
            .get("minio-it-pkg-1.0.0.tgz")
            .is_none()
    );
    assert!(
        sidecar["_attachments"]
            .get("minio-it-pkg-1.1.0.tgz")
            .is_some()
    );

    let keys = list_keys(&s3, &bucket, &format!("{prefix}{package}/")).await;
    assert!(
        keys.iter().any(|key| key.ends_with("package.json")),
        "sidecar package.json should be present"
    );
    assert!(
        keys.iter()
            .any(|key| key.ends_with("minio-it-pkg-1.1.0.tgz")),
        "retained tarball should be present in bucket"
    );
    assert!(
        !keys
            .iter()
            .any(|key| key.ends_with("minio-it-pkg-1.0.0.tgz")),
        "removed tarball should be deleted from bucket"
    );
}
