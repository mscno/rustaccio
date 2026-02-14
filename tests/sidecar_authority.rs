use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rustaccio::{
    config::{AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig},
    storage::{Store, package_name_to_encoded},
};
use serde_json::{Value, json};
use std::{collections::HashMap, future::Future, sync::OnceLock};
use tempfile::TempDir;

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

async fn with_sidecar_authority_env<T, F>(run: F) -> T
where
    F: Future<Output = T>,
{
    let _guard = env_lock().lock().await;
    let previous = std::env::var("RUSTACCIO_PACKAGE_METADATA_AUTHORITY").ok();
    unsafe {
        std::env::set_var("RUSTACCIO_PACKAGE_METADATA_AUTHORITY", "sidecar");
    }
    let result = run.await;
    unsafe {
        if let Some(value) = previous {
            std::env::set_var("RUSTACCIO_PACKAGE_METADATA_AUTHORITY", value);
        } else {
            std::env::remove_var("RUSTACCIO_PACKAGE_METADATA_AUTHORITY");
        }
    }
    result
}

fn publish_body(
    package_name: &str,
    version: &str,
    tarball_filename: &str,
    content: &[u8],
) -> Value {
    json!({
        "_id": package_name,
        "name": package_name,
        "versions": {
            version: {
                "name": package_name,
                "version": version,
                "dist": {
                    "tarball": format!(
                        "http://localhost:4873/{}/-/{}",
                        package_name_to_encoded(package_name),
                        tarball_filename
                    )
                }
            }
        },
        "dist-tags": {
            "latest": version
        },
        "_attachments": {
            tarball_filename: {
                "version": version,
                "length": content.len(),
                "shasum": "",
                "data": B64.encode(content),
            }
        }
    })
}

#[tokio::test]
async fn sidecar_authority_keeps_state_auth_only() {
    with_sidecar_authority_env(async {
        let dir = TempDir::new().expect("dir");
        let data_dir = dir.path().to_path_buf();
        let cfg = base_config(data_dir.clone());
        let store = Store::open(&cfg).await.expect("store");

        let _token = store
            .create_user("sidecar-owner", "secret")
            .await
            .expect("create user");
        let state_file = data_dir.join("state.json");
        let bytes = tokio::fs::read(&state_file).await.expect("read state");
        let state_json: Value = serde_json::from_slice(&bytes).expect("state json");
        assert!(
            state_json
                .get("users")
                .and_then(Value::as_object)
                .is_some_and(|users| users.contains_key("sidecar-owner"))
        );
        assert!(
            state_json
                .get("packages")
                .and_then(Value::as_object)
                .is_some_and(|packages| packages.is_empty())
        );

        let body = publish_body("sidecar-demo", "1.0.0", "sidecar-demo-1.0.0.tgz", b"demo");
        store
            .publish_manifest("sidecar-demo", body, "sidecar-owner")
            .await
            .expect("publish");
        let bytes = tokio::fs::read(&state_file).await.expect("read state");
        let state_json: Value = serde_json::from_slice(&bytes).expect("state json");
        assert!(
            state_json
                .get("packages")
                .and_then(Value::as_object)
                .is_some_and(|packages| packages.is_empty())
        );
    })
    .await;
}

#[tokio::test]
async fn sidecar_authority_reads_latest_sidecar_manifest() {
    with_sidecar_authority_env(async {
        let dir = TempDir::new().expect("dir");
        let data_dir = dir.path().to_path_buf();
        let cfg = base_config(data_dir.clone());
        let store = Store::open(&cfg).await.expect("store");
        store
            .create_user("sidecar-reader", "secret")
            .await
            .expect("create user");

        let body = publish_body("sidecar-live", "1.0.0", "sidecar-live-1.0.0.tgz", b"live");
        store
            .publish_manifest("sidecar-live", body, "sidecar-reader")
            .await
            .expect("publish");

        let sidecar_path = data_dir
            .join("tarballs")
            .join("sidecar-live")
            .join("package.json");
        let mut sidecar: Value =
            serde_json::from_slice(&tokio::fs::read(&sidecar_path).await.expect("read sidecar"))
                .expect("parse sidecar");
        sidecar["description"] = Value::String("updated-by-sidecar".to_string());
        tokio::fs::write(
            &sidecar_path,
            serde_json::to_vec_pretty(&sidecar).expect("encode"),
        )
        .await
        .expect("write sidecar");

        let refreshed = store
            .get_package_record("sidecar-live")
            .await
            .expect("package");
        assert_eq!(
            refreshed
                .manifest
                .get("description")
                .and_then(Value::as_str),
            Some("updated-by-sidecar")
        );
    })
    .await;
}

#[tokio::test]
async fn sidecar_authority_can_rebuild_record_when_sidecar_missing() {
    with_sidecar_authority_env(async {
        let dir = TempDir::new().expect("dir");
        let data_dir = dir.path().to_path_buf();
        let cfg = base_config(data_dir.clone());
        let store = Store::open(&cfg).await.expect("store");
        store
            .create_user("sidecar-rebuild", "secret")
            .await
            .expect("create user");

        let filename = "sidecar-rebuild-1.0.0.tgz";
        let body = publish_body("sidecar-rebuild", "1.0.0", filename, b"pkg");
        store
            .publish_manifest("sidecar-rebuild", body, "sidecar-rebuild")
            .await
            .expect("publish");

        let sidecar_path = data_dir
            .join("tarballs")
            .join("sidecar-rebuild")
            .join("package.json");
        tokio::fs::remove_file(&sidecar_path)
            .await
            .expect("remove sidecar");

        let rebuilt = store
            .get_package_record("sidecar-rebuild")
            .await
            .expect("package");
        assert!(
            rebuilt
                .manifest
                .get("_attachments")
                .and_then(Value::as_object)
                .is_some_and(|attachments| attachments.contains_key(filename))
        );
    })
    .await;
}
