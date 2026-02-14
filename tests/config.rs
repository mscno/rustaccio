use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rustaccio::config::{AuthBackend, Config, TarballStorageBackend};
use std::{collections::HashSet, io::Write, path::PathBuf, sync::Mutex};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn parses_verdaccio_style_acl_and_uplinks() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        file,
        r#"
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
packages:
  'vue':
    access: $authenticated
    publish: $authenticated
    proxy: npmjs
  '**':
    access: $all
    publish: $authenticated
    unpublish: $authenticated
flags:
  webLogin: true
publish:
  check_owners: true
"#
    )
    .expect("write");

    let cfg = Config::from_yaml_file(file.path().to_path_buf()).expect("parse");
    assert_eq!(
        cfg.uplinks.get("npmjs").map(String::as_str),
        Some("https://registry.npmjs.org")
    );
    assert_eq!(cfg.acl_rules.len(), 2);
    assert_eq!(cfg.acl_rules[0].pattern, "vue");
    assert_eq!(cfg.acl_rules[0].proxy.as_deref(), Some("npmjs"));
    assert_eq!(cfg.acl_rules[1].pattern, "**");
    assert!(cfg.web_login);
    assert!(cfg.publish_check_owners);
    assert_eq!(cfg.auth_plugin.backend, AuthBackend::Local);
    assert_eq!(cfg.tarball_storage.backend, TarballStorageBackend::Local);
}

#[test]
fn parses_plugin_config_sections() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        file,
        r#"
auth:
  backend: http
  external: true
  http:
    baseUrl: http://auth.local:9000
    addUserEndpoint: /users/add
    loginEndpoint: /users/login
    changePasswordEndpoint: /users/password
    requestAuthEndpoint: /request-auth
    allowAccessEndpoint: /allow-access
    allowPublishEndpoint: /allow-publish
    allowUnpublishEndpoint: /allow-unpublish
    timeoutMs: 2500
storage:
  backend: s3
  s3:
    bucket: npm-cache
    region: eu-north-1
    endpoint: http://127.0.0.1:9001
    accessKeyId: minio
    secretAccessKey: miniopass
    prefix: tarballs/
    forcePathStyle: true
"#
    )
    .expect("write");

    let cfg = Config::from_yaml_file(file.path().to_path_buf()).expect("parse");
    assert_eq!(cfg.auth_plugin.backend, AuthBackend::Http);
    assert!(cfg.auth_plugin.external_mode);
    let auth = cfg.auth_plugin.http.expect("http auth");
    assert_eq!(auth.base_url, "http://auth.local:9000");
    assert_eq!(auth.add_user_endpoint, "/users/add");
    assert_eq!(auth.login_endpoint, "/users/login");
    assert_eq!(auth.change_password_endpoint, "/users/password");
    assert_eq!(auth.request_auth_endpoint.as_deref(), Some("/request-auth"));
    assert_eq!(auth.allow_access_endpoint.as_deref(), Some("/allow-access"));
    assert_eq!(
        auth.allow_publish_endpoint.as_deref(),
        Some("/allow-publish")
    );
    assert_eq!(
        auth.allow_unpublish_endpoint.as_deref(),
        Some("/allow-unpublish")
    );
    assert_eq!(auth.timeout_ms, 2500);
    assert_eq!(cfg.tarball_storage.backend, TarballStorageBackend::S3);
}

#[test]
fn parses_native_verdaccio_runtime_options() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        file,
        r#"
storage: ./storage
listen:
  - 0.0.0.0:4873
web:
  title: Geoman-NPM
  enable: false
middlewares:
  audit:
    enabled: false
server:
  keepAliveTimeout: 60
  trustProxy: '127.0.0.1'
max_body_size: 10mb
url_prefix: /verdaccio/
log:
  level: debug
store:
  aws-s3-storage:
    bucket: npm-cache
    region: eu-north-1
    endpoint: http://127.0.0.1:9001
    accessKeyId: minio
    secretAccessKey: miniopass
    prefix: tarballs/
    s3ForcePathStyle: true
"#
    )
    .expect("write");

    let cfg = Config::from_yaml_file(file.path().to_path_buf()).expect("parse");
    assert_eq!(cfg.data_dir, PathBuf::from("./storage"));
    assert_eq!(cfg.listen, vec!["0.0.0.0:4873".to_string()]);
    assert!(!cfg.web_enabled);
    assert_eq!(cfg.web_title, "Geoman-NPM");
    assert!(!cfg.audit_enabled);
    assert!(cfg.trust_proxy);
    assert_eq!(cfg.keep_alive_timeout_secs, Some(60));
    assert_eq!(cfg.max_body_size, 10 * 1024 * 1024);
    assert_eq!(cfg.url_prefix, "/verdaccio");
    assert_eq!(cfg.log_level, "debug");
    assert_eq!(cfg.tarball_storage.backend, TarballStorageBackend::S3);
}

#[test]
fn from_env_with_config_file_loads_explicit_path() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        file,
        r#"
listen:
  - 127.0.0.1:4999
web:
  title: Config From Cli
  enable: false
"#
    )
    .expect("write");

    without_config_env(|| {
        let cfg = Config::from_env_with_config_file(file.path().to_path_buf()).expect("parse");
        assert_eq!(cfg.listen, vec!["127.0.0.1:4999".to_string()]);
        assert_eq!(cfg.web_title, "Config From Cli");
        assert!(!cfg.web_enabled);
    });
}

#[test]
fn from_env_with_config_file_errors_for_missing_path() {
    without_config_env(|| {
        let missing = std::env::temp_dir().join("rustaccio-does-not-exist.yml");
        let err = Config::from_env_with_config_file(missing).expect_err("missing file");
        assert!(err.contains("failed to read"));
    });
}

#[test]
fn from_env_errors_when_rustaccio_config_path_is_invalid() {
    with_env_vars(
        &[
            (
                "RUSTACCIO_CONFIG",
                Some("/definitely/missing/rustaccio.yml"),
            ),
            ("RUSTACCIO_CONFIG_BASE64", None),
            ("PORT", None),
            ("RUSTACCIO_BIND", None),
        ],
        || {
            let err = Config::from_env().expect_err("invalid env config");
            assert!(err.contains("failed to load RUSTACCIO_CONFIG"));
        },
    );
}

#[test]
fn from_env_loads_rustaccio_config_base64() {
    let yaml = r#"
listen:
  - 127.0.0.1:5111
web:
  title: Base64 Config
  enable: false
"#;
    let encoded = B64.encode(yaml.as_bytes());

    with_env_vars(
        &[
            ("RUSTACCIO_CONFIG", None),
            ("RUSTACCIO_CONFIG_BASE64", Some(encoded.as_str())),
            ("PORT", None),
            ("RUSTACCIO_BIND", None),
        ],
        || {
            let cfg = Config::from_env().expect("config from base64 env");
            assert_eq!(cfg.listen, vec!["127.0.0.1:5111".to_string()]);
            assert_eq!(cfg.web_title, "Base64 Config");
            assert!(!cfg.web_enabled);
        },
    );
}

#[test]
fn from_env_errors_when_rustaccio_config_base64_is_invalid() {
    with_env_vars(
        &[
            ("RUSTACCIO_CONFIG", None),
            ("RUSTACCIO_CONFIG_BASE64", Some("%%%not-base64%%%")),
            ("PORT", None),
            ("RUSTACCIO_BIND", None),
        ],
        || {
            let err = Config::from_env().expect_err("invalid base64 config");
            assert!(err.contains("failed to decode RUSTACCIO_CONFIG_BASE64"));
        },
    );
}

#[test]
fn from_env_errors_when_both_config_sources_are_set() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(file, "web:\n  title: From Path").expect("write");
    let yaml = "web:\n  title: From Base64";
    let encoded = B64.encode(yaml.as_bytes());

    with_env_vars(
        &[
            (
                "RUSTACCIO_CONFIG",
                Some(file.path().to_str().expect("utf8 path")),
            ),
            ("RUSTACCIO_CONFIG_BASE64", Some(encoded.as_str())),
            ("PORT", None),
            ("RUSTACCIO_BIND", None),
        ],
        || {
            let err = Config::from_env().expect_err("conflicting config sources");
            assert!(err.contains("RUSTACCIO_CONFIG and RUSTACCIO_CONFIG_BASE64"));
        },
    );
}

#[test]
fn from_env_uses_port_env_for_platform_compatibility() {
    with_env_vars(
        &[
            ("RUSTACCIO_BIND", None),
            ("RUSTACCIO_CONFIG", None),
            ("RUSTACCIO_CONFIG_BASE64", None),
            ("PORT", Some("6123")),
        ],
        || {
            let cfg = Config::from_env().expect("config from env");
            assert_eq!(cfg.listen, vec!["0.0.0.0:6123".to_string()]);
        },
    );
}

#[test]
fn port_env_overrides_rustaccio_bind() {
    with_env_vars(
        &[
            ("RUSTACCIO_BIND", Some("127.0.0.1:4999")),
            ("RUSTACCIO_CONFIG", None),
            ("RUSTACCIO_CONFIG_BASE64", None),
            ("PORT", Some("6123")),
        ],
        || {
            let cfg = Config::from_env().expect("config from env");
            assert_eq!(cfg.listen, vec!["0.0.0.0:6123".to_string()]);
        },
    );
}

#[test]
fn merge_precedence_defaults_then_files_then_env() {
    let mut env_file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        env_file,
        r#"
listen:
  - 127.0.0.1:4888
web:
  title: Env File
  enable: false
log:
  level: warn
store:
  backend: local
"#
    )
    .expect("write");

    let mut cli_file = tempfile::NamedTempFile::new().expect("temp file");
    writeln!(
        cli_file,
        r#"
listen:
  - 127.0.0.1:4999
web:
  title: Cli File
  enable: false
log:
  level: error
store:
  backend: s3
"#
    )
    .expect("write");

    with_env_vars(
        &[
            ("RUSTACCIO_BIND", None),
            ("PORT", None),
            ("RUSTACCIO_DATA_DIR", None),
            (
                "RUSTACCIO_CONFIG",
                Some(env_file.path().to_str().expect("utf8 path")),
            ),
            ("RUSTACCIO_CONFIG_BASE64", None),
            ("RUSTACCIO_UPSTREAM", None),
            ("RUSTACCIO_WEB_LOGIN", None),
            ("RUSTACCIO_WEB_ENABLE", Some("true")),
            ("RUSTACCIO_WEB_TITLE", Some("Env Var")),
            ("RUSTACCIO_PUBLISH_CHECK_OWNERS", None),
            ("RUSTACCIO_PASSWORD_MIN", None),
            ("RUSTACCIO_LOGIN_SESSION_TTL_SECONDS", None),
            ("RUSTACCIO_MAX_BODY_SIZE", None),
            ("RUSTACCIO_AUDIT_ENABLED", None),
            ("RUSTACCIO_URL_PREFIX", None),
            ("RUSTACCIO_TRUST_PROXY", None),
            ("RUSTACCIO_KEEP_ALIVE_TIMEOUT", None),
            ("RUSTACCIO_LOG_LEVEL", None),
            ("RUSTACCIO_TARBALL_BACKEND", Some("s3")),
            ("RUSTACCIO_S3_BUCKET", Some("env-bucket")),
            ("RUSTACCIO_S3_REGION", Some("eu-west-1")),
            ("RUSTACCIO_S3_ENDPOINT", None),
            ("RUSTACCIO_S3_ACCESS_KEY_ID", None),
            ("RUSTACCIO_S3_SECRET_ACCESS_KEY", None),
            ("RUSTACCIO_S3_PREFIX", None),
            ("RUSTACCIO_S3_FORCE_PATH_STYLE", None),
            ("RUSTACCIO_AUTH_BACKEND", Some("http")),
            ("RUSTACCIO_AUTH_EXTERNAL_MODE", None),
            ("RUSTACCIO_AUTH_HTTP_BASE_URL", Some("http://auth-from-env")),
            ("RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_ACCESS_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_PUBLISH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_UNPUBLISH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_TIMEOUT_MS", None),
        ],
        || {
            let cfg =
                Config::from_env_with_config_file(cli_file.path().to_path_buf()).expect("load");
            assert_eq!(cfg.listen, vec!["127.0.0.1:4999".to_string()]);
            assert!(cfg.web_enabled);
            assert_eq!(cfg.web_title, "Env Var");
            assert_eq!(cfg.log_level, "error");
            assert_eq!(cfg.tarball_storage.backend, TarballStorageBackend::S3);
            let s3 = cfg.tarball_storage.s3.expect("s3");
            assert_eq!(s3.bucket, "env-bucket");
            assert_eq!(s3.region, "eu-west-1");
            assert_eq!(cfg.auth_plugin.backend, AuthBackend::Http);
            let http = cfg.auth_plugin.http.expect("http");
            assert_eq!(http.base_url, "http://auth-from-env");
        },
    );
}

fn with_env_vars(vars: &[(&str, Option<&str>)], run: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let keys = vars
        .iter()
        .map(|(key, _)| key.to_string())
        .collect::<HashSet<_>>();
    let previous = keys
        .iter()
        .map(|key| (key.clone(), std::env::var(key).ok()))
        .collect::<Vec<_>>();

    for (key, value) in vars {
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    let run_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(run));

    for (key, value) in previous {
        unsafe {
            match value {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
    }

    if let Err(payload) = run_result {
        std::panic::resume_unwind(payload);
    }
}

fn without_config_env(run: impl FnOnce()) {
    with_env_vars(
        &[
            ("RUSTACCIO_BIND", None),
            ("PORT", None),
            ("RUSTACCIO_DATA_DIR", None),
            ("RUSTACCIO_CONFIG", None),
            ("RUSTACCIO_CONFIG_BASE64", None),
            ("RUSTACCIO_UPSTREAM", None),
            ("RUSTACCIO_WEB_LOGIN", None),
            ("RUSTACCIO_WEB_ENABLE", None),
            ("RUSTACCIO_WEB_TITLE", None),
            ("RUSTACCIO_PUBLISH_CHECK_OWNERS", None),
            ("RUSTACCIO_PASSWORD_MIN", None),
            ("RUSTACCIO_LOGIN_SESSION_TTL_SECONDS", None),
            ("RUSTACCIO_MAX_BODY_SIZE", None),
            ("RUSTACCIO_AUDIT_ENABLED", None),
            ("RUSTACCIO_URL_PREFIX", None),
            ("RUSTACCIO_TRUST_PROXY", None),
            ("RUSTACCIO_KEEP_ALIVE_TIMEOUT", None),
            ("RUSTACCIO_LOG_LEVEL", None),
            ("RUSTACCIO_AUTH_BACKEND", None),
            ("RUSTACCIO_AUTH_EXTERNAL_MODE", None),
            ("RUSTACCIO_AUTH_HTTP_BASE_URL", None),
            ("RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_ACCESS_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_PUBLISH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_ALLOW_UNPUBLISH_ENDPOINT", None),
            ("RUSTACCIO_AUTH_HTTP_TIMEOUT_MS", None),
            ("RUSTACCIO_TARBALL_BACKEND", None),
            ("RUSTACCIO_S3_BUCKET", None),
            ("RUSTACCIO_S3_REGION", None),
            ("RUSTACCIO_S3_ENDPOINT", None),
            ("RUSTACCIO_S3_ACCESS_KEY_ID", None),
            ("RUSTACCIO_S3_SECRET_ACCESS_KEY", None),
            ("RUSTACCIO_S3_PREFIX", None),
            ("RUSTACCIO_S3_FORCE_PATH_STYLE", None),
        ],
        run,
    );
}
