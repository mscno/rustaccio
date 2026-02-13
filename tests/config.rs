use rustaccio::config::{AuthBackend, Config, TarballStorageBackend};
use std::{io::Write, path::PathBuf};

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

    let cfg = Config::from_env_with_config_file(file.path().to_path_buf()).expect("parse");
    assert_eq!(cfg.listen, vec!["127.0.0.1:4999".to_string()]);
    assert_eq!(cfg.web_title, "Config From Cli");
    assert!(!cfg.web_enabled);
}

#[test]
fn from_env_with_config_file_errors_for_missing_path() {
    let missing = std::env::temp_dir().join("rustaccio-does-not-exist.yml");
    let err = Config::from_env_with_config_file(missing).expect_err("missing file");
    assert!(err.contains("failed to read"));
}
