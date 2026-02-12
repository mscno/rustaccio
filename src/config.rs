use crate::acl::PackageRule;
use serde::Deserialize;
use std::{collections::HashMap, env, net::SocketAddr, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthBackend {
    Local,
    Http,
}

impl AuthBackend {
    fn from_str(value: &str) -> Self {
        if value.eq_ignore_ascii_case("http") {
            Self::Http
        } else {
            Self::Local
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAuthPluginConfig {
    pub base_url: String,
    pub add_user_endpoint: String,
    pub login_endpoint: String,
    pub change_password_endpoint: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPluginConfig {
    pub backend: AuthBackend,
    pub http: Option<HttpAuthPluginConfig>,
}

impl Default for AuthPluginConfig {
    fn default() -> Self {
        Self {
            backend: AuthBackend::Local,
            http: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TarballStorageBackend {
    Local,
    S3,
}

impl TarballStorageBackend {
    fn from_str(value: &str) -> Self {
        if value.eq_ignore_ascii_case("s3") {
            Self::S3
        } else {
            Self::Local
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3TarballStorageConfig {
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub prefix: String,
    pub force_path_style: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarballStorageConfig {
    pub backend: TarballStorageBackend,
    pub s3: Option<S3TarballStorageConfig>,
}

impl Default for TarballStorageConfig {
    fn default() -> Self {
        Self {
            backend: TarballStorageBackend::Local,
            s3: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub upstream_registry: Option<String>,
    pub uplinks: HashMap<String, String>,
    pub acl_rules: Vec<PackageRule>,
    pub web_login: bool,
    pub publish_check_owners: bool,
    pub password_min_length: usize,
    pub login_session_ttl_seconds: i64,
    pub auth_plugin: AuthPluginConfig,
    pub tarball_storage: TarballStorageConfig,
}

impl Config {
    pub fn from_env() -> Self {
        let bind = env::var("RUSTACCIO_BIND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| "127.0.0.1:4873".parse().expect("valid default bind"));

        let data_dir = env::var("RUSTACCIO_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".rustaccio-data"));

        let upstream_registry = env::var("RUSTACCIO_UPSTREAM")
            .ok()
            .map(|v| v.trim_end_matches('/').to_string())
            .filter(|v| !v.is_empty());

        let password_min_length = env::var("RUSTACCIO_PASSWORD_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3);

        let login_session_ttl_seconds = env::var("RUSTACCIO_LOGIN_SESSION_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120);

        let web_login = env::var("RUSTACCIO_WEB_LOGIN")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        let publish_check_owners = env::var("RUSTACCIO_PUBLISH_CHECK_OWNERS")
            .ok()
            .and_then(|v| v.parse::<bool>().ok())
            .unwrap_or(false);

        let auth_plugin = parse_auth_from_env();
        let tarball_storage = parse_storage_from_env();

        let mut cfg = Self {
            bind,
            data_dir,
            upstream_registry,
            uplinks: HashMap::new(),
            acl_rules: vec![PackageRule::open("**")],
            web_login,
            publish_check_owners,
            password_min_length,
            login_session_ttl_seconds,
            auth_plugin,
            tarball_storage,
        };

        if let Ok(path) = env::var("RUSTACCIO_CONFIG")
            && let Ok(loaded) = Self::from_yaml_file(PathBuf::from(path))
        {
            cfg.uplinks = loaded.uplinks;
            cfg.acl_rules = loaded.acl_rules;
            if cfg.upstream_registry.is_none() {
                cfg.upstream_registry = loaded.upstream_registry;
            }
            cfg.web_login = loaded.web_login;
            cfg.publish_check_owners = loaded.publish_check_owners;
            cfg.auth_plugin = loaded.auth_plugin;
            cfg.tarball_storage = loaded.tarball_storage;
        }

        if let Some(upstream) = cfg.upstream_registry.clone() {
            cfg.uplinks.entry("default".to_string()).or_insert(upstream);
        }

        cfg
    }

    pub fn from_yaml_file(path: PathBuf) -> Result<Self, String> {
        let text = std::fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        let parsed: YamlConfig = serde_yaml::from_str(&text)
            .map_err(|err| format!("failed to parse {}: {err}", path.display()))?;

        let mut uplinks = HashMap::new();
        if let Some(items) = parsed.uplinks {
            for (name, uplink) in items {
                let url = uplink.url.trim_end_matches('/').to_string();
                if !url.is_empty() {
                    uplinks.insert(name, url);
                }
            }
        }

        let mut rules = Vec::new();
        if let Some(packages) = parsed.packages {
            for (pattern, value) in packages {
                let rule = parse_package_rule(pattern, value)?;
                rules.push(rule);
            }
        }

        let upstream_registry = uplinks.values().next().cloned();

        Ok(Self {
            bind: "127.0.0.1:4873".parse().expect("bind"),
            data_dir: PathBuf::from(".rustaccio-data"),
            upstream_registry,
            uplinks,
            acl_rules: if rules.is_empty() {
                vec![PackageRule::open("**")]
            } else {
                rules
            },
            web_login: parsed
                .flags
                .and_then(|flags| flags.web_login)
                .unwrap_or(false),
            publish_check_owners: parsed
                .publish
                .and_then(|publish| publish.check_owners)
                .unwrap_or(false),
            password_min_length: 3,
            login_session_ttl_seconds: 120,
            auth_plugin: parse_auth_from_yaml(parsed.auth)?,
            tarball_storage: parse_storage_from_yaml(parsed.storage),
        })
    }
}

fn parse_auth_from_env() -> AuthPluginConfig {
    let backend = env::var("RUSTACCIO_AUTH_BACKEND")
        .ok()
        .map(|v| AuthBackend::from_str(&v))
        .unwrap_or(AuthBackend::Local);

    match backend {
        AuthBackend::Local => AuthPluginConfig::default(),
        AuthBackend::Http => {
            let base_url = env::var("RUSTACCIO_AUTH_HTTP_BASE_URL").unwrap_or_default();
            let add_user_endpoint = env::var("RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT")
                .unwrap_or_else(|_| "/adduser".to_string());
            let login_endpoint = env::var("RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT")
                .unwrap_or_else(|_| "/authenticate".to_string());
            let change_password_endpoint = env::var("RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT")
                .unwrap_or_else(|_| "/change-password".to_string());
            let timeout_ms = env::var("RUSTACCIO_AUTH_HTTP_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5_000);

            AuthPluginConfig {
                backend,
                http: Some(HttpAuthPluginConfig {
                    base_url,
                    add_user_endpoint,
                    login_endpoint,
                    change_password_endpoint,
                    timeout_ms,
                }),
            }
        }
    }
}

fn parse_storage_from_env() -> TarballStorageConfig {
    let backend = env::var("RUSTACCIO_TARBALL_BACKEND")
        .ok()
        .map(|v| TarballStorageBackend::from_str(&v))
        .unwrap_or(TarballStorageBackend::Local);

    match backend {
        TarballStorageBackend::Local => TarballStorageConfig::default(),
        TarballStorageBackend::S3 => {
            let bucket = env::var("RUSTACCIO_S3_BUCKET").unwrap_or_default();
            let region =
                env::var("RUSTACCIO_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
            let endpoint = env::var("RUSTACCIO_S3_ENDPOINT")
                .ok()
                .filter(|v| !v.is_empty());
            let access_key_id = env::var("RUSTACCIO_S3_ACCESS_KEY_ID")
                .ok()
                .filter(|v| !v.is_empty());
            let secret_access_key = env::var("RUSTACCIO_S3_SECRET_ACCESS_KEY")
                .ok()
                .filter(|v| !v.is_empty());
            let prefix = env::var("RUSTACCIO_S3_PREFIX").unwrap_or_default();
            let force_path_style = env::var("RUSTACCIO_S3_FORCE_PATH_STYLE")
                .ok()
                .and_then(|v| v.parse::<bool>().ok())
                .unwrap_or(true);

            TarballStorageConfig {
                backend,
                s3: Some(S3TarballStorageConfig {
                    bucket,
                    region,
                    endpoint,
                    access_key_id,
                    secret_access_key,
                    prefix,
                    force_path_style,
                }),
            }
        }
    }
}

fn parse_auth_from_yaml(auth: Option<YamlAuth>) -> Result<AuthPluginConfig, String> {
    let Some(auth) = auth else {
        return Ok(AuthPluginConfig::default());
    };

    let backend = auth
        .backend
        .as_deref()
        .map(AuthBackend::from_str)
        .unwrap_or(AuthBackend::Local);

    match backend {
        AuthBackend::Local => Ok(AuthPluginConfig::default()),
        AuthBackend::Http => {
            let http = auth.http.ok_or_else(|| {
                "auth.http section is required when auth.backend=http".to_string()
            })?;

            Ok(AuthPluginConfig {
                backend,
                http: Some(HttpAuthPluginConfig {
                    base_url: http.base_url,
                    add_user_endpoint: http
                        .add_user_endpoint
                        .unwrap_or_else(|| "/adduser".to_string()),
                    login_endpoint: http
                        .login_endpoint
                        .unwrap_or_else(|| "/authenticate".to_string()),
                    change_password_endpoint: http
                        .change_password_endpoint
                        .unwrap_or_else(|| "/change-password".to_string()),
                    timeout_ms: http.timeout_ms.unwrap_or(5_000),
                }),
            })
        }
    }
}

fn parse_storage_from_yaml(storage: Option<YamlStorage>) -> TarballStorageConfig {
    let Some(storage) = storage else {
        return TarballStorageConfig::default();
    };

    let backend = storage
        .backend
        .as_deref()
        .map(TarballStorageBackend::from_str)
        .unwrap_or(TarballStorageBackend::Local);

    match backend {
        TarballStorageBackend::Local => TarballStorageConfig::default(),
        TarballStorageBackend::S3 => {
            let s3 = storage.s3.unwrap_or_default();
            TarballStorageConfig {
                backend,
                s3: Some(S3TarballStorageConfig {
                    bucket: s3.bucket.unwrap_or_default(),
                    region: s3.region.unwrap_or_else(|| "us-east-1".to_string()),
                    endpoint: s3.endpoint,
                    access_key_id: s3.access_key_id,
                    secret_access_key: s3.secret_access_key,
                    prefix: s3.prefix.unwrap_or_default(),
                    force_path_style: s3.force_path_style.unwrap_or(true),
                }),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct YamlConfig {
    uplinks: Option<HashMap<String, YamlUplink>>,
    packages: Option<serde_yaml::Mapping>,
    flags: Option<YamlFlags>,
    publish: Option<YamlPublish>,
    auth: Option<YamlAuth>,
    storage: Option<YamlStorage>,
}

#[derive(Debug, Deserialize)]
struct YamlUplink {
    url: String,
}

#[derive(Debug, Deserialize)]
struct YamlFlags {
    #[serde(rename = "webLogin")]
    web_login: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct YamlPublish {
    check_owners: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct YamlAuth {
    backend: Option<String>,
    http: Option<YamlAuthHttp>,
}

#[derive(Debug, Deserialize)]
struct YamlAuthHttp {
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "addUserEndpoint")]
    add_user_endpoint: Option<String>,
    #[serde(rename = "loginEndpoint")]
    login_endpoint: Option<String>,
    #[serde(rename = "changePasswordEndpoint")]
    change_password_endpoint: Option<String>,
    #[serde(rename = "timeoutMs")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct YamlStorage {
    backend: Option<String>,
    s3: Option<YamlStorageS3>,
}

#[derive(Debug, Deserialize, Default)]
struct YamlStorageS3 {
    bucket: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
    #[serde(rename = "accessKeyId")]
    access_key_id: Option<String>,
    #[serde(rename = "secretAccessKey")]
    secret_access_key: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "forcePathStyle")]
    force_path_style: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize, Default)]
struct YamlPackageRule {
    access: Option<StringOrVec>,
    publish: Option<StringOrVec>,
    unpublish: Option<StringOrVec>,
    proxy: Option<StringOrVec>,
}

fn parse_package_rule(
    pattern: serde_yaml::Value,
    value: serde_yaml::Value,
) -> Result<PackageRule, String> {
    let pattern = pattern
        .as_str()
        .ok_or_else(|| "invalid packages rule key".to_string())?
        .to_string();

    let parsed: YamlPackageRule = serde_yaml::from_value(value)
        .map_err(|err| format!("invalid package rule {pattern}: {err}"))?;

    Ok(PackageRule {
        pattern,
        access: parse_principals(parsed.access, vec!["$all".to_string()]),
        publish: parse_principals(parsed.publish, vec!["$authenticated".to_string()]),
        unpublish: parse_principals(parsed.unpublish, vec!["$authenticated".to_string()]),
        proxy: parse_proxy(parsed.proxy),
    })
}

fn parse_principals(value: Option<StringOrVec>, default_value: Vec<String>) -> Vec<String> {
    match value {
        Some(StringOrVec::One(v)) => vec![v],
        Some(StringOrVec::Many(v)) => v,
        None => default_value,
    }
}

fn parse_proxy(value: Option<StringOrVec>) -> Option<String> {
    match value {
        Some(StringOrVec::One(v)) => Some(v),
        Some(StringOrVec::Many(items)) => items.into_iter().next(),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthBackend, Config, TarballStorageBackend};
    use std::io::Write;

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
  http:
    baseUrl: http://auth.local:9000
    addUserEndpoint: /users/add
    loginEndpoint: /users/login
    changePasswordEndpoint: /users/password
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
        let auth = cfg.auth_plugin.http.expect("http auth");
        assert_eq!(auth.base_url, "http://auth.local:9000");
        assert_eq!(auth.add_user_endpoint, "/users/add");
        assert_eq!(auth.login_endpoint, "/users/login");
        assert_eq!(auth.change_password_endpoint, "/users/password");
        assert_eq!(auth.timeout_ms, 2500);

        assert_eq!(cfg.tarball_storage.backend, TarballStorageBackend::S3);
        let s3 = cfg.tarball_storage.s3.expect("s3 config");
        assert_eq!(s3.bucket, "npm-cache");
        assert_eq!(s3.region, "eu-north-1");
        assert_eq!(s3.endpoint.as_deref(), Some("http://127.0.0.1:9001"));
        assert_eq!(s3.access_key_id.as_deref(), Some("minio"));
        assert_eq!(s3.secret_access_key.as_deref(), Some("miniopass"));
        assert_eq!(s3.prefix, "tarballs/");
        assert!(s3.force_path_style);
    }
}
