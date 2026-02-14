use crate::acl::PackageRule;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use config::{Config as SettingsLoader, Environment};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

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
    pub request_auth_endpoint: Option<String>,
    pub allow_access_endpoint: Option<String>,
    pub allow_publish_endpoint: Option<String>,
    pub allow_unpublish_endpoint: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPluginConfig {
    pub backend: AuthBackend,
    pub external_mode: bool,
    pub http: Option<HttpAuthPluginConfig>,
}

impl Default for AuthPluginConfig {
    fn default() -> Self {
        Self {
            backend: AuthBackend::Local,
            external_mode: false,
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
    pub listen: Vec<String>,
    pub upstream_registry: Option<String>,
    pub uplinks: HashMap<String, String>,
    pub acl_rules: Vec<PackageRule>,
    pub web_enabled: bool,
    pub web_title: String,
    pub web_login: bool,
    pub publish_check_owners: bool,
    pub password_min_length: usize,
    pub login_session_ttl_seconds: i64,
    pub max_body_size: usize,
    pub audit_enabled: bool,
    pub url_prefix: String,
    pub trust_proxy: bool,
    pub keep_alive_timeout_secs: Option<u64>,
    pub log_level: String,
    pub auth_plugin: AuthPluginConfig,
    pub tarball_storage: TarballStorageConfig,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct RawEnvConfig {
    config: Option<String>,
    config_base64: Option<String>,
    bind: Option<String>,
    data_dir: Option<String>,
    upstream: Option<String>,
    web_login: Option<String>,
    web_enable: Option<String>,
    web_title: Option<String>,
    publish_check_owners: Option<String>,
    password_min: Option<String>,
    login_session_ttl_seconds: Option<String>,
    max_body_size: Option<String>,
    audit_enabled: Option<String>,
    url_prefix: Option<String>,
    trust_proxy: Option<String>,
    keep_alive_timeout: Option<String>,
    log_level: Option<String>,
    auth_backend: Option<String>,
    auth_external_mode: Option<String>,
    auth_http_base_url: Option<String>,
    auth_http_adduser_endpoint: Option<String>,
    auth_http_login_endpoint: Option<String>,
    auth_http_change_password_endpoint: Option<String>,
    auth_http_request_auth_endpoint: Option<String>,
    auth_http_allow_access_endpoint: Option<String>,
    auth_http_allow_publish_endpoint: Option<String>,
    auth_http_allow_unpublish_endpoint: Option<String>,
    auth_http_timeout_ms: Option<String>,
    tarball_backend: Option<String>,
    s3_bucket: Option<String>,
    s3_region: Option<String>,
    s3_endpoint: Option<String>,
    s3_access_key_id: Option<String>,
    s3_secret_access_key: Option<String>,
    s3_prefix: Option<String>,
    s3_force_path_style: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let env_cfg = load_rustaccio_env()?;
        let mut cfg = Self::defaults();
        cfg.apply_env_config_sources_if_present(&env_cfg)?;
        cfg.apply_env_overrides(&env_cfg);
        cfg.apply_port_override(load_process_env_value("port")?);
        cfg.ensure_default_uplink();
        Ok(cfg)
    }

    pub fn from_env_with_config_file(config_path: PathBuf) -> Result<Self, String> {
        let env_cfg = load_rustaccio_env()?;
        let mut cfg = Self::defaults();
        cfg.apply_env_config_sources_if_present(&env_cfg)?;
        cfg.apply_yaml_overrides(Self::from_yaml_file(config_path)?);
        cfg.apply_env_overrides(&env_cfg);
        cfg.apply_port_override(load_process_env_value("port")?);
        cfg.ensure_default_uplink();
        Ok(cfg)
    }

    fn defaults() -> Self {
        let bind: SocketAddr = "127.0.0.1:4873".parse().expect("valid default bind");
        let listen = vec![bind.to_string()];

        Self {
            bind,
            data_dir: PathBuf::from(".rustaccio-data"),
            listen,
            upstream_registry: None,
            uplinks: HashMap::new(),
            acl_rules: vec![PackageRule::open("**")],
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
            auth_plugin: AuthPluginConfig::default(),
            tarball_storage: TarballStorageConfig::default(),
        }
    }

    pub fn defaults_for_examples() -> Self {
        Self::defaults()
    }

    fn apply_env_config_sources_if_present(
        &mut self,
        env_cfg: &RawEnvConfig,
    ) -> Result<(), String> {
        let config_path = env_cfg
            .config
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let config_b64 = env_cfg
            .config_base64
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        match (config_path, config_b64) {
            (Some(_), Some(_)) => Err(
                "RUSTACCIO_CONFIG and RUSTACCIO_CONFIG_BASE64 are both set; use only one"
                    .to_string(),
            ),
            (Some(path), None) => {
                let loaded = Self::from_yaml_file(PathBuf::from(path))
                    .map_err(|err| format!("failed to load RUSTACCIO_CONFIG={path}: {err}"))?;
                self.apply_yaml_overrides(loaded);
                Ok(())
            }
            (None, Some(value)) => {
                let compact = value
                    .chars()
                    .filter(|ch| !ch.is_ascii_whitespace())
                    .collect::<String>();
                let decoded = B64
                    .decode(compact)
                    .map_err(|err| format!("failed to decode RUSTACCIO_CONFIG_BASE64: {err}"))?;
                let yaml = String::from_utf8(decoded).map_err(|err| {
                    format!(
                        "failed to decode RUSTACCIO_CONFIG_BASE64: decoded bytes are not UTF-8 ({err})"
                    )
                })?;
                let loaded = Self::from_yaml_str("RUSTACCIO_CONFIG_BASE64", &yaml)
                    .map_err(|err| format!("failed to load RUSTACCIO_CONFIG_BASE64: {err}"))?;
                self.apply_yaml_overrides(loaded);
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }

    fn apply_env_overrides(&mut self, env_cfg: &RawEnvConfig) {
        if let Some(bind) = parse_env_value::<SocketAddr>(env_cfg.bind.as_deref()) {
            self.bind = bind;
            self.listen = vec![bind.to_string()];
        }

        if let Some(raw_data_dir) = env_cfg.data_dir.as_deref() {
            self.data_dir = PathBuf::from(raw_data_dir);
        }

        if let Some(raw_upstream) = env_cfg.upstream.as_deref() {
            let upstream = raw_upstream.trim().trim_end_matches('/').to_string();
            if upstream.is_empty() {
                self.upstream_registry = None;
                self.uplinks.remove("default");
            } else {
                self.upstream_registry = Some(upstream.clone());
                self.uplinks.insert("default".to_string(), upstream);
            }
        }

        if let Some(parsed) = parse_env_value::<bool>(env_cfg.web_login.as_deref()) {
            self.web_login = parsed;
        }
        if let Some(parsed) = parse_env_value::<bool>(env_cfg.web_enable.as_deref()) {
            self.web_enabled = parsed;
        }
        if let Some(value) = env_cfg.web_title.as_deref() {
            self.web_title = value.to_string();
        }

        if let Some(parsed) = parse_env_value::<bool>(env_cfg.publish_check_owners.as_deref()) {
            self.publish_check_owners = parsed;
        }
        if let Some(parsed) = parse_env_value::<usize>(env_cfg.password_min.as_deref()) {
            self.password_min_length = parsed;
        }
        if let Some(parsed) = parse_env_value::<i64>(env_cfg.login_session_ttl_seconds.as_deref()) {
            self.login_session_ttl_seconds = parsed;
        }
        if let Some(value) = env_cfg.max_body_size.as_deref()
            && let Some(parsed) = parse_body_size(value)
        {
            self.max_body_size = parsed;
        }
        if let Some(parsed) = parse_env_value::<bool>(env_cfg.audit_enabled.as_deref()) {
            self.audit_enabled = parsed;
        }
        if let Some(value) = env_cfg.url_prefix.as_deref() {
            self.url_prefix = normalize_url_prefix(&value);
        }
        if let Some(parsed) = parse_env_value::<bool>(env_cfg.trust_proxy.as_deref()) {
            self.trust_proxy = parsed;
        }
        if let Some(value) = env_cfg.keep_alive_timeout.as_deref() {
            if value.trim().is_empty() {
                self.keep_alive_timeout_secs = None;
            } else if let Some(parsed) = parse_env_value::<u64>(Some(value)) {
                self.keep_alive_timeout_secs = Some(parsed);
            }
        }
        if let Some(value) = env_cfg.log_level.as_deref()
            && !value.trim().is_empty()
        {
            self.log_level = value.to_string();
        }

        self.apply_auth_env_overrides(env_cfg);
        self.apply_storage_env_overrides(env_cfg);
    }

    fn apply_port_override(&mut self, port_value: Option<String>) {
        // PaaS compatibility: honor injected PORT (e.g. Railway) and force a public bind address.
        if let Some(port) = parse_env_value::<u16>(port_value.as_deref()) {
            let bind = SocketAddr::from(([0, 0, 0, 0], port));
            self.bind = bind;
            self.listen = vec![bind.to_string()];
        }
    }

    fn apply_auth_env_overrides(&mut self, env_cfg: &RawEnvConfig) {
        if let Some(value) = env_cfg.auth_backend.as_deref() {
            self.auth_plugin.backend = AuthBackend::from_str(&value);
        }
        if let Some(parsed) = parse_env_value::<bool>(env_cfg.auth_external_mode.as_deref()) {
            self.auth_plugin.external_mode = parsed;
        }

        if self.auth_plugin.backend == AuthBackend::Local {
            self.auth_plugin.http = None;
            return;
        }

        let mut http = self
            .auth_plugin
            .http
            .clone()
            .unwrap_or_else(default_http_auth_config);

        if let Some(value) = env_cfg.auth_http_base_url.as_deref() {
            http.base_url = value.to_string();
        }
        if let Some(value) = env_cfg.auth_http_adduser_endpoint.as_deref() {
            http.add_user_endpoint = value.to_string();
        }
        if let Some(value) = env_cfg.auth_http_login_endpoint.as_deref() {
            http.login_endpoint = value.to_string();
        }
        if let Some(value) = env_cfg.auth_http_change_password_endpoint.as_deref() {
            http.change_password_endpoint = value.to_string();
        }
        if let Some(value) = env_cfg.auth_http_request_auth_endpoint.as_deref() {
            http.request_auth_endpoint = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.auth_http_allow_access_endpoint.as_deref() {
            http.allow_access_endpoint = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.auth_http_allow_publish_endpoint.as_deref() {
            http.allow_publish_endpoint = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.auth_http_allow_unpublish_endpoint.as_deref() {
            http.allow_unpublish_endpoint = empty_string_to_none(value.to_string());
        }
        if let Some(parsed) = parse_env_value::<u64>(env_cfg.auth_http_timeout_ms.as_deref()) {
            http.timeout_ms = parsed;
        }
        self.auth_plugin.http = Some(http);
    }

    fn apply_storage_env_overrides(&mut self, env_cfg: &RawEnvConfig) {
        if let Some(value) = env_cfg.tarball_backend.as_deref() {
            self.tarball_storage.backend = TarballStorageBackend::from_str(&value);
        }

        if self.tarball_storage.backend == TarballStorageBackend::Local {
            self.tarball_storage.s3 = None;
            return;
        }

        let mut s3 = self
            .tarball_storage
            .s3
            .clone()
            .unwrap_or_else(default_s3_storage_config);

        if let Some(value) = env_cfg.s3_bucket.as_deref()
            && !value.is_empty()
        {
            s3.bucket = value.to_string();
        }
        if let Some(value) = env_cfg.s3_region.as_deref()
            && !value.is_empty()
        {
            s3.region = value.to_string();
        }
        if let Some(value) = env_cfg.s3_endpoint.as_deref() {
            s3.endpoint = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.s3_access_key_id.as_deref() {
            s3.access_key_id = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.s3_secret_access_key.as_deref() {
            s3.secret_access_key = empty_string_to_none(value.to_string());
        }
        if let Some(value) = env_cfg.s3_prefix.as_deref() {
            s3.prefix = value.to_string();
        }
        if let Some(parsed) = parse_env_value::<bool>(env_cfg.s3_force_path_style.as_deref()) {
            s3.force_path_style = parsed;
        }

        self.tarball_storage.s3 = Some(s3);
    }

    fn apply_yaml_overrides(&mut self, loaded: Self) {
        self.bind = loaded.bind;
        self.listen = loaded.listen;
        self.data_dir = loaded.data_dir;
        self.uplinks = loaded.uplinks;
        self.acl_rules = loaded.acl_rules;
        self.upstream_registry = loaded.upstream_registry;
        self.web_enabled = loaded.web_enabled;
        self.web_title = loaded.web_title;
        self.web_login = loaded.web_login;
        self.publish_check_owners = loaded.publish_check_owners;
        self.max_body_size = loaded.max_body_size;
        self.audit_enabled = loaded.audit_enabled;
        self.url_prefix = loaded.url_prefix;
        self.trust_proxy = loaded.trust_proxy;
        self.keep_alive_timeout_secs = loaded.keep_alive_timeout_secs;
        self.log_level = loaded.log_level;
        self.auth_plugin = loaded.auth_plugin;
        self.tarball_storage = loaded.tarball_storage;
    }

    fn ensure_default_uplink(&mut self) {
        if let Some(upstream) = self.upstream_registry.clone() {
            self.uplinks
                .entry("default".to_string())
                .or_insert(upstream);
        }
    }

    pub fn from_yaml_file(path: PathBuf) -> Result<Self, String> {
        let parsed = load_yaml_config(&path)?;
        Self::from_yaml_config(parsed)
    }

    fn from_yaml_str(source: &str, text: &str) -> Result<Self, String> {
        let parsed = load_yaml_config_from_str(source, text)?;
        Self::from_yaml_config(parsed)
    }

    fn from_yaml_config(parsed: YamlConfig) -> Result<Self, String> {
        let bind = parse_bind(parsed.listen.as_ref())?;
        let listen = parse_listen(parsed.listen.as_ref(), &bind);
        let data_dir = parse_data_dir(parsed.storage.as_ref());
        let web_enabled = parsed
            .web
            .as_ref()
            .and_then(|web| web.enable)
            .unwrap_or(true);
        let web_title = parsed
            .web
            .as_ref()
            .and_then(|web| web.title.clone())
            .unwrap_or_else(|| "Rustaccio".to_string());
        let max_body_size = parsed
            .max_body_size
            .as_deref()
            .and_then(parse_body_size)
            .unwrap_or(50 * 1024 * 1024);
        let audit_enabled = parsed
            .middlewares
            .as_ref()
            .and_then(|middlewares| middlewares.audit.as_ref())
            .and_then(|audit| audit.enabled)
            .unwrap_or(true);
        let url_prefix = normalize_url_prefix(parsed.url_prefix.as_deref().unwrap_or("/"));
        let trust_proxy = parsed
            .server
            .as_ref()
            .and_then(|server| server.trust_proxy.as_ref())
            .is_some_and(yaml_truthy);
        let keep_alive_timeout_secs = parsed.server.and_then(|server| server.keep_alive_timeout);
        let log_level = parsed
            .log
            .and_then(|log| log.level)
            .unwrap_or_else(|| "info".to_string());

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
        let tarball_storage = parse_storage_from_yaml(parsed.storage.as_ref(), parsed.store);

        Ok(Self {
            bind,
            data_dir,
            listen,
            upstream_registry,
            uplinks,
            acl_rules: if rules.is_empty() {
                vec![PackageRule::open("**")]
            } else {
                rules
            },
            web_enabled,
            web_title,
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
            max_body_size,
            audit_enabled,
            url_prefix,
            trust_proxy,
            keep_alive_timeout_secs,
            log_level,
            auth_plugin: parse_auth_from_yaml(parsed.auth)?,
            tarball_storage,
        })
    }
}

fn load_yaml_config(path: &Path) -> Result<YamlConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let source = path.display().to_string();
    load_yaml_config_from_str(&source, &text)
}

fn load_yaml_config_from_str(source: &str, text: &str) -> Result<YamlConfig, String> {
    let ordered_packages = serde_yaml::from_str::<YamlPackagesOnly>(text)
        .ok()
        .and_then(|value| value.packages);

    let mut parsed = serde_yaml::from_str::<YamlConfig>(text)
        .map_err(|err| format!("failed to parse {source}: {err}"))?;
    if ordered_packages.is_some() {
        parsed.packages = ordered_packages;
    }
    Ok(parsed)
}

fn load_rustaccio_env() -> Result<RawEnvConfig, String> {
    let settings = SettingsLoader::builder()
        .add_source(Environment::with_prefix("RUSTACCIO").try_parsing(false))
        .build()
        .map_err(|err| format!("failed to load RUSTACCIO_* environment: {err}"))?;

    Ok(RawEnvConfig {
        config: env_value_for_var(&settings, "RUSTACCIO_CONFIG"),
        config_base64: env_value_for_var(&settings, "RUSTACCIO_CONFIG_BASE64"),
        bind: env_value_for_var(&settings, "RUSTACCIO_BIND"),
        data_dir: env_value_for_var(&settings, "RUSTACCIO_DATA_DIR"),
        upstream: env_value_for_var(&settings, "RUSTACCIO_UPSTREAM"),
        web_login: env_value_for_var(&settings, "RUSTACCIO_WEB_LOGIN"),
        web_enable: env_value_for_var(&settings, "RUSTACCIO_WEB_ENABLE"),
        web_title: env_value_for_var(&settings, "RUSTACCIO_WEB_TITLE"),
        publish_check_owners: env_value_for_var(&settings, "RUSTACCIO_PUBLISH_CHECK_OWNERS"),
        password_min: env_value_for_var(&settings, "RUSTACCIO_PASSWORD_MIN"),
        login_session_ttl_seconds: env_value_for_var(
            &settings,
            "RUSTACCIO_LOGIN_SESSION_TTL_SECONDS",
        ),
        max_body_size: env_value_for_var(&settings, "RUSTACCIO_MAX_BODY_SIZE"),
        audit_enabled: env_value_for_var(&settings, "RUSTACCIO_AUDIT_ENABLED"),
        url_prefix: env_value_for_var(&settings, "RUSTACCIO_URL_PREFIX"),
        trust_proxy: env_value_for_var(&settings, "RUSTACCIO_TRUST_PROXY"),
        keep_alive_timeout: env_value_for_var(&settings, "RUSTACCIO_KEEP_ALIVE_TIMEOUT"),
        log_level: env_value_for_var(&settings, "RUSTACCIO_LOG_LEVEL"),
        auth_backend: env_value_for_var(&settings, "RUSTACCIO_AUTH_BACKEND"),
        auth_external_mode: env_value_for_var(&settings, "RUSTACCIO_AUTH_EXTERNAL_MODE"),
        auth_http_base_url: env_value_for_var(&settings, "RUSTACCIO_AUTH_HTTP_BASE_URL"),
        auth_http_adduser_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_ADDUSER_ENDPOINT",
        ),
        auth_http_login_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_LOGIN_ENDPOINT",
        ),
        auth_http_change_password_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_CHANGE_PASSWORD_ENDPOINT",
        ),
        auth_http_request_auth_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_REQUEST_AUTH_ENDPOINT",
        ),
        auth_http_allow_access_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_ALLOW_ACCESS_ENDPOINT",
        ),
        auth_http_allow_publish_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_ALLOW_PUBLISH_ENDPOINT",
        ),
        auth_http_allow_unpublish_endpoint: env_value_for_var(
            &settings,
            "RUSTACCIO_AUTH_HTTP_ALLOW_UNPUBLISH_ENDPOINT",
        ),
        auth_http_timeout_ms: env_value_for_var(&settings, "RUSTACCIO_AUTH_HTTP_TIMEOUT_MS"),
        tarball_backend: env_value_for_var(&settings, "RUSTACCIO_TARBALL_BACKEND"),
        s3_bucket: env_value_for_var(&settings, "RUSTACCIO_S3_BUCKET"),
        s3_region: env_value_for_var(&settings, "RUSTACCIO_S3_REGION"),
        s3_endpoint: env_value_for_var(&settings, "RUSTACCIO_S3_ENDPOINT"),
        s3_access_key_id: env_value_for_var(&settings, "RUSTACCIO_S3_ACCESS_KEY_ID"),
        s3_secret_access_key: env_value_for_var(&settings, "RUSTACCIO_S3_SECRET_ACCESS_KEY"),
        s3_prefix: env_value_for_var(&settings, "RUSTACCIO_S3_PREFIX"),
        s3_force_path_style: env_value_for_var(&settings, "RUSTACCIO_S3_FORCE_PATH_STYLE"),
    })
}

fn load_process_env_value(key: &str) -> Result<Option<String>, String> {
    let settings = SettingsLoader::builder()
        .add_source(Environment::default().try_parsing(false))
        .build()
        .map_err(|err| format!("failed to load process environment: {err}"))?;
    Ok(env_value(&settings, key))
}

fn env_value(settings: &SettingsLoader, key: &str) -> Option<String> {
    settings
        .get_string(key)
        .ok()
        .or_else(|| settings.get_string(&key.to_ascii_uppercase()).ok())
}

fn env_value_for_var(settings: &SettingsLoader, env_var: &str) -> Option<String> {
    let key = env_var
        .strip_prefix("RUSTACCIO_")
        .unwrap_or(env_var)
        .to_ascii_lowercase();
    env_value(settings, &key)
}

fn parse_env_value<T>(raw: Option<&str>) -> Option<T>
where
    T: std::str::FromStr,
{
    raw.and_then(|value| value.parse::<T>().ok())
}

pub fn default_http_auth_config_for_examples() -> HttpAuthPluginConfig {
    default_http_auth_config()
}

pub fn default_s3_storage_config_for_examples() -> S3TarballStorageConfig {
    default_s3_storage_config()
}

fn default_http_auth_config() -> HttpAuthPluginConfig {
    HttpAuthPluginConfig {
        base_url: String::new(),
        add_user_endpoint: "/adduser".to_string(),
        login_endpoint: "/authenticate".to_string(),
        change_password_endpoint: "/change-password".to_string(),
        request_auth_endpoint: None,
        allow_access_endpoint: None,
        allow_publish_endpoint: None,
        allow_unpublish_endpoint: None,
        timeout_ms: 5_000,
    }
}

fn default_s3_storage_config() -> S3TarballStorageConfig {
    S3TarballStorageConfig {
        bucket: String::new(),
        region: "us-east-1".to_string(),
        endpoint: None,
        access_key_id: None,
        secret_access_key: None,
        prefix: String::new(),
        force_path_style: true,
    }
}

fn empty_string_to_none(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
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
    let external_mode = auth.external.unwrap_or(false);

    match backend {
        AuthBackend::Local => Ok(AuthPluginConfig {
            backend,
            external_mode,
            http: None,
        }),
        AuthBackend::Http => {
            let http = auth.http.ok_or_else(|| {
                "auth.http section is required when auth.backend=http".to_string()
            })?;

            Ok(AuthPluginConfig {
                backend,
                external_mode,
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
                    request_auth_endpoint: http.request_auth_endpoint,
                    allow_access_endpoint: http.allow_access_endpoint,
                    allow_publish_endpoint: http.allow_publish_endpoint,
                    allow_unpublish_endpoint: http.allow_unpublish_endpoint,
                    timeout_ms: http.timeout_ms.unwrap_or(5_000),
                }),
            })
        }
    }
}

fn parse_storage_from_yaml(
    storage: Option<&serde_yaml::Value>,
    store: Option<serde_yaml::Value>,
) -> TarballStorageConfig {
    if let Some(store_cfg) = store
        .and_then(parse_store_storage_config)
        .or_else(|| storage.and_then(parse_storage_storage_config))
    {
        return store_cfg;
    }
    TarballStorageConfig::default()
}

fn parse_storage_storage_config(value: &serde_yaml::Value) -> Option<TarballStorageConfig> {
    let parsed = serde_yaml::from_value::<YamlStorage>(value.clone()).ok()?;
    Some(parse_storage_config(parsed))
}

fn parse_store_storage_config(value: serde_yaml::Value) -> Option<TarballStorageConfig> {
    let mapping = value.as_mapping()?;
    if mapping.contains_key(serde_yaml::Value::String("backend".to_string())) {
        let parsed = serde_yaml::from_value::<YamlStorage>(value).ok()?;
        return Some(parse_storage_config(parsed));
    }

    let legacy = mapping.get(serde_yaml::Value::String("aws-s3-storage".to_string()))?;
    let parsed = serde_yaml::from_value::<YamlStorageS3Legacy>(legacy.clone()).ok()?;
    Some(TarballStorageConfig {
        backend: TarballStorageBackend::S3,
        s3: Some(S3TarballStorageConfig {
            bucket: parsed.bucket.unwrap_or_default(),
            region: parsed.region.unwrap_or_else(|| "us-east-1".to_string()),
            endpoint: parsed.endpoint,
            access_key_id: parsed.access_key_id,
            secret_access_key: parsed.secret_access_key,
            prefix: parsed.prefix.unwrap_or_default(),
            force_path_style: parsed.s3_force_path_style.unwrap_or(true),
        }),
    })
}

fn parse_storage_config(storage: YamlStorage) -> TarballStorageConfig {
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
    listen: Option<StringOrVec>,
    storage: Option<serde_yaml::Value>,
    store: Option<serde_yaml::Value>,
    uplinks: Option<HashMap<String, YamlUplink>>,
    packages: Option<serde_yaml::Mapping>,
    web: Option<YamlWeb>,
    flags: Option<YamlFlags>,
    publish: Option<YamlPublish>,
    middlewares: Option<YamlMiddlewares>,
    max_body_size: Option<String>,
    url_prefix: Option<String>,
    server: Option<YamlServer>,
    log: Option<YamlLog>,
    auth: Option<YamlAuth>,
}

#[derive(Debug, Deserialize)]
struct YamlPackagesOnly {
    packages: Option<serde_yaml::Mapping>,
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
    external: Option<bool>,
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
    #[serde(rename = "requestAuthEndpoint")]
    request_auth_endpoint: Option<String>,
    #[serde(rename = "allowAccessEndpoint")]
    allow_access_endpoint: Option<String>,
    #[serde(rename = "allowPublishEndpoint")]
    allow_publish_endpoint: Option<String>,
    #[serde(rename = "allowUnpublishEndpoint")]
    allow_unpublish_endpoint: Option<String>,
    #[serde(rename = "timeoutMs")]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct YamlWeb {
    enable: Option<bool>,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct YamlMiddlewares {
    audit: Option<YamlAudit>,
}

#[derive(Debug, Deserialize)]
struct YamlAudit {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct YamlServer {
    #[serde(rename = "keepAliveTimeout")]
    keep_alive_timeout: Option<u64>,
    #[serde(rename = "trustProxy")]
    trust_proxy: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct YamlLog {
    level: Option<String>,
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

#[derive(Debug, Deserialize, Default)]
struct YamlStorageS3Legacy {
    bucket: Option<String>,
    region: Option<String>,
    endpoint: Option<String>,
    #[serde(rename = "accessKeyId")]
    access_key_id: Option<String>,
    #[serde(rename = "secretAccessKey")]
    secret_access_key: Option<String>,
    prefix: Option<String>,
    #[serde(rename = "s3ForcePathStyle")]
    s3_force_path_style: Option<bool>,
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
    #[serde(default, rename = "uplinksLook", alias = "uplinks_look")]
    uplinks_look: Option<bool>,
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
        uplinks_look: parsed.uplinks_look.unwrap_or(true),
    })
}

fn parse_principals(value: Option<StringOrVec>, default_value: Vec<String>) -> Vec<String> {
    let principals = match value {
        Some(StringOrVec::One(v)) => split_principals(&v),
        Some(StringOrVec::Many(values)) => values
            .into_iter()
            .flat_map(|value| split_principals(&value))
            .collect(),
        None => return default_value,
    };
    if principals.is_empty() {
        default_value
    } else {
        principals
    }
}

fn split_principals(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(ToOwned::to_owned).collect()
}

fn parse_proxy(value: Option<StringOrVec>) -> Option<String> {
    match value {
        Some(StringOrVec::One(v)) => Some(v),
        Some(StringOrVec::Many(items)) => items.into_iter().next(),
        None => None,
    }
}

fn parse_bind(listen: Option<&StringOrVec>) -> Result<SocketAddr, String> {
    let first = listen
        .and_then(|value| match value {
            StringOrVec::One(v) => Some(v.as_str()),
            StringOrVec::Many(items) => items.first().map(String::as_str),
        })
        .unwrap_or("127.0.0.1:4873");
    first
        .parse()
        .map_err(|err| format!("invalid listen address '{first}': {err}"))
}

fn parse_listen(listen: Option<&StringOrVec>, bind: &SocketAddr) -> Vec<String> {
    match listen {
        Some(StringOrVec::One(v)) => vec![v.clone()],
        Some(StringOrVec::Many(items)) if !items.is_empty() => items.clone(),
        _ => vec![bind.to_string()],
    }
}

fn parse_data_dir(storage: Option<&serde_yaml::Value>) -> PathBuf {
    storage
        .and_then(serde_yaml::Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".rustaccio-data"))
}

fn parse_body_size(raw: &str) -> Option<usize> {
    let value = raw.trim().to_lowercase();
    if value.is_empty() {
        return None;
    }
    let (number, unit) = split_number_and_unit(&value)?;
    let n = number.parse::<usize>().ok()?;
    let multiplier = match unit {
        "" | "b" => 1usize,
        "kb" => 1024usize,
        "mb" => 1024usize * 1024,
        "gb" => 1024usize * 1024 * 1024,
        _ => return None,
    };
    n.checked_mul(multiplier)
}

fn split_number_and_unit(value: &str) -> Option<(&str, &str)> {
    let idx = value
        .char_indices()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(i, _)| i)
        .unwrap_or(value.len());
    if idx == 0 {
        return None;
    }
    Some((&value[..idx], value[idx..].trim()))
}

fn normalize_url_prefix(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let with_leading = if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    };
    with_leading.trim_end_matches('/').to_string()
}

fn yaml_truthy(value: &serde_yaml::Value) -> bool {
    match value {
        serde_yaml::Value::Bool(v) => *v,
        serde_yaml::Value::Number(n) => n.as_i64().is_some_and(|v| v != 0),
        serde_yaml::Value::String(s) => !s.trim().is_empty() && s != "false" && s != "0",
        _ => false,
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
    fn parses_whitespace_separated_acl_principals() {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(
            file,
            r#"
packages:
  '@geoman-io/*':
    access: geo-admin read-only
    publish: geo-admin read-only
    unpublish: geo-admin read-only
"#
        )
        .expect("write");

        let cfg = Config::from_yaml_file(file.path().to_path_buf()).expect("parse");
        assert_eq!(cfg.acl_rules.len(), 1);
        assert_eq!(
            cfg.acl_rules[0].access,
            vec!["geo-admin".to_string(), "read-only".to_string()]
        );
        assert_eq!(
            cfg.acl_rules[0].publish,
            vec!["geo-admin".to_string(), "read-only".to_string()]
        );
        assert_eq!(
            cfg.acl_rules[0].unpublish,
            vec!["geo-admin".to_string(), "read-only".to_string()]
        );
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
