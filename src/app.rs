use crate::{
    acl::Acl, api, governance::GovernanceEngine, policy::PolicyEngine, storage::Store,
    upstream::Upstream,
};
use axum::{
    Router,
    http::{HeaderName, StatusCode},
    routing::any,
};
use config::{Config as SettingsLoader, Environment};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminAccessConfig {
    pub allow_any_authenticated: bool,
    pub users: Vec<String>,
    pub groups: Vec<String>,
}

impl Default for AdminAccessConfig {
    fn default() -> Self {
        Self {
            allow_any_authenticated: true,
            users: Vec::new(),
            groups: Vec::new(),
        }
    }
}

impl AdminAccessConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Some(parsed) = parse_bool_env(
            "RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED",
            cfg.allow_any_authenticated,
        ) {
            cfg.allow_any_authenticated = parsed;
        }
        if let Some(value) = load_env_value("RUSTACCIO_ADMIN_USERS") {
            cfg.users = parse_principal_list(&value);
        }
        if let Some(value) = load_env_value("RUSTACCIO_ADMIN_GROUPS") {
            cfg.groups = parse_principal_list(&value);
        }
        cfg
    }
}

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub acl: Acl,
    pub policy: Arc<dyn PolicyEngine>,
    pub governance: Arc<GovernanceEngine>,
    pub admin_access: AdminAccessConfig,
    pub uplinks: HashMap<String, Upstream>,
    pub web_enabled: bool,
    pub web_title: String,
    pub web_login_enabled: bool,
    pub publish_check_owners: bool,
    pub max_body_size: usize,
    pub audit_enabled: bool,
    pub url_prefix: String,
    pub trust_proxy: bool,
    pub auth_external_mode: bool,
}

pub fn build_router(state: AppState) -> Router {
    let request_id_header = HeaderName::from_static("x-request-id");
    let max_body_size = state.max_body_size;
    let request_timeout_secs = request_timeout_secs_from_env();
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO))
        .on_failure(DefaultOnFailure::new().level(Level::ERROR));

    Router::new()
        .fallback(any(api::dispatch))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(max_body_size))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(request_timeout_secs),
        ))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(trace_layer)
}

fn request_timeout_secs_from_env() -> u64 {
    let raw = load_env_value("RUSTACCIO_REQUEST_TIMEOUT_SECS");
    parse_request_timeout_secs(raw.as_deref())
}

fn parse_request_timeout_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 300)
}

fn load_env_value(key: &str) -> Option<String> {
    let settings = SettingsLoader::builder()
        .add_source(Environment::default().try_parsing(false))
        .build()
        .ok()?;
    settings
        .get_string(key)
        .ok()
        .or_else(|| settings.get_string(&key.to_ascii_lowercase()).ok())
}

fn parse_bool_env(key: &str, default: bool) -> Option<bool> {
    let value = load_env_value(key)?;
    let parsed = match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => true,
        "false" | "0" | "no" => false,
        _ => default,
    };
    Some(parsed)
}

fn parse_principal_list(raw: &str) -> Vec<String> {
    raw.split([',', ' '])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{AdminAccessConfig, parse_principal_list, parse_request_timeout_secs};

    #[test]
    fn request_timeout_defaults_to_30() {
        assert_eq!(parse_request_timeout_secs(None), 30);
        assert_eq!(parse_request_timeout_secs(Some("bad")), 30);
    }

    #[test]
    fn request_timeout_is_clamped() {
        assert_eq!(parse_request_timeout_secs(Some("0")), 1);
        assert_eq!(parse_request_timeout_secs(Some("999")), 300);
    }

    #[test]
    fn admin_access_defaults_to_any_authenticated() {
        assert!(AdminAccessConfig::default().allow_any_authenticated);
    }

    #[test]
    fn parse_principal_list_supports_commas_and_whitespace() {
        assert_eq!(
            parse_principal_list("ops,ci admins"),
            vec!["ops".to_string(), "ci".to_string(), "admins".to_string()]
        );
    }
}
