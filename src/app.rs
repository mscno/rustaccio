use crate::{acl::Acl, api, storage::Store, upstream::Upstream};
use axum::{
    Router,
    http::{HeaderName, StatusCode},
    routing::any,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnFailure, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
    pub acl: Acl,
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
    let request_timeout_secs = std::env::var("RUSTACCIO_REQUEST_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
        .clamp(1, 300);
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
