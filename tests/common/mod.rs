//! Shared helpers for integration tests.
//!
//! The registry only supports anonymous access or external HTTP token auth, so
//! tests that need an authenticated identity point the registry at a mock
//! external auth service. The mock authenticates any bearer token by echoing
//! the token back as the username, so a test can use a username directly as its
//! bearer token (e.g. `Bearer alice` authenticates as user `alice`).
#![allow(dead_code)]

use rustaccio::config::HttpAuthPluginConfig;
use serde_json::json;
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

/// Start a mock external auth server whose `/request-auth` endpoint
/// authenticates any non-empty bearer token by echoing it back as the username.
/// An empty/missing token is rejected with 401 (anonymous).
pub async fn start_token_echo_auth() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/request-auth"))
        .respond_with(|req: &Request| {
            let token = serde_json::from_slice::<serde_json::Value>(&req.body)
                .ok()
                .and_then(|body| {
                    body.get("token")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned)
                })
                .unwrap_or_default();
            if token.is_empty() {
                ResponseTemplate::new(401)
            } else {
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "authenticated": true, "username": token }))
            }
        })
        .mount(&server)
        .await;
    server
}

/// Build an `HttpAuthPluginConfig` pointing at a mock auth server's
/// `/request-auth` endpoint.
pub fn external_auth_plugin(base_url: &str) -> HttpAuthPluginConfig {
    HttpAuthPluginConfig {
        base_url: base_url.to_string(),
        request_auth_endpoint: Some("/request-auth".to_string()),
        allow_access_endpoint: None,
        allow_publish_endpoint: None,
        allow_unpublish_endpoint: None,
        timeout_ms: 5_000,
    }
}
