use crate::{
    config::HttpAuthPluginConfig,
    constants::{API_ERROR_BAD_USERNAME_PASSWORD, API_ERROR_PASSWORD_SHORT},
    error::RegistryError,
};
use axum::http::StatusCode;
use reqwest::Client;
use serde_json::{Value, json};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct HttpAuthPlugin {
    base_url: String,
    add_user_endpoint: String,
    login_endpoint: String,
    change_password_endpoint: String,
    client: Client,
}

impl HttpAuthPlugin {
    pub fn new(cfg: &HttpAuthPluginConfig) -> Result<Self, RegistryError> {
        let base_url = cfg.base_url.trim().trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "auth plugin base_url is required",
            ));
        }

        let client = Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .build()
            .map_err(|_| RegistryError::Internal)?;

        Ok(Self {
            base_url,
            add_user_endpoint: normalize_endpoint(&cfg.add_user_endpoint),
            login_endpoint: normalize_endpoint(&cfg.login_endpoint),
            change_password_endpoint: normalize_endpoint(&cfg.change_password_endpoint),
            client,
        })
    }

    pub async fn add_user(
        &self,
        username: &str,
        password: &str,
        min_password_len: usize,
    ) -> Result<(), RegistryError> {
        if password.len() < min_password_len {
            return Err(RegistryError::http(
                StatusCode::BAD_REQUEST,
                API_ERROR_PASSWORD_SHORT,
            ));
        }
        self.post_json(
            &self.add_user_endpoint,
            &json!({
                "username": username,
                "password": password,
            }),
        )
        .await
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<(), RegistryError> {
        self.post_json(
            &self.login_endpoint,
            &json!({
                "username": username,
                "password": password,
            }),
        )
        .await
    }

    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
        min_password_len: usize,
    ) -> Result<(), RegistryError> {
        if new_password.len() < min_password_len {
            return Err(RegistryError::http(
                StatusCode::UNAUTHORIZED,
                API_ERROR_PASSWORD_SHORT,
            ));
        }
        self.post_json(
            &self.change_password_endpoint,
            &json!({
                "username": username,
                "old_password": old_password,
                "new_password": new_password,
            }),
        )
        .await
    }

    async fn post_json(&self, endpoint: &str, payload: &Value) -> Result<(), RegistryError> {
        let url = format!("{}{}", self.base_url, endpoint);
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "auth plugin offline"))?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
        let message = extract_error_message(response)
            .await
            .unwrap_or_else(|| API_ERROR_BAD_USERNAME_PASSWORD.to_string());

        Err(RegistryError::http(status, message))
    }
}

fn normalize_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

async fn extract_error_message(response: reqwest::Response) -> Option<String> {
    let parsed = response.json::<Value>().await.ok()?;
    parsed
        .get("error")
        .and_then(Value::as_str)
        .or_else(|| parsed.get("message").and_then(Value::as_str))
        .map(ToOwned::to_owned)
}
