use crate::{
    auth::AuthHook,
    config::HttpAuthPluginConfig,
    constants::{API_ERROR_BAD_USERNAME_PASSWORD, API_ERROR_PASSWORD_SHORT},
    error::RegistryError,
    models::AuthIdentity,
};
use async_trait::async_trait;
use axum::http::StatusCode;
use reqwest::Client;
use serde_json::{Value, json};
use std::time::Duration;
use tracing::{debug, instrument, warn};

#[derive(Debug, Clone)]
pub struct HttpAuthPlugin {
    base_url: String,
    add_user_endpoint: String,
    login_endpoint: String,
    change_password_endpoint: String,
    request_auth_endpoint: Option<String>,
    allow_access_endpoint: Option<String>,
    allow_publish_endpoint: Option<String>,
    allow_unpublish_endpoint: Option<String>,
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
            request_auth_endpoint: cfg
                .request_auth_endpoint
                .clone()
                .map(|v| normalize_endpoint(&v)),
            allow_access_endpoint: cfg
                .allow_access_endpoint
                .clone()
                .map(|v| normalize_endpoint(&v)),
            allow_publish_endpoint: cfg
                .allow_publish_endpoint
                .clone()
                .map(|v| normalize_endpoint(&v)),
            allow_unpublish_endpoint: cfg
                .allow_unpublish_endpoint
                .clone()
                .map(|v| normalize_endpoint(&v)),
            client,
        })
    }

    #[instrument(skip(self, password), fields(username))]
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

    #[instrument(skip(self, password), fields(username))]
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

    #[instrument(skip(self, old_password, new_password), fields(username))]
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

    #[instrument(skip(self, token), fields(method, path))]
    pub async fn authenticate_request(
        &self,
        token: &str,
        method: &str,
        path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        let Some(endpoint) = &self.request_auth_endpoint else {
            return Ok(None);
        };
        let url = format!("{}{}", self.base_url, endpoint);
        let response = self
            .client
            .post(url)
            .json(&json!({
                "token": token,
                "method": method,
                "path": path,
            }))
            .send()
            .await
            .map_err(|_| {
                warn!("auth plugin request-auth endpoint is offline");
                RegistryError::http(StatusCode::BAD_GATEWAY, "auth plugin offline")
            })?;

        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            debug!(
                status = response.status().as_u16(),
                "request auth rejected by plugin"
            );
            return Ok(None);
        }
        if !response.status().is_success() {
            let status = response.status();
            warn!(status = status.as_u16(), "request auth endpoint failed");
            let message = extract_error_message(response)
                .await
                .unwrap_or_else(|| "request auth failed".to_string());
            return Err(RegistryError::http(status, message));
        }

        let payload = response
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad auth plugin payload"))?;

        if payload
            .get("authenticated")
            .and_then(Value::as_bool)
            .is_some_and(|authenticated| !authenticated)
        {
            debug!("request auth returned authenticated=false");
            return Ok(None);
        }

        let username = payload
            .get("username")
            .or_else(|| payload.get("user"))
            .or_else(|| payload.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                payload
                    .get("group")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            });

        let mut groups = payload
            .get("groups")
            .or_else(|| payload.get("roles"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        if groups.is_empty()
            && let Some(group) = payload.get("group").and_then(Value::as_str)
        {
            groups.push(group.to_string());
        }

        if username.is_none() && groups.is_empty() {
            debug!("request auth returned empty identity");
            return Ok(None);
        }

        debug!(
            has_username = username.is_some(),
            group_count = groups.len(),
            "request auth accepted"
        );
        Ok(Some(AuthIdentity { username, groups }))
    }

    #[instrument(skip(self, identity), fields(package_name))]
    pub async fn allow_access(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        self.allow_decision(
            self.allow_access_endpoint.as_deref(),
            identity,
            package_name,
        )
        .await
    }

    #[instrument(skip(self, identity), fields(package_name))]
    pub async fn allow_publish(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        self.allow_decision(
            self.allow_publish_endpoint.as_deref(),
            identity,
            package_name,
        )
        .await
    }

    #[instrument(skip(self, identity), fields(package_name))]
    pub async fn allow_unpublish(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        self.allow_decision(
            self.allow_unpublish_endpoint.as_deref(),
            identity,
            package_name,
        )
        .await
    }

    #[instrument(skip(self, identity), fields(endpoint = endpoint.unwrap_or("<none>"), package_name))]
    async fn allow_decision(
        &self,
        endpoint: Option<&str>,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        let Some(endpoint) = endpoint else {
            return Ok(None);
        };

        let url = format!("{}{}", self.base_url, endpoint);
        let response = self
            .client
            .post(url)
            .json(&json!({
                "package": package_name,
                "username": identity.as_ref().and_then(|id| id.username.as_deref()),
                "groups": identity
                    .as_ref()
                    .map(|id| id.groups.clone())
                    .unwrap_or_default(),
                "identity": identity,
            }))
            .send()
            .await
            .map_err(|_| {
                warn!("auth plugin allow endpoint is offline");
                RegistryError::http(StatusCode::BAD_GATEWAY, "auth plugin offline")
            })?;

        if response.status() == StatusCode::UNAUTHORIZED
            || response.status() == StatusCode::FORBIDDEN
        {
            debug!(
                status = response.status().as_u16(),
                "allow endpoint denied request"
            );
            return Ok(Some(false));
        }
        if !response.status().is_success() {
            let status = response.status();
            warn!(status = status.as_u16(), "allow endpoint failed");
            let message = extract_error_message(response)
                .await
                .unwrap_or_else(|| "allow hook request failed".to_string());
            return Err(RegistryError::http(status, message));
        }

        let payload = response
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad auth plugin payload"))?;

        if let Some(allowed) = payload.get("allowed").and_then(Value::as_bool) {
            debug!(allowed, "allow endpoint decision");
            return Ok(Some(allowed));
        }
        if let Some(allowed) = payload.as_bool() {
            debug!(allowed, "allow endpoint decision");
            return Ok(Some(allowed));
        }

        debug!("allow endpoint did not return a decision");
        Ok(None)
    }

    #[instrument(skip(self, payload), fields(endpoint))]
    async fn post_json(&self, endpoint: &str, payload: &Value) -> Result<(), RegistryError> {
        let url = format!("{}{}", self.base_url, endpoint);
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|_| {
                warn!("auth plugin endpoint is offline");
                RegistryError::http(StatusCode::BAD_GATEWAY, "auth plugin offline")
            })?;

        if response.status().is_success() {
            debug!(
                status = response.status().as_u16(),
                "auth plugin request succeeded"
            );
            return Ok(());
        }

        let status = response.status();
        warn!(status = status.as_u16(), "auth plugin request failed");
        let message = extract_error_message(response)
            .await
            .unwrap_or_else(|| API_ERROR_BAD_USERNAME_PASSWORD.to_string());

        Err(RegistryError::http(status, message))
    }
}

#[async_trait]
impl AuthHook for HttpAuthPlugin {
    async fn add_user(
        &self,
        username: &str,
        password: &str,
        min_password_len: usize,
    ) -> Result<(), RegistryError> {
        HttpAuthPlugin::add_user(self, username, password, min_password_len).await
    }

    async fn authenticate(&self, username: &str, password: &str) -> Result<(), RegistryError> {
        HttpAuthPlugin::authenticate(self, username, password).await
    }

    async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
        min_password_len: usize,
    ) -> Result<(), RegistryError> {
        HttpAuthPlugin::change_password(
            self,
            username,
            old_password,
            new_password,
            min_password_len,
        )
        .await
    }

    async fn authenticate_request(
        &self,
        token: &str,
        method: &str,
        path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        HttpAuthPlugin::authenticate_request(self, token, method, path).await
    }

    async fn allow_access(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        HttpAuthPlugin::allow_access(self, identity, package_name).await
    }

    async fn allow_publish(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        HttpAuthPlugin::allow_publish(self, identity, package_name).await
    }

    async fn allow_unpublish(
        &self,
        identity: Option<AuthIdentity>,
        package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        HttpAuthPlugin::allow_unpublish(self, identity, package_name).await
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
