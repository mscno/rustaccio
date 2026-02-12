use crate::error::RegistryError;
use axum::http::StatusCode;
use reqwest::Client;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Upstream {
    base_url: String,
    client: Client,
}

impl Upstream {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
        }
    }

    pub async fn fetch_package(&self, package_name: &str) -> Result<Option<Value>, RegistryError> {
        let encoded = urlencoding::encode(package_name);
        let url = format!("{}/{}", self.base_url, encoded);
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline"))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let value = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        Ok(Some(value))
    }

    pub async fn fetch_search(&self, query: &str) -> Result<Vec<Value>, RegistryError> {
        let url = if query.is_empty() {
            format!("{}/-/v1/search", self.base_url)
        } else {
            format!("{}/-/v1/search?{}", self.base_url, query)
        };
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline"))?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            return Ok(Vec::new());
        }

        let body = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        let objects = body
            .get("objects")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(objects)
    }

    pub async fn fetch_tarball(&self, tarball_url: &str) -> Result<Option<Vec<u8>>, RegistryError> {
        let resp = self
            .client
            .get(tarball_url)
            .send()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline"))?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        Ok(Some(bytes.to_vec()))
    }

    pub async fn post_security_advisories_bulk(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/advisories/bulk", payload)
            .await
    }

    pub async fn post_security_audits_quick(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/audits/quick", payload)
            .await
    }

    pub async fn post_security_audits(
        &self,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        self.post_json_path("/-/npm/v1/security/audits", payload)
            .await
    }

    async fn post_json_path(
        &self,
        path: &str,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = match self.client.post(url).json(payload).send().await {
            Ok(resp) => resp,
            Err(_) => return Ok(None),
        };

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Ok(None);
        }

        let value = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        Ok(Some(value))
    }

    pub fn default_tarball_url(&self, package_name: &str, filename: &str) -> String {
        format!(
            "{}/{}/-/{}",
            self.base_url,
            urlencoding::encode(package_name),
            filename
        )
    }
}
