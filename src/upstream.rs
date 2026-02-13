use crate::error::RegistryError;
use axum::http::StatusCode;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, instrument, warn};

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

    #[instrument(skip(self), fields(package = package_name, upstream = %self.base_url))]
    pub async fn fetch_package(&self, package_name: &str) -> Result<Option<Value>, RegistryError> {
        let encoded = urlencoding::encode(package_name);
        let url = format!("{}/{}", self.base_url, encoded);
        let resp = self.client.get(url).send().await.map_err(|_| {
            warn!("uplink package request failed");
            RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline")
        })?;
        if resp.status() == StatusCode::NOT_FOUND {
            debug!("package not found upstream");
            return Ok(None);
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected uplink package status"
            );
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let value = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        debug!("fetched package from upstream");
        Ok(Some(value))
    }

    #[instrument(skip(self), fields(has_query = !query.is_empty(), upstream = %self.base_url))]
    pub async fn fetch_search(&self, query: &str) -> Result<Vec<Value>, RegistryError> {
        let url = if query.is_empty() {
            format!("{}/-/v1/search", self.base_url)
        } else {
            format!("{}/-/v1/search?{}", self.base_url, query)
        };
        let resp = self.client.get(url).send().await.map_err(|_| {
            warn!("uplink search request failed");
            RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline")
        })?;
        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected uplink search status"
            );
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
        debug!(result_count = objects.len(), "fetched upstream search");
        Ok(objects)
    }

    #[instrument(skip(self), fields(upstream = %self.base_url))]
    pub async fn fetch_tarball(&self, tarball_url: &str) -> Result<Option<Vec<u8>>, RegistryError> {
        let resp = self.client.get(tarball_url).send().await.map_err(|_| {
            warn!("uplink tarball request failed");
            RegistryError::http(StatusCode::BAD_GATEWAY, "uplink is offline")
        })?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected uplink tarball status"
            );
            return Err(RegistryError::http(
                StatusCode::BAD_GATEWAY,
                "bad status code",
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        debug!(bytes = bytes.len(), "fetched upstream tarball");
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

    #[instrument(skip(self, payload), fields(path, upstream = %self.base_url))]
    async fn post_json_path(
        &self,
        path: &str,
        payload: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        let url = format!("{}{}", self.base_url, path);
        let resp = match self.client.post(url).json(payload).send().await {
            Ok(resp) => resp,
            Err(_) => {
                warn!("upstream post request failed");
                return Ok(None);
            }
        };

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            warn!(
                status = resp.status().as_u16(),
                "unexpected upstream post status"
            );
            return Ok(None);
        }

        let value = resp
            .json::<Value>()
            .await
            .map_err(|_| RegistryError::http(StatusCode::BAD_GATEWAY, "bad uplink payload"))?;
        debug!("received upstream post response");
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
