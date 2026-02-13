use crate::{
    config::{Config, S3TarballStorageConfig, TarballStorageBackend},
    error::RegistryError,
};
use axum::http::StatusCode;
use std::path::PathBuf;
use tracing::{debug, instrument, warn};

#[derive(Debug, Clone)]
pub enum TarballBackend {
    Local(LocalTarballBackend),
    #[cfg(feature = "s3")]
    S3(S3TarballBackend),
}

impl TarballBackend {
    #[instrument(skip(config), fields(backend = ?config.tarball_storage.backend, data_dir = %config.data_dir.display()))]
    pub async fn from_config(config: &Config) -> Result<Self, RegistryError> {
        match config.tarball_storage.backend {
            TarballStorageBackend::Local => {
                let root = config.data_dir.join("tarballs");
                tokio::fs::create_dir_all(&root).await?;
                debug!(root = %root.display(), "initialized local tarball backend");
                Ok(Self::Local(LocalTarballBackend::new(root)))
            }
            TarballStorageBackend::S3 => {
                #[cfg(feature = "s3")]
                {
                    let Some(s3) = config.tarball_storage.s3.as_ref() else {
                        return Err(RegistryError::http(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "s3 tarball backend configured without s3 section",
                        ));
                    };
                    Ok(Self::S3(S3TarballBackend::new(s3).await?))
                }
                #[cfg(not(feature = "s3"))]
                {
                    Err(RegistryError::http(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "s3 tarball backend is not compiled in (enable `s3` feature)",
                    ))
                }
            }
        }
    }

    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        match self {
            Self::Local(backend) => backend.put(package, filename, content).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.put(package, filename, content).await,
        }
    }

    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        match self {
            Self::Local(backend) => backend.get(package, filename).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.get(package, filename).await,
        }
    }

    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        match self {
            Self::Local(backend) => backend.delete(package, filename).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.delete(package, filename).await,
        }
    }

    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        match self {
            Self::Local(backend) => backend.delete_package(package).await,
            #[cfg(feature = "s3")]
            Self::S3(backend) => backend.delete_package(package).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalTarballBackend {
    root: PathBuf,
}

impl LocalTarballBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn package_dir(name: &str) -> String {
        name.replace('/', "__")
    }

    fn tarball_path(&self, package: &str, filename: &str) -> PathBuf {
        self.root.join(Self::package_dir(package)).join(filename)
    }

    #[instrument(skip(self, content), fields(package, filename, bytes = content.len()))]
    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        let path = self.tarball_path(package, filename);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, content).await?;
        debug!(path = %path.display(), "wrote tarball to local storage");
        Ok(())
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        let path = self.tarball_path(package, filename);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            debug!(path = %path.display(), "local tarball missing");
            return Ok(None);
        }
        debug!(path = %path.display(), "reading local tarball");
        Ok(Some(tokio::fs::read(path).await?))
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        let path = self.tarball_path(package, filename);
        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Ok(false);
        }
        tokio::fs::remove_file(path).await?;
        debug!("deleted local tarball");
        Ok(true)
    }

    #[instrument(skip(self), fields(package))]
    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        let path = self.root.join(Self::package_dir(package));
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            let _ = tokio::fs::remove_dir_all(path).await;
            debug!("deleted local package tarball directory");
        }
        Ok(())
    }
}

#[cfg(feature = "s3")]
#[derive(Debug, Clone)]
pub struct S3TarballBackend {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[cfg(feature = "s3")]
impl S3TarballBackend {
    #[instrument(skip(cfg), fields(bucket = cfg.bucket, region = cfg.region, endpoint = cfg.endpoint.as_deref().unwrap_or("<aws-default>")))]
    pub async fn new(cfg: &S3TarballStorageConfig) -> Result<Self, RegistryError> {
        if cfg.bucket.trim().is_empty() {
            return Err(RegistryError::http(
                StatusCode::INTERNAL_SERVER_ERROR,
                "s3.bucket is required for s3 tarball backend",
            ));
        }

        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(cfg.region.clone()));

        if let (Some(access_key), Some(secret_key)) =
            (cfg.access_key_id.clone(), cfg.secret_access_key.clone())
        {
            loader = loader.credentials_provider(aws_sdk_s3::config::Credentials::new(
                access_key,
                secret_key,
                None,
                None,
                "rustaccio-static",
            ));
        }

        let shared = loader.load().await;
        let mut builder = aws_sdk_s3::config::Builder::from(&shared);
        if let Some(endpoint) = cfg.endpoint.clone() {
            builder = builder.endpoint_url(endpoint);
        }
        if cfg.force_path_style {
            builder = builder.force_path_style(true);
        }

        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(builder.build()),
            bucket: cfg.bucket.clone(),
            prefix: normalize_prefix(&cfg.prefix),
        })
    }

    fn key(&self, package: &str, filename: &str) -> String {
        format!("{}{}/{}", self.prefix, package.replace('/', "__"), filename)
    }

    fn package_prefix(&self, package: &str) -> String {
        format!("{}{}/", self.prefix, package.replace('/', "__"))
    }

    #[instrument(skip(self), fields(key))]
    async fn exists(&self, key: &str) -> Result<bool, RegistryError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) if is_not_found(&err) => Ok(false),
            Err(_) => {
                warn!("s3 head_object failed");
                Err(RegistryError::Internal)
            }
        }
    }

    #[instrument(skip(self, content), fields(package, filename, bytes = content.len()))]
    pub async fn put(
        &self,
        package: &str,
        filename: &str,
        content: &[u8],
    ) -> Result<(), RegistryError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(package, filename))
            .body(aws_sdk_s3::primitives::ByteStream::from(content.to_vec()))
            .send()
            .await
            .map_err(|_| RegistryError::Internal)?;
        debug!("uploaded tarball to s3");
        Ok(())
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn get(
        &self,
        package: &str,
        filename: &str,
    ) -> Result<Option<Vec<u8>>, RegistryError> {
        let key = self.key(package, filename);
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(err) if is_not_found(&err) => return Ok(None),
            Err(_) => {
                warn!("s3 get_object failed");
                return Err(RegistryError::Internal);
            }
        };

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|_| RegistryError::Internal)?;
        let bytes = bytes.into_bytes();
        debug!(bytes = bytes.len(), "downloaded tarball from s3");
        Ok(Some(bytes.to_vec()))
    }

    #[instrument(skip(self), fields(package, filename))]
    pub async fn delete(&self, package: &str, filename: &str) -> Result<bool, RegistryError> {
        let key = self.key(package, filename);
        if !self.exists(&key).await? {
            return Ok(false);
        }

        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|_| RegistryError::Internal)?;
        debug!("deleted tarball from s3");
        Ok(true)
    }

    #[instrument(skip(self), fields(package))]
    pub async fn delete_package(&self, package: &str) -> Result<(), RegistryError> {
        let mut continuation: Option<String> = None;
        let prefix = self.package_prefix(package);

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(prefix.clone());
            if let Some(token) = continuation.clone() {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|_| RegistryError::Internal)?;
            let objects = response.contents();
            for object in objects {
                if let Some(key) = object.key() {
                    self.client
                        .delete_object()
                        .bucket(&self.bucket)
                        .key(key)
                        .send()
                        .await
                        .map_err(|_| RegistryError::Internal)?;
                }
            }

            if response.is_truncated.unwrap_or(false) {
                continuation = response.next_continuation_token;
            } else {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(feature = "s3")]
fn normalize_prefix(prefix: &str) -> String {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

#[cfg(feature = "s3")]
fn is_not_found<E>(err: &aws_sdk_s3::error::SdkError<E>) -> bool {
    err.raw_response()
        .map(|response| response.status().as_u16() == 404)
        .unwrap_or(false)
}
