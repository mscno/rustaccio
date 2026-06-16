use crate::{error::RegistryError, models::AuthIdentity};
use async_trait::async_trait;

#[async_trait]
pub trait AuthHook: Send + Sync {
    async fn authenticate_request(
        &self,
        _token: &str,
        _method: &str,
        _path: &str,
    ) -> Result<Option<AuthIdentity>, RegistryError> {
        Ok(None)
    }

    async fn allow_access(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        Ok(None)
    }

    async fn allow_publish(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        Ok(None)
    }

    async fn allow_unpublish(
        &self,
        _identity: Option<AuthIdentity>,
        _package_name: &str,
    ) -> Result<Option<bool>, RegistryError> {
        Ok(None)
    }
}
