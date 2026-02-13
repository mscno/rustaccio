use crate::{error::RegistryError, models::AuthIdentity};
use async_trait::async_trait;
use axum::http::StatusCode;

#[async_trait]
pub trait AuthHook: Send + Sync {
    async fn add_user(
        &self,
        _username: &str,
        _password: &str,
        _min_password_len: usize,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::http(
            StatusCode::FORBIDDEN,
            "adduser is not supported",
        ))
    }

    async fn authenticate(&self, _username: &str, _password: &str) -> Result<(), RegistryError> {
        Err(RegistryError::http(
            StatusCode::FORBIDDEN,
            "authentication is not supported",
        ))
    }

    async fn change_password(
        &self,
        _username: &str,
        _old_password: &str,
        _new_password: &str,
        _min_password_len: usize,
    ) -> Result<(), RegistryError> {
        Err(RegistryError::http(
            StatusCode::FORBIDDEN,
            "changePassword is not supported",
        ))
    }

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
