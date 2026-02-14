use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct AuthIdentity {
    pub username: Option<String>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct TenantContext {
    pub org_id: Option<String>,
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub password_hash: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTokenRecord {
    pub user: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NpmTokenRecord {
    pub user: String,
    pub token: String,
    pub key: String,
    pub auth_key: String,
    pub cidr: Vec<String>,
    pub readonly: bool,
    pub created: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginSessionRecord {
    pub token: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRecord {
    pub manifest: Value,
    pub upstream_tarballs: HashMap<String, String>,
    pub updated_at: i64,
    #[serde(default)]
    pub cached_from_uplink: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub users: HashMap<String, UserRecord>,
    pub auth_tokens: HashMap<String, AuthTokenRecord>,
    pub npm_tokens: Vec<NpmTokenRecord>,
    pub login_sessions: HashMap<String, LoginSessionRecord>,
    pub packages: HashMap<String, PackageRecord>,
}
