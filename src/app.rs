use crate::{acl::Acl, api, storage::Store, upstream::Upstream};
use axum::{Router, routing::any};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Debug)]
pub struct AppState {
    pub store: Arc<Store>,
    pub acl: Acl,
    pub uplinks: HashMap<String, Upstream>,
    pub web_login_enabled: bool,
    pub publish_check_owners: bool,
}

pub fn build_router(state: AppState) -> Router {
    Router::new().fallback(any(api::dispatch)).with_state(state)
}
