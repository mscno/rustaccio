use rustaccio::{
    acl::Acl,
    app::{AppState, build_router},
    config::Config,
    storage::Store,
    upstream::Upstream,
};
use std::{collections::HashMap, sync::Arc};
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("rustaccio=info".parse().expect("directive")),
        )
        .init();

    let config = Config::from_env();
    let store = Arc::new(Store::open(&config).await.expect("open store"));
    let mut uplinks = HashMap::new();
    for (name, url) in &config.uplinks {
        uplinks.insert(name.clone(), Upstream::new(url.clone()));
    }
    if uplinks.is_empty()
        && let Some(url) = config.upstream_registry.clone()
    {
        uplinks.insert("default".to_string(), Upstream::new(url));
    }

    let state = AppState {
        store,
        acl: Acl::new(config.acl_rules.clone()),
        uplinks,
        web_login_enabled: config.web_login,
        publish_check_owners: config.publish_check_owners,
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .expect("bind listener");
    tracing::info!("rustaccio listening on {}", config.bind);

    axum::serve(listener, app).await.expect("server error");
}
