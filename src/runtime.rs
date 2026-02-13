use crate::{
    acl::Acl,
    app::{AppState, build_router},
    auth::AuthHook,
    config::Config,
    error::RegistryError,
    observability,
    storage::{Store, StoreOptions},
    upstream::Upstream,
};
use axum::http::StatusCode;
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;

#[instrument(skip(config, auth_hook))]
pub async fn build_state(
    config: &Config,
    auth_hook: Option<Arc<dyn AuthHook>>,
) -> Result<AppState, RegistryError> {
    let store = Arc::new(Store::open_with_options(config, StoreOptions { auth_hook }).await?);

    let mut uplinks = HashMap::new();
    for (name, url) in &config.uplinks {
        uplinks.insert(name.clone(), Upstream::new(url.clone()));
    }
    if uplinks.is_empty()
        && let Some(url) = config.upstream_registry.clone()
    {
        uplinks.insert("default".to_string(), Upstream::new(url));
    }

    Ok(AppState {
        store,
        acl: Acl::new(config.acl_rules.clone()),
        uplinks,
        web_enabled: config.web_enabled,
        web_title: config.web_title.clone(),
        web_login_enabled: config.web_login,
        publish_check_owners: config.publish_check_owners,
        max_body_size: config.max_body_size,
        audit_enabled: config.audit_enabled,
        url_prefix: config.url_prefix.clone(),
        trust_proxy: config.trust_proxy,
        auth_external_mode: config.auth_plugin.external_mode,
    })
}

pub async fn run(
    config: Config,
    auth_hook: Option<Arc<dyn AuthHook>>,
) -> Result<(), RegistryError> {
    let bind = config.bind;
    let data_dir = config.data_dir.display().to_string();
    let uplink_count = config.uplinks.len();
    let state = build_state(&config, auth_hook).await?;
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;

    if let Some(keep_alive_timeout_secs) = config.keep_alive_timeout_secs {
        tracing::warn!(
            keep_alive_timeout_secs,
            "server.keepAliveTimeout is configured but currently not supported by this axum runtime path"
        );
    }

    tracing::info!(
        bind = %bind,
        data_dir,
        uplink_count,
        "rustaccio listening"
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .tcp_nodelay(true)
        .await
        .map_err(|_| RegistryError::Internal)
}

pub async fn run_standalone(config: Config) -> Result<(), RegistryError> {
    let default_level = startup_log_level(&config).to_string();
    let tracing_settings = observability::init_from_env(&default_level);
    tracing::debug!(
        log_filter = tracing_settings.filter,
        log_format = tracing_settings.log_format.as_str(),
        "initialized tracing subscriber"
    );
    run(config, None).await
}

pub async fn run_from_env() -> Result<(), RegistryError> {
    let config = Config::from_env().map_err(|err| {
        RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid runtime configuration: {err}"),
        )
    })?;
    run_standalone(config).await
}

fn startup_log_level(config: &Config) -> &str {
    config.log_level.as_str()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        let terminate = async {
            if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
                let _ = sigterm.recv().await;
            }
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::startup_log_level;
    use crate::config::Config;

    #[test]
    fn startup_log_level_uses_config_value() {
        let mut cfg = Config::defaults_for_examples();
        cfg.log_level = "debug".to_string();
        assert_eq!(startup_log_level(&cfg), "debug");
    }
}
