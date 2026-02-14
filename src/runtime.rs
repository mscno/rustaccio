use crate::{
    acl::Acl,
    app::{AdminAccessConfig, AppState, build_router},
    auth::AuthHook,
    config::Config,
    error::RegistryError,
    governance::GovernanceEngine,
    observability,
    policy::{DefaultPolicyEngine, HttpPolicyConfig},
    storage::{Store, StoreOptions},
    upstream::Upstream,
};
use axum::{body::Body, extract::Request, http::StatusCode};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as HyperBuilder,
    service::TowerToHyperService,
};
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tower::{Service, ServiceExt as _};
use tracing::instrument;

#[instrument(skip(config, auth_hook))]
pub async fn build_state(
    config: &Config,
    auth_hook: Option<Arc<dyn AuthHook>>,
) -> Result<AppState, RegistryError> {
    let store = Arc::new(Store::open_with_options(config, StoreOptions { auth_hook }).await?);
    let acl = Acl::new(config.acl_rules.clone());
    let governance = Arc::new(GovernanceEngine::from_env().await?);
    let admin_access = AdminAccessConfig::from_env();
    validate_saas_guardrails(config, &admin_access)?;
    let policy = if let Some(policy_cfg) = HttpPolicyConfig::from_env() {
        Arc::new(DefaultPolicyEngine::new_with_http(
            store.clone(),
            acl.clone(),
            policy_cfg,
        )?)
    } else {
        Arc::new(DefaultPolicyEngine::new(store.clone(), acl.clone()))
    };

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
        acl,
        policy,
        governance,
        admin_access,
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

    tracing::info!(
        bind = %bind,
        data_dir,
        uplink_count,
        "rustaccio listening"
    );

    if let Some(keep_alive_timeout_secs) = config.keep_alive_timeout_secs {
        serve_with_keep_alive_timeout(listener, app, keep_alive_timeout_secs).await
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .tcp_nodelay(true)
            .await
            .map_err(|_| RegistryError::Internal)
    }
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

fn validate_saas_guardrails(
    config: &Config,
    admin_access: &AdminAccessConfig,
) -> Result<(), RegistryError> {
    validate_saas_guardrails_with_mode(saas_mode_enabled_from_env(), config, admin_access)
}

fn validate_saas_guardrails_with_mode(
    saas_mode: bool,
    config: &Config,
    admin_access: &AdminAccessConfig,
) -> Result<(), RegistryError> {
    if !saas_mode {
        return Ok(());
    }

    if admin_access.allow_any_authenticated {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_SAAS_MODE=true requires RUSTACCIO_ADMIN_ALLOW_ANY_AUTHENTICATED=false",
        ));
    }

    if admin_access.users.is_empty() && admin_access.groups.is_empty() {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_SAAS_MODE=true requires RUSTACCIO_ADMIN_USERS or RUSTACCIO_ADMIN_GROUPS",
        ));
    }

    if !config.auth_plugin.external_mode {
        return Err(RegistryError::http(
            StatusCode::INTERNAL_SERVER_ERROR,
            "RUSTACCIO_SAAS_MODE=true requires auth.plugin.externalMode=true",
        ));
    }

    Ok(())
}

fn saas_mode_enabled_from_env() -> bool {
    std::env::var("RUSTACCIO_SAAS_MODE")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

async fn serve_with_keep_alive_timeout(
    listener: TcpListener,
    app: axum::Router,
    keep_alive_timeout_secs: u64,
) -> Result<(), RegistryError> {
    let timeout_secs = keep_alive_timeout_secs.max(1);
    if keep_alive_timeout_secs == 0 {
        tracing::warn!(
            "server.keepAliveTimeout=0 is invalid; clamping to 1 second for HTTP/1 header read timeout"
        );
    }
    let keep_alive_timeout = Duration::from_secs(timeout_secs);
    tracing::info!(
        keep_alive_timeout_secs = timeout_secs,
        "applying server.keepAliveTimeout as HTTP/1 header read timeout"
    );

    let mut make_service = app.into_make_service();
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut connection_tasks = tokio::task::JoinSet::new();

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (tcp_stream, remote_addr) = tokio::select! {
            _ = &mut shutdown => {
                let _ = shutdown_tx.send(());
                break;
            }
            incoming = accept_connection(&listener) => {
                match incoming {
                    Some(conn) => conn,
                    None => continue,
                }
            }
        };

        if let Err(error) = tcp_stream.set_nodelay(true) {
            tracing::debug!(%error, "failed to set TCP_NODELAY on incoming connection");
        }

        let io = TokioIo::new(tcp_stream);
        let tower_service = make_service
            .call(())
            .await
            .unwrap_or_else(|err| match err {})
            .map_request(|request: Request<Incoming>| request.map(Body::new));
        let hyper_service = TowerToHyperService::new(tower_service);
        let mut shutdown_rx = shutdown_rx.clone();

        connection_tasks.spawn(async move {
            let mut builder = HyperBuilder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(TokioTimer::new())
                .header_read_timeout(Some(keep_alive_timeout));

            let connection = builder.serve_connection_with_upgrades(io, hyper_service);
            tokio::pin!(connection);

            tokio::select! {
                result = &mut connection => {
                    if let Err(error) = result {
                        tracing::debug!(%error, %remote_addr, "failed to serve connection");
                    }
                }
                _ = shutdown_rx.changed() => {
                    connection.as_mut().graceful_shutdown();
                    if let Err(error) = connection.await {
                        tracing::debug!(%error, %remote_addr, "failed to gracefully shut down connection");
                    }
                }
            }
        });
    }

    while let Some(result) = connection_tasks.join_next().await {
        if let Err(error) = result {
            tracing::debug!(%error, "connection task aborted");
        }
    }

    Ok(())
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

async fn accept_connection(listener: &TcpListener) -> Option<(TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok(conn) => Some(conn),
        Err(error) => {
            if is_connection_error(&error) {
                return None;
            }
            tracing::error!(%error, "accept error");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    use super::{startup_log_level, validate_saas_guardrails_with_mode};
    use crate::{
        app::AdminAccessConfig,
        config::{
            AuthBackend, AuthPluginConfig, Config, TarballStorageBackend, TarballStorageConfig,
        },
    };

    fn config_with_external_mode(external_mode: bool) -> Config {
        Config {
            bind: "127.0.0.1:4873".parse().expect("bind"),
            data_dir: std::env::temp_dir(),
            listen: vec!["127.0.0.1:4873".to_string()],
            upstream_registry: None,
            uplinks: std::collections::HashMap::new(),
            acl_rules: vec![crate::acl::PackageRule::open("**")],
            web_enabled: true,
            web_title: "Rustaccio".to_string(),
            web_login: true,
            publish_check_owners: false,
            password_min_length: 3,
            login_session_ttl_seconds: 600,
            max_body_size: 50 * 1024 * 1024,
            audit_enabled: true,
            url_prefix: "/".to_string(),
            trust_proxy: false,
            keep_alive_timeout_secs: None,
            log_level: "info".to_string(),
            auth_plugin: AuthPluginConfig {
                backend: AuthBackend::Local,
                external_mode,
                http: None,
            },
            tarball_storage: TarballStorageConfig {
                backend: TarballStorageBackend::Local,
                s3: None,
            },
        }
    }

    #[test]
    fn startup_log_level_uses_config_value() {
        let mut cfg = Config::defaults_for_examples();
        cfg.log_level = "debug".to_string();
        assert_eq!(startup_log_level(&cfg), "debug");
    }

    #[test]
    fn saas_guardrails_allow_simple_mode_defaults() {
        let config = config_with_external_mode(false);
        let admin = AdminAccessConfig::default();
        assert!(validate_saas_guardrails_with_mode(false, &config, &admin).is_ok());
    }

    #[test]
    fn saas_guardrails_reject_any_authenticated_admin_access() {
        let config = config_with_external_mode(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: true,
            users: vec!["ops".to_string()],
            groups: Vec::new(),
        };
        let err = validate_saas_guardrails_with_mode(true, &config, &admin).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("ADMIN_ALLOW_ANY_AUTHENTICATED=false")
        );
    }

    #[test]
    fn saas_guardrails_reject_missing_admin_principals() {
        let config = config_with_external_mode(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: Vec::new(),
            groups: Vec::new(),
        };
        let err = validate_saas_guardrails_with_mode(true, &config, &admin).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("ADMIN_USERS or RUSTACCIO_ADMIN_GROUPS")
        );
    }

    #[test]
    fn saas_guardrails_require_external_auth_mode() {
        let config = config_with_external_mode(false);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: vec!["ops".to_string()],
            groups: Vec::new(),
        };
        let err = validate_saas_guardrails_with_mode(true, &config, &admin).expect_err("must fail");
        assert!(err.to_string().contains("auth.plugin.externalMode=true"));
    }

    #[test]
    fn saas_guardrails_accept_external_mode_with_explicit_admins() {
        let config = config_with_external_mode(true);
        let admin = AdminAccessConfig {
            allow_any_authenticated: false,
            users: vec!["ops".to_string()],
            groups: vec!["platform-admins".to_string()],
        };
        assert!(validate_saas_guardrails_with_mode(true, &config, &admin).is_ok());
    }
}
