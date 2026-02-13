use std::sync::OnceLock;
use tracing_subscriber::{
    EnvFilter, fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

static TRACING_INIT: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub enum LogFormat {
    Pretty,
    Compact,
    Json,
}

impl LogFormat {
    fn from_env() -> Self {
        match std::env::var("RUSTACCIO_LOG_FORMAT")
            .unwrap_or_else(|_| "pretty".to_string())
            .to_ascii_lowercase()
            .as_str()
        {
            "json" => Self::Json,
            "compact" => Self::Compact,
            _ => Self::Pretty,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pretty => "pretty",
            Self::Compact => "compact",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TracingSettings {
    pub filter: String,
    pub log_format: LogFormat,
}

pub fn init_from_env(default_level: &str) -> TracingSettings {
    let filter = std::env::var("RUST_LOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("rustaccio={default_level},tower_http=info"));
    let log_format = LogFormat::from_env();

    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(filter.clone()))
        .unwrap_or_else(|_| EnvFilter::new("rustaccio=info,tower_http=info"));

    TRACING_INIT.get_or_init(|| match log_format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(
                    fmt::layer()
                        .json()
                        .flatten_event(true)
                        .with_current_span(true)
                        .with_span_list(true)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(
                    fmt::layer()
                        .compact()
                        .with_target(true)
                        .with_line_number(true)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_error::ErrorLayer::default())
                .with(
                    fmt::layer()
                        .pretty()
                        .with_target(true)
                        .with_line_number(true)
                        .with_span_events(FmtSpan::CLOSE),
                )
                .init();
        }
    });

    TracingSettings { filter, log_format }
}
