use std::sync::OnceLock;
use tracing_subscriber::{
    EnvFilter, fmt, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};

static TRACING_INIT: OnceLock<()> = OnceLock::new();
const NOISY_DEP_TARGETS: [&str; 9] = [
    "aws_config",
    "aws_runtime",
    "aws_sdk_s3",
    "aws_smithy_runtime",
    "aws_smithy_runtime_api",
    "aws_smithy_http_client",
    "hyper_util",
    "h2",
    "rustls",
];

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
    let base_filter = std::env::var("RUST_LOG")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("rustaccio={default_level},tower_http=info"));
    let filter = with_noisy_dependency_guards(base_filter);
    let log_format = LogFormat::from_env();

    let env_filter = EnvFilter::try_new(filter.clone())
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

fn with_noisy_dependency_guards(filter: String) -> String {
    let verbose_dependencies = std::env::var("RUSTACCIO_VERBOSE_DEP_LOGS")
        .map(|value| value.eq_ignore_ascii_case("true") || value == "1")
        .unwrap_or(false);
    if verbose_dependencies {
        return filter;
    }

    let mut directives = filter;
    for target in NOISY_DEP_TARGETS {
        if !has_target_directive(&directives, target) {
            directives.push(',');
            directives.push_str(target);
            directives.push_str("=warn");
        }
    }
    directives
}

fn has_target_directive(filter: &str, target: &str) -> bool {
    filter
        .split(',')
        .map(str::trim)
        .any(|directive| directive.starts_with(&format!("{target}=")))
}

#[cfg(test)]
mod tests {
    use super::{has_target_directive, with_noisy_dependency_guards};

    #[test]
    fn appends_dependency_guards_to_global_debug_filter() {
        let out = with_noisy_dependency_guards("debug".to_string());
        assert!(out.contains("aws_sdk_s3=warn"));
        assert!(out.contains("aws_smithy_runtime=warn"));
    }

    #[test]
    fn keeps_explicit_dependency_directive() {
        let out = with_noisy_dependency_guards("rustaccio=debug,aws_sdk_s3=debug".to_string());
        assert!(out.contains("aws_sdk_s3=debug"));
        assert!(!out.contains("aws_sdk_s3=warn"));
    }

    #[test]
    fn detects_existing_target_directive() {
        assert!(has_target_directive(
            "a=b,aws_smithy_runtime=trace",
            "aws_smithy_runtime"
        ));
        assert!(!has_target_directive(
            "a=b,aws_smithy=trace",
            "aws_smithy_runtime"
        ));
    }
}
