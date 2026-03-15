use crate::config::{Config, TarballStorageBackend};
use reqwest::Url;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tracing::{info, warn};

const NPM_REGISTRY_URL: &str = "https://registry.npmjs.org";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectivityTarget {
    label: &'static str,
    url: String,
}

pub async fn run_if_enabled(config: &Config) {
    if !startup_connectivity_check_enabled() {
        return;
    }

    let timeout = Duration::from_secs(startup_connectivity_check_timeout_secs());
    let targets = startup_connectivity_targets(config);

    info!(
        timeout_ms = timeout.as_millis() as u64,
        target_count = targets.len(),
        "running startup connectivity checks"
    );

    for target in targets {
        probe_target(&target, timeout).await;
    }
}

fn startup_connectivity_check_enabled() -> bool {
    std::env::var("RUSTACCIO_STARTUP_CONNECTIVITY_CHECK")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(false)
}

fn startup_connectivity_check_timeout_secs() -> u64 {
    std::env::var("RUSTACCIO_UPSTREAM_CONNECT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(3)
        .clamp(1, 60)
}

fn startup_connectivity_targets(config: &Config) -> Vec<ConnectivityTarget> {
    let mut targets = vec![ConnectivityTarget {
        label: "npm_registry",
        url: NPM_REGISTRY_URL.to_string(),
    }];

    if config.tarball_storage.backend == TarballStorageBackend::S3
        && let Some(endpoint) = config
            .tarball_storage
            .s3
            .as_ref()
            .and_then(|s3| s3.endpoint.as_ref())
            .map(|endpoint| endpoint.trim())
            .filter(|endpoint| !endpoint.is_empty())
    {
        targets.push(ConnectivityTarget {
            label: "tarball_s3_endpoint",
            url: endpoint.to_string(),
        });
    }

    targets
}

fn parse_target_endpoint(url: &str) -> Result<(String, u16), String> {
    let parsed = Url::parse(url).map_err(|err| format!("invalid url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "missing host".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "missing port".to_string())?;
    Ok((host, port))
}

async fn probe_target(target: &ConnectivityTarget, timeout_duration: Duration) {
    let (host, port) = match parse_target_endpoint(&target.url) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            warn!(
                target = target.label,
                url = target.url.as_str(),
                error = err.as_str(),
                "startup connectivity check skipped invalid target"
            );
            return;
        }
    };

    let resolved = match lookup_host((host.as_str(), port)).await {
        Ok(resolved) => resolved.collect::<Vec<_>>(),
        Err(err) => {
            warn!(
                target = target.label,
                url = target.url.as_str(),
                host = host.as_str(),
                port,
                error = %err,
                "startup connectivity check failed to resolve host"
            );
            return;
        }
    };

    let (ipv4_addrs, ipv6_addrs) = partition_addresses(resolved);
    probe_family(target, &host, port, "ipv4", &ipv4_addrs, timeout_duration).await;
    probe_family(target, &host, port, "ipv6", &ipv6_addrs, timeout_duration).await;
}

fn partition_addresses(addrs: Vec<SocketAddr>) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();

    for addr in addrs {
        if addr.is_ipv4() {
            ipv4.insert(addr);
        } else {
            ipv6.insert(addr);
        }
    }

    (ipv4.into_iter().collect(), ipv6.into_iter().collect())
}

async fn probe_family(
    target: &ConnectivityTarget,
    host: &str,
    port: u16,
    family: &'static str,
    addrs: &[SocketAddr],
    timeout_duration: Duration,
) {
    if addrs.is_empty() {
        warn!(
            target = target.label,
            url = target.url.as_str(),
            host,
            port,
            family,
            "startup connectivity check resolved no addresses for family"
        );
        return;
    }

    let mut last_error = None;
    for addr in addrs {
        let started = Instant::now();
        match timeout(timeout_duration, TcpStream::connect(*addr)).await {
            Ok(Ok(stream)) => {
                drop(stream);
                info!(
                    target = target.label,
                    url = target.url.as_str(),
                    host,
                    port,
                    family,
                    addr = %addr,
                    latency_ms = started.elapsed().as_millis() as u64,
                    resolved_addr_count = addrs.len(),
                    "startup connectivity check succeeded"
                );
                return;
            }
            Ok(Err(err)) => {
                last_error = Some(format!("{addr}: {err}"));
            }
            Err(_) => {
                last_error = Some(format!(
                    "{addr}: timeout after {}ms",
                    timeout_duration.as_millis()
                ));
            }
        }
    }

    warn!(
        target = target.label,
        url = target.url.as_str(),
        host,
        port,
        family,
        resolved_addrs = ?addrs,
        error = last_error.unwrap_or_else(|| "unknown connect failure".to_string()),
        "startup connectivity check failed"
    );
}

#[cfg(test)]
mod tests {
    use super::{parse_target_endpoint, partition_addresses, startup_connectivity_targets};
    use crate::config::{
        Config, TarballStorageBackend, TarballStorageConfig, default_s3_storage_config_for_examples,
    };
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn startup_targets_include_registry_and_s3_endpoint() {
        let mut cfg = Config::defaults_for_examples();
        let mut s3 = default_s3_storage_config_for_examples();
        s3.endpoint = Some("https://t3.storageapi.dev".to_string());
        cfg.tarball_storage = TarballStorageConfig {
            backend: TarballStorageBackend::S3,
            s3: Some(s3),
        };

        let targets = startup_connectivity_targets(&cfg);
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].url, "https://registry.npmjs.org");
        assert_eq!(targets[1].url, "https://t3.storageapi.dev");
    }

    #[test]
    fn startup_targets_skip_s3_when_backend_is_local() {
        let cfg = Config::defaults_for_examples();
        let targets = startup_connectivity_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].url, "https://registry.npmjs.org");
    }

    #[test]
    fn parse_target_endpoint_uses_known_default_port() {
        assert_eq!(
            parse_target_endpoint("https://registry.npmjs.org").expect("parse"),
            ("registry.npmjs.org".to_string(), 443)
        );
    }

    #[test]
    fn parse_target_endpoint_preserves_explicit_port() {
        assert_eq!(
            parse_target_endpoint("https://example.com:8443").expect("parse"),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn partition_addresses_groups_by_family() {
        let addrs = vec![
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443)),
        ];

        let (ipv4, ipv6) = partition_addresses(addrs);
        assert_eq!(ipv4.len(), 1);
        assert_eq!(ipv6.len(), 1);
        assert!(ipv4[0].is_ipv4());
        assert!(ipv6[0].is_ipv6());
    }
}
