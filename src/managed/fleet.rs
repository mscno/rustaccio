//! Fleet heartbeat and placement tracking for managed data planes.
//!
//! The node heartbeats once at startup and then every 30 seconds. When the
//! control plane reports a newer `config_revision` the node fetches and
//! stores the fleet config. With `RUSTACCIO_REQUIRE_PLACEMENT=true` startup
//! fails unless the control plane has placed this node (a config content is
//! known for it); placement is a startup guardrail, not a per-request gate.

use super::ManagedState;
use super::client::HeartbeatRequest;
use crate::error::RegistryError;
use axum::http::StatusCode;
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

pub struct FleetState {
    pub config_revision: AtomicI64,
    pub config_content: RwLock<Option<Value>>,
    pub last_heartbeat_ok: AtomicBool,
}

impl Default for FleetState {
    fn default() -> Self {
        Self::new()
    }
}

impl FleetState {
    pub fn new() -> Self {
        Self {
            config_revision: AtomicI64::new(0),
            config_content: RwLock::new(None),
            last_heartbeat_ok: AtomicBool::new(false),
        }
    }
}

impl ManagedState {
    /// One heartbeat plus a config fetch when the control plane advertises a
    /// newer revision. Returns whether the node is placed.
    async fn heartbeat_once(&self) -> Result<bool, RegistryError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let response = self
            .client
            .heartbeat(
                &HeartbeatRequest {
                    identity: &self.config.identity,
                    version: env!("CARGO_PKG_VERSION"),
                    capabilities: &self.config.capabilities,
                },
                &request_id,
            )
            .await
            .map_err(|err| err.into_unavailable("fleet heartbeat"))?;
        self.fleet.last_heartbeat_ok.store(true, Ordering::Relaxed);

        let current = self.fleet.config_revision.load(Ordering::Relaxed);
        if response.config_revision > current {
            let config = self
                .client
                .fleet_config(current, &request_id)
                .await
                .map_err(|err| err.into_unavailable("fleet config"))?;
            if config.revision > 0 {
                let mut content = self.fleet.config_content.write().await;
                *content = config.content.clone();
                self.fleet
                    .config_revision
                    .store(config.revision, Ordering::Relaxed);
                debug!(
                    revision = config.revision,
                    has_content = config.content.is_some(),
                    "stored fleet config"
                );
            }
        }
        Ok(self.fleet.config_content.read().await.is_some())
    }

    /// Startup handshake: heartbeat now, enforce placement when required, then
    /// spawn the 30s heartbeat loop.
    pub async fn start_fleet(self: &Arc<Self>) -> Result<(), RegistryError> {
        let placed = match self.heartbeat_once().await {
            Ok(placed) => placed,
            Err(err) => {
                if self.config.require_placement {
                    return Err(err);
                }
                warn!(error = ?err, "initial fleet heartbeat failed; retrying in background");
                false
            }
        };
        if self.config.require_placement && !placed {
            return Err(RegistryError::http(
                StatusCode::SERVICE_UNAVAILABLE,
                "RUSTACCIO_REQUIRE_PLACEMENT=true but the control plane has not placed this node",
            ));
        }

        let state = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(error) = state.heartbeat_once().await {
                    state
                        .fleet
                        .last_heartbeat_ok
                        .store(false, Ordering::Relaxed);
                    warn!(error = ?error, "fleet heartbeat failed");
                }
            }
        });
        Ok(())
    }
}
