//! Best-effort usage/operational event reporting to the control plane.
//!
//! Events are buffered on a bounded channel with a drop-on-full policy:
//! reporting never blocks or fails an npm operation. A background worker
//! batches the buffer into `POST /v1/events` calls; delivery failures are
//! logged and dropped (the control plane deduplicates by `event_id`, and
//! events are only generated once per completed transfer observation).

use super::client::{ControlPlaneClient, ManagedEvent};
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub const EVENT_DOWNLOAD: &str = "download";
pub const EVENT_PUBLISH: &str = "publish";

const FLUSH_BATCH: usize = 50;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct EventReporter {
    tx: mpsc::Sender<ManagedEvent>,
}

impl EventReporter {
    pub fn new(client: Arc<ControlPlaneClient>, capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity.max(16));
        tokio::spawn(event_worker(client, rx));
        Self { tx }
    }

    /// Queue one event; drops (with a warning) when the buffer is full.
    pub fn report(&self, event: ManagedEvent) {
        if let Err(err) = self.tx.try_send(event) {
            warn!(error = %err, "managed event buffer full; dropping event");
        }
    }

    pub fn event(
        kind: &str,
        tenant_id: Option<&str>,
        package: &str,
        version: Option<&str>,
        bytes: u64,
        credential_id: Option<&str>,
    ) -> ManagedEvent {
        ManagedEvent {
            event_id: uuid::Uuid::new_v4().to_string(),
            kind: kind.to_string(),
            tenant_id: tenant_id.unwrap_or_default().to_string(),
            package: package.to_string(),
            version: version.map(ToOwned::to_owned),
            credential_id: credential_id.map(ToOwned::to_owned),
            bytes,
            occurred_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

async fn event_worker(client: Arc<ControlPlaneClient>, mut rx: mpsc::Receiver<ManagedEvent>) {
    let mut batch = Vec::with_capacity(FLUSH_BATCH);
    let mut interval = tokio::time::interval(FLUSH_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let ticked = tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(event) => {
                        batch.push(event);
                        false
                    }
                    None => break,
                }
            }
            _ = interval.tick() => true
        };
        while batch.len() < FLUSH_BATCH {
            match rx.try_recv() {
                Ok(event) => batch.push(event),
                Err(_) => break,
            }
        }
        if batch.is_empty() || (!ticked && batch.len() < FLUSH_BATCH) {
            continue;
        }
        let accepted = batch.len();
        if let Err(error) = client.send_events(&batch).await {
            warn!(
                accepted,
                error = ?error,
                "failed to deliver managed events; dropping batch"
            );
        } else {
            debug!(accepted, "delivered managed events");
        }
        batch.clear();
    }
}
