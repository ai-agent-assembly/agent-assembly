//! Anomaly response action executor.
//!
//! Receives [`AnomalyEvent`](super::types::AnomalyEvent) values from the
//! detector and logs the response action via `tracing`. When the event bus
//! (AAASM-141) is implemented, alerts will be published as
//! `AlertTriggered`(proto::event::AlertTriggered) messages.

use super::types::{AnomalyEvent, AnomalyResponse};

/// Executes response actions for detected anomalies.
///
/// Currently emits structured `tracing` logs. Future versions will publish
/// `AlertTriggered` proto messages on the event bus and trigger registry
/// actions (suspend, block, quarantine).
pub struct AnomalyResponder;

impl AnomalyResponder {
    /// Execute the response action for a detected anomaly.
    ///
    /// Logs the anomaly with structured fields so it can be picked up by
    /// observability tooling. Returns the response action for the caller
    /// to enforce.
    pub fn respond(event: &AnomalyEvent) -> AnomalyResponse {
        match event.response {
            AnomalyResponse::Pause => {
                tracing::warn!(
                    anomaly_type = ?event.anomaly_type,
                    response = "pause",
                    agent_id = ?event.agent_id.as_bytes(),
                    description = %event.description,
                    "Anomaly detected: auto-pausing agent"
                );
            }
            AnomalyResponse::Block => {
                tracing::warn!(
                    anomaly_type = ?event.anomaly_type,
                    response = "block",
                    agent_id = ?event.agent_id.as_bytes(),
                    description = %event.description,
                    "Anomaly detected: blocking action"
                );
            }
            AnomalyResponse::Alert => {
                tracing::warn!(
                    anomaly_type = ?event.anomaly_type,
                    response = "alert",
                    agent_id = ?event.agent_id.as_bytes(),
                    description = %event.description,
                    "Anomaly detected: alert emitted"
                );
            }
            AnomalyResponse::Quarantine => {
                tracing::warn!(
                    anomaly_type = ?event.anomaly_type,
                    response = "quarantine",
                    agent_id = ?event.agent_id.as_bytes(),
                    description = %event.description,
                    "Anomaly detected: quarantining agent"
                );
            }
        }
        // TODO(AAASM-141): Publish AlertTriggered proto message on event bus.
        // TODO(AAASM-137): Trigger registry actions (suspend/block/quarantine).
        event.response
    }
}
