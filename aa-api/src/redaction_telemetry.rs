//! Cross-process redaction telemetry ingest (AAASM-5871).
//!
//! `aa-proxy` redacts outbound credentials locally, before a payload leaves the
//! machine, and it runs in a different OS process from `aa-api`. The dashboard's
//! secret-alert path ([`aa_gateway::alerts::SecretAlert`] →
//! `EventBroadcast::secret_tx` → `spawn_secret_alert_capture` → alert store →
//! `GET /api/v1/alerts`) is an in-process `tokio::broadcast` channel the proxy
//! cannot reach directly. This module is the network hop that closes that gap:
//! a private, loopback-only gRPC service that accepts a proxy's pre-transmission
//! REDACT event and republishes it onto the existing in-process channel, so the
//! event flows through the *same* capture/store/API path a co-located gateway
//! would use — no new dashboard code, no demo shortcut.
//!
//! Security invariant: this surface carries only non-sensitive evidence
//! (finding kinds, a count, identity tags, destination host). No byte of any
//! matched secret ever crosses it, and the mapping here never reconstructs one.
//!
//! Related: AAASM-5848 (documented the gap), AAASM-1545 (the alert path reused).

use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use aa_core::AgentId;
use aa_gateway::alerts::SecretAlert;
use aa_proto::assembly::telemetry::v1::redaction_telemetry_service_server::{
    RedactionTelemetryService, RedactionTelemetryServiceServer,
};
use aa_proto::assembly::telemetry::v1::{ReportRedactionRequest, ReportRedactionResponse};
use aa_security::CredentialKind;

/// Sentinel identity for redaction events the proxy reports without an
/// attributed agent. All-zero UUID bytes: a well-known "unattributed proxy
/// path" marker, never a real registered agent. Using it keeps the dashboard
/// honest — the event is shown under a recognisably-synthetic id rather than a
/// fabricated one that could be mistaken for a real agent.
const UNATTRIBUTED_PROXY_AGENT: AgentId = AgentId::from_bytes([0u8; 16]);

/// gRPC ingest for [`aa_proto::assembly::telemetry::v1::RedactionTelemetryService`].
///
/// Holds a clone of the API layer's secret-alert broadcast sender and an
/// idempotency set keyed on `event_id`.
pub struct RedactionTelemetryIngest {
    /// The same sender `EventBroadcast::secret_sender()` hands out; the
    /// in-process capture task is already subscribed to its receiver.
    secret_tx: broadcast::Sender<SecretAlert>,
    /// Event ids already recorded, for idempotent replay handling. In-process
    /// and single-node, matching the alert store's own durability posture.
    seen: Arc<Mutex<HashSet<String>>>,
}

impl RedactionTelemetryIngest {
    /// Construct an ingest that republishes onto `secret_tx`.
    pub fn new(secret_tx: broadcast::Sender<SecretAlert>) -> Self {
        Self {
            secret_tx,
            seen: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Wrap this ingest in its generated tonic server.
    pub fn into_server(self) -> RedactionTelemetryServiceServer<Self> {
        RedactionTelemetryServiceServer::new(self)
    }
}

/// Reverse of [`CredentialKind::as_str`]: map a stable wire tag back to its
/// enum. An unknown tag — a newer proxy reporting a kind this build predates —
/// maps to [`CredentialKind::Custom`] rather than being dropped, so the alert
/// still surfaces (with a generic kind) instead of vanishing.
fn kind_from_wire(tag: &str) -> CredentialKind {
    CredentialKind::ALL
        .iter()
        .find(|k| k.as_str() == tag)
        .cloned()
        .unwrap_or(CredentialKind::Custom)
}

/// Resolve the wire `agent_id` bytes to an [`AgentId`]. Exactly 16 bytes is a
/// real attributed identity; anything else (empty = unattributed proxy path, or
/// a malformed length) resolves to the sentinel rather than erroring — the
/// event is still worth surfacing without an authenticated identity.
fn resolve_agent_id(bytes: &[u8]) -> AgentId {
    match <[u8; 16]>::try_from(bytes) {
        Ok(raw) => AgentId::from_bytes(raw),
        Err(_) => UNATTRIBUTED_PROXY_AGENT,
    }
}

#[tonic::async_trait]
impl RedactionTelemetryService for RedactionTelemetryIngest {
    async fn report_redaction(
        &self,
        request: Request<ReportRedactionRequest>,
    ) -> Result<Response<ReportRedactionResponse>, Status> {
        let event = request
            .into_inner()
            .event
            .ok_or_else(|| Status::invalid_argument("missing redaction event"))?;

        if event.event_id.is_empty() {
            return Err(Status::invalid_argument(
                "event_id is required as the idempotency key",
            ));
        }
        if event.finding_kinds.is_empty() {
            return Err(Status::invalid_argument(
                "finding_kinds must be non-empty for a redaction event",
            ));
        }

        // Idempotency: record at most one alert per distinct event_id. A retry
        // after an ambiguous failure is acknowledged without double-counting.
        {
            let mut seen = self.seen.lock().await;
            if !seen.insert(event.event_id.clone()) {
                return Ok(Response::new(ReportRedactionResponse { recorded: false }));
            }
        }

        let agent_id = resolve_agent_id(&event.agent_id);
        let team_id = if event.team_id.is_empty() {
            None
        } else {
            Some(event.team_id.clone())
        };
        let kinds: Vec<CredentialKind> = event.finding_kinds.iter().map(|t| kind_from_wire(t)).collect();
        // Prefer the reported count; fall back to the distinct-kind count if a
        // caller left it zero, so the alert never claims zero findings.
        let finding_count = if event.finding_count == 0 {
            kinds.len()
        } else {
            event.finding_count as usize
        };

        // Non-sensitive operational record of the cross-process hop. Carries the
        // routing/timing evidence (destination host, occurred-at) that the
        // current StoredAlert schema does not surface, so it is observable
        // without inventing a dashboard column. No secret value is present.
        tracing::info!(
            target: "aa_api::redaction_telemetry",
            event_id = %event.event_id,
            destination_host = %event.destination_host,
            occurred_at_ms = event.occurred_at_ms,
            finding_count,
            kinds = ?kinds.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
            "recording cross-process proxy redaction event into the dashboard alert path"
        );

        let alert = SecretAlert {
            agent_id,
            team_id,
            kinds,
            finding_count,
        };

        // Republish onto the same in-process channel the gateway path uses. The
        // secret-alert capture task (spawned in `run_server_with_spa`) records
        // it into the alert store, surfacing it via `GET /api/v1/alerts`. A send
        // error means no receiver is currently subscribed (e.g. mid-shutdown);
        // the event was still accepted and deduped, so the client is not failed.
        if self.secret_tx.send(alert).is_err() {
            tracing::warn!(
                target: "aa_api::redaction_telemetry",
                event_id = %event.event_id,
                "no secret-alert subscriber; redaction event accepted but not captured"
            );
        }

        Ok(Response::new(ReportRedactionResponse { recorded: true }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_from_wire_round_trips_known_kinds() {
        for kind in CredentialKind::ALL {
            assert_eq!(&kind_from_wire(kind.as_str()), kind);
        }
    }

    #[test]
    fn kind_from_wire_unknown_tag_falls_back_to_custom() {
        assert_eq!(kind_from_wire("NotARealKind"), CredentialKind::Custom);
    }

    #[test]
    fn resolve_agent_id_uses_sentinel_when_absent() {
        assert_eq!(resolve_agent_id(&[]), UNATTRIBUTED_PROXY_AGENT);
        assert_eq!(resolve_agent_id(&[1, 2, 3]), UNATTRIBUTED_PROXY_AGENT);
    }

    #[test]
    fn resolve_agent_id_reads_full_uuid_bytes() {
        let raw = [7u8; 16];
        assert_eq!(resolve_agent_id(&raw), AgentId::from_bytes(raw));
    }
}
