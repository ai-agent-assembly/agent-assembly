//! Optional gRPC client for reporting pre-transmission redaction events to
//! `aa-api` (AAASM-5871).
//!
//! `aa-proxy` redacts outbound credentials locally and runs in a separate OS
//! process from `aa-api`, whose dashboard alert path is an in-process broadcast
//! channel. When configured with a telemetry endpoint, the proxy uses this
//! client to report each `ForwardedRedacted` decision so the real Scrub/Alerts
//! dashboard can observe it.
//!
//! Best-effort by design: the client is built over a **lazy** channel so an
//! unreachable ingest never blocks proxy startup, and a failed `report_redaction`
//! never changes the enforcement outcome the proxy already applied. Only
//! non-sensitive evidence crosses the wire — never a matched secret value.

use std::time::{SystemTime, UNIX_EPOCH};

use aa_proto::assembly::telemetry::v1::redaction_telemetry_service_client::RedactionTelemetryServiceClient;
use aa_proto::assembly::telemetry::v1::{RedactionEvent, ReportRedactionRequest, ReportRedactionResponse};
use tonic::transport::Channel;

/// gRPC client wrapper for `aa-api`'s `RedactionTelemetryService`.
pub struct RedactionTelemetryClient {
    client: RedactionTelemetryServiceClient<Channel>,
}

impl RedactionTelemetryClient {
    /// Build a client over a **lazy** channel to `endpoint` without connecting
    /// eagerly. Returns `None` if `endpoint` is not a valid URI.
    ///
    /// Lazy on purpose: redaction telemetry is best-effort observability, so a
    /// down ingest must not fail proxy startup — the channel connects on first
    /// use and recovers automatically once the ingest comes up.
    pub fn connect_lazy_owned(endpoint: &str) -> Option<Self> {
        let channel = Channel::from_shared(endpoint.to_string()).ok()?.connect_lazy();
        Some(Self {
            client: RedactionTelemetryServiceClient::new(channel),
        })
    }

    /// Report one redaction event. Errors are the caller's to swallow — this
    /// path is best-effort and must never propagate into enforcement.
    pub async fn report_redaction(&mut self, event: RedactionEvent) -> Result<ReportRedactionResponse, tonic::Status> {
        let resp = self
            .client
            .report_redaction(ReportRedactionRequest { event: Some(event) })
            .await?;
        Ok(resp.into_inner())
    }
}

/// Build a [`RedactionEvent`] with a freshly generated `event_id` (idempotency
/// key) and an `occurred_at_ms` stamped at call time.
///
/// `agent_id` is left empty: the proxy redaction path has no attributed agent
/// identity at the enforcement point today (identity plumbing is a documented
/// follow-up), so the ingest records the event under a sentinel rather than a
/// fabricated identity. `finding_kinds` carries stable `CredentialKind::as_str`
/// tags only — never a matched value.
pub fn new_redaction_event(
    destination_host: String,
    team_id: Option<String>,
    finding_kinds: Vec<String>,
    finding_count: u32,
) -> RedactionEvent {
    let occurred_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    RedactionEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        occurred_at_ms,
        agent_id: Vec::new(),
        team_id: team_id.unwrap_or_default(),
        destination_host,
        finding_kinds,
        finding_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_lazy_owned_accepts_valid_uri() {
        assert!(RedactionTelemetryClient::connect_lazy_owned("http://127.0.0.1:50052").is_some());
    }

    #[test]
    fn connect_lazy_owned_rejects_invalid_uri() {
        assert!(RedactionTelemetryClient::connect_lazy_owned("").is_none());
    }

    #[test]
    fn new_redaction_event_generates_unique_ids_and_no_agent() {
        let a = new_redaction_event(
            "api.anthropic.com".to_string(),
            None,
            vec!["AwsAccessKey".to_string()],
            1,
        );
        let b = new_redaction_event(
            "api.anthropic.com".to_string(),
            None,
            vec!["AwsAccessKey".to_string()],
            1,
        );
        assert_ne!(a.event_id, b.event_id, "event_id must be unique per event");
        assert!(a.agent_id.is_empty(), "proxy path is unattributed");
        assert_eq!(a.finding_kinds, vec!["AwsAccessKey".to_string()]);
        assert_eq!(a.finding_count, 1);
    }
}
