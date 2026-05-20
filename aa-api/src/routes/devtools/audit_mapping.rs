//! Map a [`SaasAuditEvent`] into the canonical [`AuditEntry`] shape used by
//! the gateway's audit pipeline.
//!
//! AAASM-924 AC: "Handler writes each event to the existing audit-pipeline
//! ingest queue from Epic 6 — do NOT add a new persistence path." The
//! mapping below reuses [`AuditEventType::ToolCallIntercepted`] and the
//! existing [`Lineage::spawned_by_tool`] field as the SaaS-provider tag
//! so downstream consumers can filter without a schema change.
//!
//! [`SaasAuditEvent`]: aa_devtool_saas::event::SaasAuditEvent
//! [`AuditEntry`]: aa_core::AuditEntry

use std::time::{SystemTime, UNIX_EPOCH};

use aa_core::audit::Lineage;
use aa_core::{AgentId, AuditEntry, AuditEventType, SessionId};
use aa_devtool_saas::event::SaasAuditEvent;
use aa_devtool_saas::provider::SaasProvider;

/// Human-readable provider label used both as the synthesized agent-id
/// prefix and as `Lineage::spawned_by_tool`.
fn provider_label(p: &SaasProvider) -> &'static str {
    match p {
        SaasProvider::ClaudeAi => "saas:claude-ai",
        SaasProvider::ChatGpt => "saas:chatgpt",
        SaasProvider::CursorCloud => "saas:cursor",
    }
}

/// Deterministic 16-byte encoding from a label — UTF-8 prefix, zero-padded.
///
/// Stable across processes for the same input; not cryptographically
/// meaningful. Suitable for synthesizing [`AgentId`] / [`SessionId`] for
/// SaaS events that have no native agent/session identity.
fn label_bytes(label: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let src = label.as_bytes();
    let n = src.len().min(16);
    buf[..n].copy_from_slice(&src[..n]);
    buf
}

/// Build an [`AuditEntry`] from a [`SaasAuditEvent`].
///
/// - `event_type` is fixed to [`AuditEventType::ToolCallIntercepted`] —
///   the closest existing variant. SaaS-ness is signalled via lineage.
/// - `agent_id` is derived from the provider label, so all events from
///   the same provider share an agent identifier.
/// - `session_id` is derived from the event id so each external event
///   has a stable per-event session identifier.
/// - `payload` is the full serialized [`SaasAuditEvent`] — no fields
///   are dropped during normalization.
/// - `Lineage::spawned_by_tool` carries the provider label for filtering.
/// - `seq` is `0` and `previous_hash` is zeroed: SaaS webhook events are
///   not part of any agent's intra-session hash chain. Downstream
///   consumers must not treat seq as monotonic for these entries.
pub fn to_audit_entry(event: &SaasAuditEvent) -> AuditEntry {
    let timestamp_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let label = provider_label(&event.provider);
    let agent_id = AgentId::from_bytes(label_bytes(label));
    let session_id = SessionId::from_bytes(label_bytes(&event.event_id));
    let payload = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string());

    let lineage = Lineage {
        spawned_by_tool: Some(label.to_string()),
        ..Default::default()
    };

    AuditEntry::new_with_lineage(
        0,
        timestamp_ns,
        AuditEventType::ToolCallIntercepted,
        agent_id,
        session_id,
        payload,
        [0u8; 32],
        lineage,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_devtool_saas::provider::SaasProvider;

    fn sample(provider: SaasProvider, event_id: &str) -> SaasAuditEvent {
        SaasAuditEvent {
            provider,
            event_id: event_id.into(),
            timestamp: "2026-05-20T08:30:00Z".into(),
            actor: "alice@example.com".into(),
            action: "tool_call:bash".into(),
            raw: serde_json::json!({"x": 1}),
        }
    }

    #[test]
    fn claude_ai_event_maps_to_tool_call_intercepted_with_provider_lineage() {
        let event = sample(SaasProvider::ClaudeAi, "evt_1");
        let entry = to_audit_entry(&event);
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        assert_eq!(entry.spawned_by_tool(), Some("saas:claude-ai"));
        // agent_id is derived from the provider label — same label, same bytes.
        assert_eq!(entry.agent_id(), AgentId::from_bytes(label_bytes("saas:claude-ai")));
    }

    #[test]
    fn payload_preserves_full_serialized_event() {
        let event = sample(SaasProvider::ChatGpt, "evt_42");
        let entry = to_audit_entry(&event);
        let round: SaasAuditEvent = serde_json::from_str(entry.payload()).expect("roundtrips");
        assert_eq!(round, event);
    }

    #[test]
    fn different_providers_get_different_agent_ids() {
        let claude = to_audit_entry(&sample(SaasProvider::ClaudeAi, "e"));
        let chatgpt = to_audit_entry(&sample(SaasProvider::ChatGpt, "e"));
        let cursor = to_audit_entry(&sample(SaasProvider::CursorCloud, "e"));
        assert_ne!(claude.agent_id(), chatgpt.agent_id());
        assert_ne!(chatgpt.agent_id(), cursor.agent_id());
        assert_ne!(claude.agent_id(), cursor.agent_id());
    }

    #[test]
    fn same_provider_same_event_id_produces_same_session_id() {
        let a = to_audit_entry(&sample(SaasProvider::CursorCloud, "evt_stable"));
        let b = to_audit_entry(&sample(SaasProvider::CursorCloud, "evt_stable"));
        assert_eq!(a.session_id(), b.session_id());
    }
}
