//! Normalized webhook event type shared across all SaaS providers.
//!
//! Each provider sends events in its own JSON shape. The webhook handler
//! decodes the provider-specific body into a [`SaasAuditEvent`] before
//! handing it off to the audit pipeline.
//!
//! The unparsed body is preserved verbatim in [`SaasAuditEvent::raw`] so
//! downstream consumers can mine provider-specific fields without losing
//! information during the normalization step.

use crate::provider::SaasProvider;

/// Provider-agnostic representation of a single SaaS coding-agent audit event.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SaasAuditEvent {
    /// Which SaaS coding-agent provider emitted this event.
    pub provider: SaasProvider,
    /// Provider-assigned event identifier. Must be unique per provider.
    pub event_id: String,
    /// Event timestamp as an RFC 3339 / ISO 8601 string preserved verbatim
    /// from the source payload. Providers vary in resolution and timezone
    /// representation, so the string is stored unmodified.
    pub timestamp: String,
    /// Identity of the human or service account associated with the event.
    /// For Claude.ai and ChatGPT this is typically an email; for Cursor it
    /// is the workspace member id.
    pub actor: String,
    /// Short label describing the action — e.g. tool name, command, or
    /// operation kind. Provider-specific semantics.
    pub action: String,
    /// Original event body, preserved verbatim for downstream inspection.
    pub raw: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> SaasAuditEvent {
        SaasAuditEvent {
            provider: SaasProvider::ClaudeAi,
            event_id: "evt_abc123".into(),
            timestamp: "2026-05-20T08:30:00Z".into(),
            actor: "alice@example.com".into(),
            action: "tool_call:bash".into(),
            raw: serde_json::json!({"event": "tool_call", "tool": "bash"}),
        }
    }

    #[test]
    fn serde_roundtrip_preserves_fields() {
        let original = sample_event();
        let serialized = serde_json::to_string(&original).expect("serializes");
        let deserialized: SaasAuditEvent = serde_json::from_str(&serialized).expect("deserializes");
        assert_eq!(original, deserialized);
    }
}
