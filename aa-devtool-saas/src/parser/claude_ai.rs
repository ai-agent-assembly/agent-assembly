//! Claude.ai webhook body parser.
//!
//! Expected JSON shape (Workspaces audit-event API, abridged):
//!
//! ```json
//! {
//!   "event_id": "evt_01H...",
//!   "timestamp": "2026-05-20T08:30:00Z",
//!   "actor": { "email": "alice@example.com" },
//!   "action": { "tool": "bash" }
//! }
//! ```

use crate::event::SaasAuditEvent;
use crate::provider::SaasProvider;

use super::ParseError;

/// Decode a Claude.ai webhook body into [`SaasAuditEvent`].
pub fn parse(body: &[u8]) -> Result<SaasAuditEvent, ParseError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| ParseError::MalformedJson(e.to_string()))?;

    let event_id = raw
        .get("event_id")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("event_id"))?
        .to_owned();
    let timestamp = raw
        .get("timestamp")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("timestamp"))?
        .to_owned();
    let actor = raw
        .get("actor")
        .and_then(|a| a.get("email"))
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("actor.email"))?
        .to_owned();
    let action = raw
        .get("action")
        .and_then(|a| a.get("tool"))
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("action.tool"))?
        .to_owned();

    Ok(SaasAuditEvent {
        provider: SaasProvider::ClaudeAi,
        event_id,
        timestamp,
        actor,
        action,
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_parses_all_fields() {
        let body = br#"{
            "event_id": "evt_01H",
            "timestamp": "2026-05-20T08:30:00Z",
            "actor": {"email": "alice@example.com"},
            "action": {"tool": "bash"}
        }"#;
        let evt = parse(body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::ClaudeAi);
        assert_eq!(evt.event_id, "evt_01H");
        assert_eq!(evt.timestamp, "2026-05-20T08:30:00Z");
        assert_eq!(evt.actor, "alice@example.com");
        assert_eq!(evt.action, "bash");
    }

    #[test]
    fn malformed_json_returns_error() {
        let err = parse(b"not json").expect_err("rejects non-json");
        assert!(matches!(err, ParseError::MalformedJson(_)));
    }

    #[test]
    fn missing_event_id_returns_missing_field() {
        let body = br#"{"timestamp": "t", "actor": {"email": "a"}, "action": {"tool": "b"}}"#;
        let err = parse(body).expect_err("requires event_id");
        assert!(matches!(err, ParseError::MissingField("event_id")));
    }

    #[test]
    fn missing_actor_email_returns_missing_field() {
        let body = br#"{"event_id": "e", "timestamp": "t", "actor": {}, "action": {"tool": "b"}}"#;
        let err = parse(body).expect_err("requires actor.email");
        assert!(matches!(err, ParseError::MissingField("actor.email")));
    }
}
