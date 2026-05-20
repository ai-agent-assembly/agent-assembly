//! ChatGPT (OpenAI Enterprise compliance API) webhook body parser.
//!
//! Expected JSON shape (compliance event, abridged):
//!
//! ```json
//! {
//!   "id": "evt-01H...",
//!   "created": "2026-05-20T08:30:00Z",
//!   "user": { "email": "bob@example.com" },
//!   "action": "chat.completion"
//! }
//! ```

use crate::event::SaasAuditEvent;
use crate::provider::SaasProvider;

use super::ParseError;

/// Decode a ChatGPT webhook body into [`SaasAuditEvent`].
pub fn parse(body: &[u8]) -> Result<SaasAuditEvent, ParseError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| ParseError::MalformedJson(e.to_string()))?;

    let event_id = raw
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("id"))?
        .to_owned();
    let timestamp = raw
        .get("created")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("created"))?
        .to_owned();
    let actor = raw
        .get("user")
        .and_then(|u| u.get("email"))
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("user.email"))?
        .to_owned();
    let action = raw
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("action"))?
        .to_owned();

    Ok(SaasAuditEvent {
        provider: SaasProvider::ChatGpt,
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
            "id": "evt-01H",
            "created": "2026-05-20T08:30:00Z",
            "user": {"email": "bob@example.com"},
            "action": "chat.completion"
        }"#;
        let evt = parse(body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::ChatGpt);
        assert_eq!(evt.event_id, "evt-01H");
        assert_eq!(evt.timestamp, "2026-05-20T08:30:00Z");
        assert_eq!(evt.actor, "bob@example.com");
        assert_eq!(evt.action, "chat.completion");
    }

    #[test]
    fn malformed_json_returns_error() {
        let err = parse(b"not json").expect_err("rejects non-json");
        assert!(matches!(err, ParseError::MalformedJson(_)));
    }

    #[test]
    fn missing_action_returns_missing_field() {
        let body = br#"{"id": "e", "created": "t", "user": {"email": "a"}}"#;
        let err = parse(body).expect_err("requires action");
        assert!(matches!(err, ParseError::MissingField("action")));
    }
}
