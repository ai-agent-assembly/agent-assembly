//! Cursor cloud webhook body parser.
//!
//! Expected JSON shape (audit-webhook envelope, abridged):
//!
//! ```json
//! {
//!   "event_id": "cur_evt_01H...",
//!   "ts": "2026-05-20T08:30:00Z",
//!   "user": "carol@example.com",
//!   "op": "edit.apply"
//! }
//! ```

use crate::event::SaasAuditEvent;
use crate::provider::SaasProvider;

use super::ParseError;

/// Decode a Cursor cloud webhook body into [`SaasAuditEvent`].
pub fn parse(body: &[u8]) -> Result<SaasAuditEvent, ParseError> {
    let raw: serde_json::Value = serde_json::from_slice(body).map_err(|e| ParseError::MalformedJson(e.to_string()))?;

    let event_id = raw
        .get("event_id")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("event_id"))?
        .to_owned();
    let timestamp = raw
        .get("ts")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("ts"))?
        .to_owned();
    let actor = raw
        .get("user")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("user"))?
        .to_owned();
    let action = raw
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or(ParseError::MissingField("op"))?
        .to_owned();

    Ok(SaasAuditEvent {
        provider: SaasProvider::CursorCloud,
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
            "event_id": "cur_evt_01H",
            "ts": "2026-05-20T08:30:00Z",
            "user": "carol@example.com",
            "op": "edit.apply"
        }"#;
        let evt = parse(body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::CursorCloud);
        assert_eq!(evt.event_id, "cur_evt_01H");
        assert_eq!(evt.timestamp, "2026-05-20T08:30:00Z");
        assert_eq!(evt.actor, "carol@example.com");
        assert_eq!(evt.action, "edit.apply");
    }

    #[test]
    fn malformed_json_returns_error() {
        let err = parse(b"{not json").expect_err("rejects bad json");
        assert!(matches!(err, ParseError::MalformedJson(_)));
    }

    #[test]
    fn missing_user_returns_missing_field() {
        let body = br#"{"event_id": "e", "ts": "t", "op": "o"}"#;
        let err = parse(body).expect_err("requires user");
        assert!(matches!(err, ParseError::MissingField("user")));
    }
}
