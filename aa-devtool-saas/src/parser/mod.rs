//! Per-provider webhook body parsers.
//!
//! Each SaaS provider sends events in its own JSON shape. The submodules in
//! this folder decode their provider's body into the normalized
//! [`crate::event::SaasAuditEvent`] type. The [`parse`] dispatcher routes a
//! request to the right provider module based on
//! [`crate::provider::SaasProvider`].
//!
//! # Adding a new provider
//!
//! 1. Add a new submodule (e.g. `mod foo;`).
//! 2. Expose a `pub fn parse(body: &[u8]) -> Result<SaasAuditEvent, ParseError>`.
//! 3. Add the arm in [`parse`].

pub mod chatgpt;
pub mod claude_ai;
pub mod cursor;

use crate::event::SaasAuditEvent;
use crate::provider::SaasProvider;

/// Error returned when a provider-specific body fails to decode.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// The body was not valid JSON.
    ///
    /// The caller should return HTTP 400.
    #[error("malformed JSON body: {0}")]
    MalformedJson(String),

    /// The body parsed as JSON but a required provider-specific field was
    /// missing or had the wrong type.
    #[error("missing or invalid field: {0}")]
    MissingField(&'static str),
}

/// Decode a webhook body for the given provider into [`SaasAuditEvent`].
///
/// Routes to the provider's submodule. Each provider owns its own field
/// names and validation logic — schemes are intentionally not shared.
pub fn parse(provider: &SaasProvider, body: &[u8]) -> Result<SaasAuditEvent, ParseError> {
    match provider {
        SaasProvider::ClaudeAi => claude_ai::parse(body),
        SaasProvider::ChatGpt => chatgpt::parse(body),
        SaasProvider::CursorCloud => cursor::parse(body),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_routes_claude_ai_to_claude_parser() {
        let body = br#"{
            "event_id": "evt",
            "timestamp": "t",
            "actor": {"email": "a@b"},
            "action": {"tool": "bash"}
        }"#;
        let evt = parse(&SaasProvider::ClaudeAi, body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::ClaudeAi);
    }

    #[test]
    fn dispatcher_routes_chatgpt_to_chatgpt_parser() {
        let body = br#"{
            "id": "evt",
            "created": "t",
            "user": {"email": "a@b"},
            "action": "x"
        }"#;
        let evt = parse(&SaasProvider::ChatGpt, body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::ChatGpt);
    }

    #[test]
    fn dispatcher_routes_cursor_cloud_to_cursor_parser() {
        let body = br#"{
            "event_id": "evt",
            "ts": "t",
            "user": "a@b",
            "op": "x"
        }"#;
        let evt = parse(&SaasProvider::CursorCloud, body).expect("parses");
        assert_eq!(evt.provider, SaasProvider::CursorCloud);
    }
}
