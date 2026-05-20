//! Per-provider webhook body parsers.
//!
//! Each SaaS provider sends events in its own JSON shape. The submodules in
//! this folder decode their provider's body into the normalized
//! [`crate::event::SaasAuditEvent`] type. The [`parse`] dispatcher (added
//! once all per-provider modules exist) routes a request to the right one.
//!
//! # Adding a new provider
//!
//! 1. Add a new submodule (e.g. `mod foo;`).
//! 2. Expose a `pub fn parse(body: &[u8]) -> Result<SaasAuditEvent, ParseError>`.
//! 3. Add the arm in [`parse`].

pub mod chatgpt;
pub mod claude_ai;

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
