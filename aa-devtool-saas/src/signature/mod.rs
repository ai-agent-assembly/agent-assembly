//! Per-provider HMAC-SHA256 webhook signature verification.
//!
//! AAASM-924 requires that each provider's verifier live in its own module
//! and that no scheme be shared across providers. The [`verify`] function
//! here is a thin dispatcher; the actual byte-level work happens in
//! [`claude_ai`], [`chatgpt`], and [`cursor`].
//!
//! # Security
//!
//! All comparisons are constant-time via [`hmac::Mac::verify_slice`], which
//! is built on `subtle::ConstantTimeEq`. Never replace these with `==`
//! comparisons — timing-side-channel attacks on HMAC-based webhook
//! signatures are a known threat.

pub mod chatgpt;
pub mod claude_ai;
pub mod cursor;

use crate::provider::SaasProvider;

/// Error returned when webhook signature verification fails.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    /// The expected signature header was absent from the request.
    #[error("missing signature header")]
    MissingHeader,

    /// The signature was present but did not match the computed HMAC.
    ///
    /// The caller should return HTTP 401 and not process the event body.
    #[error("invalid signature")]
    InvalidSignature,
}

/// Verify the webhook signature for the given provider.
///
/// # Provider schemes
///
/// | Provider | Header | Format |
/// | --- | --- | --- |
/// | [`SaasProvider::ClaudeAi`] | `anthropic-signature` | `sha256=<hex>` |
/// | [`SaasProvider::ChatGpt`]  | `openai-signature`    | `sha256=<hex>` |
/// | [`SaasProvider::CursorCloud`] | `x-cursor-signature` | raw hex |
///
/// # Arguments
///
/// * `provider` — selects the per-provider verifier module.
/// * `headers`  — the HTTP request headers received from the provider.
/// * `body`     — the raw (unparsed) request body bytes.
/// * `secret`   — the resolved HMAC key bytes. The caller is responsible for
///   resolving the Vault reference before calling this function.
///
/// # Errors
///
/// Returns [`SignatureError::MissingHeader`] when the expected header is not
/// present. Returns [`SignatureError::InvalidSignature`] when the header is
/// present but the HMAC does not match.
pub fn verify(
    provider: &SaasProvider,
    headers: &http::HeaderMap,
    body: &[u8],
    secret: &[u8],
) -> Result<(), SignatureError> {
    match provider {
        SaasProvider::ClaudeAi => claude_ai::verify(headers, body, secret),
        SaasProvider::ChatGpt => chatgpt::verify(headers, body, secret),
        SaasProvider::CursorCloud => cursor::verify(headers, body, secret),
    }
}
