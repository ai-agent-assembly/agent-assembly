//! Per-provider HMAC-SHA256 webhook signature verification.
//!
//! Each SaaS provider uses a distinct header name and encoding scheme. This
//! module centralises the dispatch so callers always use the same entry point:
//! [`verify`].
//!
//! # Security
//!
//! All comparisons use the constant-time [`hmac::Mac::verify_slice`] method
//! provided by the `hmac` crate, which is built on `subtle::ConstantTimeEq`.
//! Never replace these with `==` comparisons — timing-side-channel attacks on
//! HMAC-based webhook signatures are a known threat.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::provider::SaasProvider;

type HmacSha256 = Hmac<Sha256>;

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
/// * `provider` — determines which header name and format to look up.
/// * `headers`  — the HTTP request headers received from the provider.
/// * `body`     — the raw (unparsed) request body bytes.
/// * `secret`   — the resolved HMAC key bytes (caller must have resolved
///   the Vault reference before calling this function).
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
        SaasProvider::ClaudeAi => verify_prefixed(headers, body, secret, "anthropic-signature"),
        SaasProvider::ChatGpt => verify_prefixed(headers, body, secret, "openai-signature"),
        SaasProvider::CursorCloud => verify_raw_hex(headers, body, secret, "x-cursor-signature"),
    }
}

/// Verify a `sha256=<hex>` prefixed signature header.
fn verify_prefixed(
    headers: &http::HeaderMap,
    body: &[u8],
    secret: &[u8],
    header_name: &str,
) -> Result<(), SignatureError> {
    let header_value = headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    let hex_part = header_value
        .strip_prefix("sha256=")
        .ok_or(SignatureError::InvalidSignature)?;

    let received_bytes = hex::decode(hex_part).map_err(|_| SignatureError::InvalidSignature)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| SignatureError::InvalidSignature)?;
    mac.update(body);
    mac.verify_slice(&received_bytes)
        .map_err(|_| SignatureError::InvalidSignature)
}

/// Verify a raw-hex signature header (no `sha256=` prefix).
fn verify_raw_hex(
    headers: &http::HeaderMap,
    body: &[u8],
    secret: &[u8],
    header_name: &str,
) -> Result<(), SignatureError> {
    let header_value = headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .ok_or(SignatureError::MissingHeader)?;

    let received_bytes = hex::decode(header_value).map_err(|_| SignatureError::InvalidSignature)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| SignatureError::InvalidSignature)?;
    mac.update(body);
    mac.verify_slice(&received_bytes)
        .map_err(|_| SignatureError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;
    use http::HeaderMap;

    fn compute_hmac(secret: &[u8], body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn claude_ai_valid_signature_passes() {
        let secret = b"test-secret";
        let body = b"hello world";
        let sig = format!("sha256={}", hex::encode(compute_hmac(secret, body)));
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-signature", sig.parse().unwrap());
        assert!(verify(&SaasProvider::ClaudeAi, &headers, body, secret).is_ok());
    }

    #[test]
    fn claude_ai_bad_signature_returns_err() {
        let secret = b"test-secret";
        let body = b"hello world";
        let mut bad_bytes = compute_hmac(secret, body);
        bad_bytes[0] ^= 0xff; // flip one byte
        let sig = format!("sha256={}", hex::encode(bad_bytes));
        let mut headers = HeaderMap::new();
        headers.insert("anthropic-signature", sig.parse().unwrap());
        assert!(matches!(
            verify(&SaasProvider::ClaudeAi, &headers, body, secret),
            Err(SignatureError::InvalidSignature)
        ));
    }

    #[test]
    fn chatgpt_valid_signature_passes() {
        let secret = b"gpt-secret";
        let body = b"chatgpt event";
        let sig = format!("sha256={}", hex::encode(compute_hmac(secret, body)));
        let mut headers = HeaderMap::new();
        headers.insert("openai-signature", sig.parse().unwrap());
        assert!(verify(&SaasProvider::ChatGpt, &headers, body, secret).is_ok());
    }

    #[test]
    fn cursor_bad_signature_returns_err() {
        let secret = b"cursor-secret";
        let body = b"cursor event";
        let mut bad_bytes = compute_hmac(secret, body);
        bad_bytes[0] ^= 0x01;
        let sig = hex::encode(bad_bytes);
        let mut headers = HeaderMap::new();
        headers.insert("x-cursor-signature", sig.parse().unwrap());
        assert!(matches!(
            verify(&SaasProvider::CursorCloud, &headers, body, secret),
            Err(SignatureError::InvalidSignature)
        ));
    }

    #[test]
    fn missing_header_returns_missing_header_error() {
        let headers = HeaderMap::new();
        assert!(matches!(
            verify(&SaasProvider::ClaudeAi, &headers, b"body", b"secret"),
            Err(SignatureError::MissingHeader)
        ));
    }
}
