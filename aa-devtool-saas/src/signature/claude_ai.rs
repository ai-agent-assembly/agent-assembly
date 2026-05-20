//! Anthropic Claude.ai webhook signature verification.
//!
//! Header: `anthropic-signature`. Value format: `sha256=<hex>`.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::SignatureError;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header carrying the Claude.ai HMAC-SHA256 signature.
const HEADER: &str = "anthropic-signature";

/// Verify a Claude.ai webhook signature.
///
/// The header value must be `sha256=<hex>`. Any other shape is rejected as
/// [`SignatureError::InvalidSignature`].
pub fn verify(headers: &http::HeaderMap, body: &[u8], secret: &[u8]) -> Result<(), SignatureError> {
    let header_value = headers
        .get(HEADER)
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

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;

    fn compute_hmac(secret: &[u8], body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn valid_signature_passes() {
        let secret = b"test-secret";
        let body = b"hello world";
        let sig = format!("sha256={}", hex::encode(compute_hmac(secret, body)));
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, sig.parse().unwrap());
        assert!(verify(&headers, body, secret).is_ok());
    }

    #[test]
    fn bad_signature_returns_invalid() {
        let secret = b"test-secret";
        let body = b"hello world";
        let mut bad_bytes = compute_hmac(secret, body);
        bad_bytes[0] ^= 0xff;
        let sig = format!("sha256={}", hex::encode(bad_bytes));
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, sig.parse().unwrap());
        assert!(matches!(
            verify(&headers, body, secret),
            Err(SignatureError::InvalidSignature)
        ));
    }

    #[test]
    fn missing_header_returns_missing() {
        let headers = HeaderMap::new();
        assert!(matches!(
            verify(&headers, b"body", b"secret"),
            Err(SignatureError::MissingHeader)
        ));
    }

    #[test]
    fn missing_prefix_returns_invalid() {
        let secret = b"test-secret";
        let body = b"hello world";
        let sig = hex::encode(compute_hmac(secret, body)); // no "sha256=" prefix
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, sig.parse().unwrap());
        assert!(matches!(
            verify(&headers, body, secret),
            Err(SignatureError::InvalidSignature)
        ));
    }
}
