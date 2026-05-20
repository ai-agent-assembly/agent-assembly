//! Cursor cloud webhook signature verification.
//!
//! Header: `x-cursor-signature`. Value format: raw hex (no scheme prefix).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::SignatureError;

type HmacSha256 = Hmac<Sha256>;

/// HTTP header carrying the Cursor HMAC-SHA256 signature.
const HEADER: &str = "x-cursor-signature";

/// Verify a Cursor cloud webhook signature.
///
/// Unlike Anthropic and OpenAI, Cursor sends the hex digest with no
/// `sha256=` prefix.
pub fn verify(headers: &http::HeaderMap, body: &[u8], secret: &[u8]) -> Result<(), SignatureError> {
    let header_value = headers
        .get(HEADER)
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
    use http::HeaderMap;

    fn compute_hmac(secret: &[u8], body: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(secret).expect("valid key");
        mac.update(body);
        mac.finalize().into_bytes().to_vec()
    }

    #[test]
    fn valid_signature_passes() {
        let secret = b"cursor-secret";
        let body = b"cursor event";
        let sig = hex::encode(compute_hmac(secret, body));
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, sig.parse().unwrap());
        assert!(verify(&headers, body, secret).is_ok());
    }

    #[test]
    fn bad_signature_returns_invalid() {
        let secret = b"cursor-secret";
        let body = b"cursor event";
        let mut bad_bytes = compute_hmac(secret, body);
        bad_bytes[0] ^= 0x01;
        let sig = hex::encode(bad_bytes);
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
}
