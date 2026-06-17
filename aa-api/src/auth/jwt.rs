//! JWT signing and verification using HMAC-SHA256.

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::scope::Scope;

/// JWT token expiry duration: 24 hours in seconds.
const TOKEN_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// JWT claims payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the API key ID that this token was issued for.
    pub sub: String,
    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: u64,
    /// Expiry timestamp (Unix epoch seconds).
    pub exp: u64,
    /// Scopes granted to this token.
    pub scope: Vec<Scope>,
    /// AAASM-3139 — the team this token is scoped to. When present, a
    /// non-admin caller is confined to its own team for per-tenant data
    /// (e.g. `/costs`, `/agents/{id}/budget`). `None` on legacy tokens
    /// issued before tenant claims existed, which therefore carry no team
    /// scope (and remain admin-gated for cross-tenant data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// AAASM-3139 — the org this token is scoped to. See [`Claims::team_id`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

/// Signs JWTs using HMAC-SHA256.
pub struct JwtSigner {
    encoding_key: EncodingKey,
}

impl JwtSigner {
    /// Create a new signer from a raw HMAC secret.
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
        }
    }

    /// Sign a new JWT for the given API key ID and scopes.
    ///
    /// The token expires after 24 hours.
    pub fn sign(&self, key_id: &str, scopes: &[Scope]) -> Result<String, JwtError> {
        self.sign_with_tenant(key_id, scopes, None, None)
    }

    /// Sign a JWT that additionally carries a tenant scope (AAASM-3139).
    ///
    /// `team_id` / `org_id` confine a non-admin caller to its own tenant for
    /// per-tenant data endpoints. Pass `None` for either to leave it unscoped.
    /// The token expires after 24 hours.
    pub fn sign_with_tenant(
        &self,
        key_id: &str,
        scopes: &[Scope],
        team_id: Option<String>,
        org_id: Option<String>,
    ) -> Result<String, JwtError> {
        let now = now_epoch_secs();
        let claims = Claims {
            sub: key_id.to_string(),
            iat: now,
            exp: now + TOKEN_EXPIRY_SECS,
            scope: scopes.to_vec(),
            team_id,
            org_id,
        };
        encode(&Header::default(), &claims, &self.encoding_key).map_err(JwtError::Encode)
    }

    /// Sign a JWT with a custom expiry (for testing).
    #[cfg(test)]
    fn sign_with_expiry(&self, key_id: &str, scopes: &[Scope], exp: u64) -> Result<String, JwtError> {
        let claims = Claims {
            sub: key_id.to_string(),
            iat: now_epoch_secs(),
            exp,
            scope: scopes.to_vec(),
            team_id: None,
            org_id: None,
        };
        encode(&Header::default(), &claims, &self.encoding_key).map_err(JwtError::Encode)
    }
}

/// Verifies JWT tokens using HMAC-SHA256.
pub struct JwtVerifier {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtVerifier {
    /// Create a new verifier from a raw HMAC secret.
    pub fn new(secret: &[u8]) -> Self {
        let mut validation = Validation::default();
        validation.set_required_spec_claims(&["sub", "iat", "exp"]);
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Verify a JWT token and return its claims.
    ///
    /// Returns an error if the signature is invalid or the token has expired.
    pub fn verify(&self, token: &str) -> Result<Claims, JwtError> {
        let data = decode::<Claims>(token, &self.decoding_key, &self.validation).map_err(JwtError::Decode)?;
        Ok(data.claims)
    }
}

/// Return the current Unix epoch timestamp in seconds.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_secs()
}

/// Errors related to JWT operations.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("failed to encode JWT: {0}")]
    Encode(jsonwebtoken::errors::Error),
    #[error("failed to decode JWT: {0}")]
    Decode(jsonwebtoken::errors::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-that-is-at-least-32-bytes-long!!";

    #[test]
    fn test_jwt_sign_verify_roundtrip() {
        let signer = JwtSigner::new(TEST_SECRET);
        let verifier = JwtVerifier::new(TEST_SECRET);

        let token = signer
            .sign("key-123", &[Scope::Read, Scope::Write])
            .expect("signing should succeed");
        let claims = verifier.verify(&token).expect("verification should succeed");

        assert_eq!(claims.sub, "key-123");
        assert_eq!(claims.scope, vec![Scope::Read, Scope::Write]);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn test_jwt_expired_token_rejected() {
        let signer = JwtSigner::new(TEST_SECRET);
        let verifier = JwtVerifier::new(TEST_SECRET);

        // Create a token that expired 1 hour ago.
        let expired = now_epoch_secs() - 3600;
        let token = signer
            .sign_with_expiry("key-123", &[Scope::Read], expired)
            .expect("signing should succeed");

        let result = verifier.verify(&token);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_jwt_wrong_secret_rejected() {
        let signer = JwtSigner::new(TEST_SECRET);
        let verifier = JwtVerifier::new(b"different-secret-that-is-also-32-bytes-long!!");

        let token = signer.sign("key-123", &[Scope::Read]).expect("signing should succeed");

        let result = verifier.verify(&token);
        assert!(result.is_err(), "token signed with different secret should be rejected");
    }

    #[test]
    fn test_jwt_tenant_claim_roundtrip() {
        // AAASM-3139: a tenant-scoped token must carry team_id back through
        // verification; a plain token leaves the tenant claim None.
        let signer = JwtSigner::new(TEST_SECRET);
        let verifier = JwtVerifier::new(TEST_SECRET);

        let scoped = signer
            .sign_with_tenant("key-1", &[Scope::Read], Some("alpha".into()), Some("org-1".into()))
            .unwrap();
        let claims = verifier.verify(&scoped).unwrap();
        assert_eq!(claims.team_id.as_deref(), Some("alpha"));
        assert_eq!(claims.org_id.as_deref(), Some("org-1"));

        let plain = signer.sign("key-2", &[Scope::Read]).unwrap();
        let plain_claims = verifier.verify(&plain).unwrap();
        assert_eq!(plain_claims.team_id, None);
        assert_eq!(plain_claims.org_id, None);
    }

    #[test]
    fn test_jwt_scopes_preserved() {
        let signer = JwtSigner::new(TEST_SECRET);
        let verifier = JwtVerifier::new(TEST_SECRET);

        let scopes = vec![Scope::Read, Scope::Write, Scope::Admin];
        let token = signer.sign("key-456", &scopes).expect("signing should succeed");
        let claims = verifier.verify(&token).expect("verification should succeed");

        assert_eq!(claims.scope, scopes);
    }
}
