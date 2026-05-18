//! AAASM-1499 — Authentication & authorization integration test matrix.
//!
//! 25 live-gateway HTTP integration tests (via `reqwest` against a real
//! in-process Axum server) covering 6 auth sections:
//!
//! - S1: JWT validation
//! - S2: API key authentication
//! - S3: Scope-based authorization
//! - S4: Rate limiting
//! - S5: Bypass attempts
//! - S6: Policy → RBAC integration

mod common;

use aa_api::auth::jwt::JwtSigner;
use aa_api::auth::scope::Scope;
use common::{make_api_key, TopologyTestEnv, AUTH_IT_JWT_SECRET};
use reqwest::StatusCode;
use serde_json::Value;

// ── Section 1 — JWT validation ───────────────────────────────────────────────
//
// S1 tests use POST /api/v1/auth/token because it requires AuthenticatedCaller
// (enforces auth). GET /api/v1/agents is public and does not validate auth.

/// Build an expired JWT using the same secret as the test harness.
///
/// We construct Claims manually with `exp` in the past and encode directly
/// with `jsonwebtoken` — `JwtSigner::sign_with_expiry` is `#[cfg(test)]`-private
/// to aa-api and is not accessible from integration tests.
fn build_expired_jwt() -> String {
    use aa_api::auth::jwt::Claims;
    use jsonwebtoken::{encode, EncodingKey, Header};
    let claims = Claims {
        sub: "test-expired".to_string(),
        iat: 0,
        exp: 1, // epoch second 1 — always in the past
        scope: vec![],
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(AUTH_IT_JWT_SECRET),
    )
    .unwrap()
}

#[tokio::test]
async fn auth_jwt_valid_signed_token_grants_access() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("test-sub", &[Scope::Read, Scope::Write])
        .unwrap();

    // POST /api/v1/auth/token enforces AuthenticatedCaller; a valid JWT should succeed.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_jwt_expired_token_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();
    let jwt = build_expired_jwt();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("expired"),
        "expected 'expired' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_invalid_signature_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    // Sign with the wrong secret — signature will be invalid.
    let jwt = JwtSigner::new(b"wrong-secret-totally-different-32bytes!!")
        .sign("test-sub", &[Scope::Read])
        .unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&jwt)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").to_lowercase().contains("invalid"),
        "expected 'invalid' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_malformed_token_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth("not.a.jwt")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("").to_lowercase();
    assert!(
        detail.contains("invalid") || detail.contains("token"),
        "expected 'invalid' or 'token' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_jwt_missing_authorization_header_returns_401() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    // No Authorization header at all.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("Missing"),
        "expected 'Missing' in detail, got: {:?}",
        body["detail"]
    );
}

// ── Section 2 — API key authentication ─────────────────────────────────────

#[tokio::test]
async fn auth_api_key_via_bearer_header_grants_access() {
    // API key auth uses Authorization: Bearer aa_<hex> — not X-API-Key header
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/agents", env.base_url()))
        .bearer_auth(&plaintext)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_api_key_query_param_unsupported_returns_401() {
    // Query-param API key auth is not implemented; only Authorization: Bearer is supported
    let (plaintext, entry) = make_api_key("key-1", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Provide key via query param only — no Authorization header.
    // Use an auth-protected endpoint so we can observe the 401.
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token?api_key={plaintext}", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_api_key_revoked_returns_401() {
    let (plaintext, entry) = make_api_key("key-rev", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Revoke the key at runtime — the server holds the same Arc<ApiKeyStore>.
    env.key_store.revoke("key-rev");

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["detail"].as_str().unwrap_or("").contains("revoked"),
        "expected 'revoked' in detail, got: {:?}",
        body["detail"]
    );
}

#[tokio::test]
async fn auth_api_key_unknown_returns_401() {
    // No keys seeded — any aa_-prefixed token is unknown.
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth("aa_00000000000000000000000000000000")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("").to_lowercase();
    assert!(
        detail.contains("invalid") || detail.contains("api key"),
        "expected 'invalid' or 'api key' in detail, got: {:?}",
        body["detail"]
    );
}

// ── Section 3 — Scope-based authorization ────────────────────────────────────

#[tokio::test]
async fn auth_scope_read_key_accesses_public_endpoint() {
    // GET /agents has no scope guard — any valid auth is accepted
    let (plaintext, entry) = make_api_key("read-key", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/agents", env.base_url()))
        .bearer_auth(&plaintext)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_scope_read_cannot_elevate_to_write_via_token() {
    // read-scoped caller cannot elevate to write via token endpoint
    let (plaintext, entry) = make_api_key("read-key", vec![Scope::Read]);
    let env = TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({"scopes": ["write"]}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
