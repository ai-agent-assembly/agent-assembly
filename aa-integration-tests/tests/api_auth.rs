//! AAASM-1485 / F122 ST-D — live-gateway integration tests for
//! `POST /api/v1/auth/token` (JWT issuance from API key credentials).
//!
//! All tests spin up a real `TopologyTestEnv` with `AuthMode::On` via
//! `start_with_auth()`, make HTTP calls with `reqwest`, and assert on the
//! actual HTTP response — nothing is mocked.
//!
//! ## Divergence note
//!
//! The JIRA ticket was drafted against a `{api_key, secret}` request body
//! design. The implemented endpoint instead authenticates via the
//! `Authorization: Bearer <aa_key>` header with an optional `{"scopes":[…]}`
//! body. Tests match the actual implementation.

mod common;

use aa_api::auth::jwt::JwtVerifier;
use aa_api::auth::scope::Scope;
use reqwest::StatusCode;

// ─── happy path ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_token_with_valid_api_key_returns_jwt() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["token"].as_str().expect("response must have 'token' string");
    assert!(!token.is_empty(), "token must be non-empty");
    assert!(body["expires_at"].is_u64(), "response must have 'expires_at' as u64");
    assert!(body["scopes"].is_array(), "response must have 'scopes' as array");
}

#[tokio::test]
async fn auth_token_jwt_is_well_formed() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let token_str = body["token"].as_str().expect("response must have 'token' string");

    let verifier = JwtVerifier::new(common::AUTH_IT_JWT_SECRET);
    let claims = verifier
        .verify(token_str)
        .expect("JWT must verify with the test secret");

    assert!(!claims.sub.is_empty(), "JWT payload must have non-empty 'sub'");
    assert!(claims.exp > 0, "JWT payload must have positive 'exp'");
    assert!(claims.iat > 0, "JWT payload must have positive 'iat'");
    assert!(!claims.scope.is_empty(), "JWT payload must have non-empty 'scope'");
}

#[tokio::test]
async fn auth_token_with_scoped_api_key_returns_scoped_jwt() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.unwrap();
    let token_str = body["token"].as_str().expect("response must have 'token' string");

    let verifier = JwtVerifier::new(common::AUTH_IT_JWT_SECRET);
    let claims = verifier
        .verify(token_str)
        .expect("JWT must verify with the test secret");

    assert_eq!(
        claims.scope,
        vec![Scope::Read],
        "JWT scope must match the API key's scopes"
    );
}
