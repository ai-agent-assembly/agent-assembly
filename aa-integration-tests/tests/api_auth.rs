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

// ─── error paths ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_token_with_unknown_api_key_returns_401() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Generate a fresh key that was never registered in the store.
    let (unknown_plaintext, _) = common::make_api_key("key-unknown", vec![Scope::Read]);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&unknown_plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Suppress unused-variable warning; plaintext kept to make the store non-empty.
    let _ = plaintext;
}

#[tokio::test]
async fn auth_token_without_auth_header_returns_401() {
    let (_, entry) = common::make_api_key("key-1", vec![Scope::Read]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_token_with_revoked_key_returns_401() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read]);
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 1000).await.unwrap();

    // Revoke the key via the shared Arc before making the request.
    env.key_store.revoke("key-1");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/auth/token", env.base_url()))
        .bearer_auth(&plaintext)
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.unwrap();
    let detail = body["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("revoked"),
        "error detail must mention 'revoked'; got: {detail}"
    );
}

// ─── rate limit ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn auth_token_rate_limit_applies_per_api_key() {
    let (plaintext, entry) = common::make_api_key("key-1", vec![Scope::Read]);
    // Set rate limit to 5 requests per minute so it is easily triggered in tests.
    let env = common::TopologyTestEnv::start_with_auth(&[entry], 5).await.unwrap();

    let client = reqwest::Client::new();
    let mut statuses = Vec::new();
    for _ in 0..10 {
        let resp = client
            .post(format!("{}/api/v1/auth/token", env.base_url()))
            .bearer_auth(&plaintext)
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        statuses.push(resp.status());
    }

    let ok_count = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let rate_limited = statuses.contains(&StatusCode::TOO_MANY_REQUESTS);

    assert!(
        ok_count >= 1,
        "at least one request should succeed before the limit kicks in"
    );
    assert!(
        rate_limited,
        "some requests must be rate-limited (429) when limit is 5 rpm"
    );
}
