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
use common::{TopologyTestEnv, AUTH_IT_JWT_SECRET};
use reqwest::StatusCode;

// ── Section 1 — JWT validation ───────────────────────────────────────────────

#[tokio::test]
async fn auth_jwt_valid_signed_token_grants_access() {
    let env = TopologyTestEnv::start_with_auth(&[], 1000).await.unwrap();

    let jwt = JwtSigner::new(AUTH_IT_JWT_SECRET)
        .sign("test-sub", &[Scope::Read, Scope::Write])
        .unwrap();

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/agents", env.base_url()))
        .bearer_auth(&jwt)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
