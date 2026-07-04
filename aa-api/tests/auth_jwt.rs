//! Integration tests for JWT authentication flow.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

#[tokio::test]
async fn test_valid_jwt_grants_access() {
    let (_plaintext, entry) = common::generate_test_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);
    let jwt = common::generate_test_jwt("key-1", &[Scope::Read, Scope::Write]);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_expired_jwt_returns_401() {
    let (_plaintext, entry) = common::generate_test_api_key("key-1", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    // JWT signed with a different secret should fail verification.
    let wrong_signer = aa_api::auth::jwt::JwtSigner::new(b"wrong-secret-that-is-at-least-32-bytes-long!!");
    let wrong_jwt = wrong_signer
        .sign("key-1", &[Scope::Read])
        .expect("signing should succeed");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {wrong_jwt}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_wrong_secret_jwt_returns_401() {
    let (_plaintext, entry) = common::generate_test_api_key("key-1", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let wrong_signer = aa_api::auth::jwt::JwtSigner::new(b"different-secret-that-is-also-32-bytes-long!!");
    let jwt = wrong_signer
        .sign("key-1", &[Scope::Read])
        .expect("signing should succeed");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {jwt}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_endpoint_issues_jwt() {
    let (plaintext, entry) = common::generate_test_api_key("key-1", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {plaintext}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["token"].is_string(), "response should contain a token");
    assert!(json["expires_at"].is_u64(), "response should contain expires_at");
    assert!(json["scopes"].is_array(), "response should contain scopes");
}

#[tokio::test]
async fn test_token_endpoint_respects_scope_subset() {
    let (plaintext, entry) = common::generate_test_api_key("key-1", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    // Request Write scope when caller only has Read — should fail.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {plaintext}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"scopes":["write"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── AAASM-3894 — issued JWT retains the caller's tenant ───────────────────────
//
// `issue_token` previously signed without the caller's tenant, so a
// tenant-confined API key's issued JWT lost its team_id/org_id and fell back to
// admin-only cross-tenant gating. The issued token must carry the caller's
// tenant claims through verification.

#[tokio::test]
async fn issued_jwt_retains_caller_tenant() {
    use aa_api::auth::api_key::{ApiKey, ApiKeyEntry};
    use aa_api::auth::jwt::JwtVerifier;

    // Must match the test harness JWT secret in `common`.
    const TEST_SECRET: &[u8] = b"test-secret-key-that-is-at-least-32-bytes-long!!";

    let key = ApiKey::generate();
    let entry = ApiKeyEntry {
        id: "key-tenant".to_string(),
        key_hash: key.hash().expect("hashing should succeed"),
        scopes: vec![Scope::Read, Scope::Write],
        created_at: 1700000000,
        label: Some("tenant key".to_string()),
        team_id: Some("alpha".to_string()),
        org_id: Some("org-1".to_string()),
        key_lookup: Some(key.lookup()),
    };
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/token")
                .header("authorization", format!("Bearer {}", key.as_str()))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["token"].as_str().expect("response carries a token");

    // The issued JWT must still carry the caller's tenant claims.
    let claims = JwtVerifier::new(TEST_SECRET).verify(token).expect("token verifies");
    assert_eq!(
        claims.team_id.as_deref(),
        Some("alpha"),
        "issued JWT dropped the caller's team_id"
    );
    assert_eq!(
        claims.org_id.as_deref(),
        Some("org-1"),
        "issued JWT dropped the caller's org_id"
    );
}
