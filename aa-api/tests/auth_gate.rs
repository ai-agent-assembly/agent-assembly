//! Integration tests for the router-level authentication gate (AAASM-3125,
//! AAASM-3129, AAASM-3126).
//!
//! These assert the deny-by-default behavior of the protected sub-router:
//! protected routes reject unauthenticated callers with 401, public routes
//! stay reachable, alert-rule CRUD is gated, and the cross-tenant spend
//! surfaces are restricted.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

fn bearer(uri: &str, method: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap()
}

// ── F1 / AAASM-3125: deny-by-default over protected routes ──────────────────

#[tokio::test]
async fn protected_route_without_credentials_is_401() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/agents").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_route_with_valid_key_is_not_401() {
    let (plaintext, entry) = common::generate_test_api_key("k", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(bearer("/api/v1/agents", "GET", &plaintext)).await.unwrap();

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_endpoint_stays_public() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ── N1 / AAASM-3129: alert-rule CRUD requires auth ──────────────────────────

#[tokio::test]
async fn alert_rules_list_without_credentials_is_401() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts/rules")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn alert_rules_create_without_credentials_is_401() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/alerts/rules")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn alert_rules_create_with_read_only_key_is_403() {
    let (plaintext, entry) = common::generate_test_api_key("ro", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/alerts/rules")
                .header("authorization", format!("Bearer {plaintext}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Read-only caller is authenticated but lacks write scope.
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── F1a / AAASM-3126: cross-tenant IDOR on /costs ───────────────────────────

#[tokio::test]
async fn costs_without_credentials_is_401() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn costs_non_admin_does_not_leak_cross_tenant_breakdown() {
    let (plaintext, entry) = common::generate_test_api_key("ro", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(bearer("/api/v1/costs", "GET", &plaintext)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["per_agent"].as_array().unwrap().len(),
        0,
        "non-admin must not receive the cross-tenant per-agent breakdown"
    );
    assert_eq!(
        json["per_team"].as_array().unwrap().len(),
        0,
        "non-admin must not receive the cross-tenant per-team breakdown"
    );
}

// ── F1a / AAASM-3126: cross-tenant IDOR on /agents/{id}/budget ──────────────

#[tokio::test]
async fn agent_budget_without_credentials_is_401() {
    let app = common::test_app_with_auth(&[], 1000);
    let agent_id = "00000000000000000000000000000000";

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{agent_id}/budget"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn agent_budget_non_admin_is_403() {
    let (plaintext, entry) = common::generate_test_api_key("ro", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);
    let agent_id = "00000000000000000000000000000000";

    let response = app
        .oneshot(bearer(&format!("/api/v1/agents/{agent_id}/budget"), "GET", &plaintext))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
