//! Integration tests for `GET /api/v1/tools`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn get_tools_returns_200_and_array() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/tools").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.is_array(), "response body should be a JSON array");
}

#[tokio::test]
async fn get_tools_returns_empty_array_when_no_tools() {
    // test_app injects an empty DiscoveryService (no adapters registered).
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/tools").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json,
        serde_json::json!([]),
        "expected empty array when no tools are installed"
    );
}

// ── AAASM-3894 — /tools requires read scope ───────────────────────────────────
//
// The discovered tool list exposes each tool's on-host `install_path`, so it
// must not be enumerable without authentication. An unauthenticated caller is
// rejected (401); a read-scoped caller is allowed (200).

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;

#[tokio::test]
async fn get_tools_without_token_is_401() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/tools").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "an unauthenticated caller must not enumerate dev tools"
    );
}

#[tokio::test]
async fn get_tools_with_read_token_is_200() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt("r", &[Scope::Read]);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/tools")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a read-scoped caller must be able to list dev tools"
    );
}
