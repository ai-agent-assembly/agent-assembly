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
