//! Integration tests for `GET /api/v1/audit/violations-by-lineage` (AAASM-3805).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn violations_by_lineage_returns_200_with_empty_set() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/violations-by-lineage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["nodes"].is_array());
    assert!(json["window_secs"].is_number());
    assert!(json["generated_at"].is_string());
}

#[tokio::test]
async fn violations_by_lineage_accepts_window_param() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/violations-by-lineage?window=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["window_secs"], 3600);
}
