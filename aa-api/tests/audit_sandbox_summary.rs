//! Integration tests for `GET /api/v1/audit/sandbox-summary` (AAASM-1911).
//!
//! Drives the live router so the route registration, query parsing,
//! payload parsing, and JSON response shape are exercised end-to-end. The
//! pure aggregator logic is covered by unit tests in `routes::audit`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn sandbox_summary_returns_zero_counts_when_no_audit_entries() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["counts"]["would_be_denies"], 0);
    assert_eq!(json["counts"]["would_be_redactions"], 0);
    assert_eq!(json["counts"]["would_be_pending_approvals"], 0);
    assert!(json["top_rule"].is_null());
    assert_eq!(json["window_secs"], 86_400);
    assert!(json["generated_at"].is_string());
}

#[tokio::test]
async fn sandbox_summary_respects_window_query_param() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary?window=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["window_secs"], 3_600);
}

#[tokio::test]
async fn sandbox_summary_falls_back_to_24h_for_invalid_window() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary?window=garbage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Default is 24h = 86_400 seconds — invalid input degrades to default,
    // matching the violations-by-lineage handler's behaviour.
    assert_eq!(json["window_secs"], 86_400);
}
