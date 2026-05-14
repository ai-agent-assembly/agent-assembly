//! Integration tests for the per-op lifecycle endpoints
//! (`POST /api/v1/ops/{id}/{pause,resume,terminate}`).
//!
//! These endpoints are stubs today (see `routes/ops.rs`) — they validate
//! the op id, log the request, and return 202 Accepted. The tests cover
//! the happy path for each action and the 400-on-empty-id failure path.

mod common;

use aa_api::server::build_app;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

async fn post(action: &str, path_id: &str) -> (StatusCode, Value) {
    let state = common::test_state();
    let app = build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/ops/{path_id}/{action}"))
                .header("content-type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 64).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn pause_op_returns_202_with_ack() {
    let (status, body) = post("pause", "op-1").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["op_id"], "op-1");
    assert_eq!(body["action"], "pause");
    assert!(body["accepted_at"].is_string());
}

#[tokio::test]
async fn resume_op_returns_202_with_ack() {
    let (status, body) = post("resume", "op-42").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["op_id"], "op-42");
    assert_eq!(body["action"], "resume");
}

#[tokio::test]
async fn terminate_op_returns_202_with_ack() {
    let (status, body) = post("terminate", "op-7").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["op_id"], "op-7");
    assert_eq!(body["action"], "terminate");
}

#[tokio::test]
async fn op_id_with_url_encoded_chars_is_accepted_verbatim() {
    let (status, body) = post("pause", "op%2F123").await;
    assert_eq!(status, StatusCode::ACCEPTED);
    // axum's Path extractor decodes the path segment.
    assert_eq!(body["op_id"], "op/123");
}

#[tokio::test]
async fn whitespace_only_op_id_returns_400() {
    let (status, body) = post("pause", "%20%20").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("Operation id must not be empty"));
}

#[tokio::test]
async fn unknown_action_falls_through_to_404() {
    // Sanity check: only pause/resume/terminate are routed; anything else
    // hits the catch-all `fallback_404`.
    let (status, _body) = post("delete", "op-1").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
