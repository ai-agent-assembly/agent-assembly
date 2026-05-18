//! Unit tests for the per-op lifecycle endpoints
//! (`GET /api/v1/ops`, `POST /api/v1/ops`, `POST /api/v1/ops/{id}/{pause,resume,terminate}`).
//!
//! State machine is now backed by OpsRegistry on AppState (AAASM-1525).
//! Each lifecycle test registers an op first via POST /api/v1/ops.

mod common;

use aa_api::server::build_app;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

async fn post_json(app: axum::Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 64).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

async fn post_empty(app: axum::Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
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
async fn register_op_returns_201_with_running_state() {
    let app = build_app(common::test_state());
    let (status, body) = post_json(app, "/api/v1/ops", json!({"op_id": "op-new"})).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["op_id"], "op-new");
    assert_eq!(body["state"], "running");
    assert!(body["registered_at"].is_string());
}

#[tokio::test]
async fn pause_op_returns_200_with_ack() {
    let app = build_app(common::test_state());
    // Register first
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-1"})).await;
    let (status, body) = post_empty(app, "/api/v1/ops/op-1/pause").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["op_id"], "op-1");
    assert_eq!(body["action"], "pause");
    assert!(body["accepted_at"].is_string());
}

#[tokio::test]
async fn resume_op_returns_200_with_ack() {
    let app = build_app(common::test_state());
    // Register → pause → resume
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-42"})).await;
    post_empty(app.clone(), "/api/v1/ops/op-42/pause").await;
    let (status, body) = post_empty(app, "/api/v1/ops/op-42/resume").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["op_id"], "op-42");
    assert_eq!(body["action"], "resume");
}

#[tokio::test]
async fn terminate_op_returns_200_with_ack() {
    let app = build_app(common::test_state());
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-7"})).await;
    let (status, body) = post_empty(app, "/api/v1/ops/op-7/terminate").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["op_id"], "op-7");
    assert_eq!(body["action"], "terminate");
}

#[tokio::test]
async fn op_unknown_id_returns_404() {
    let app = build_app(common::test_state());
    let (status, _body) = post_empty(app, "/api/v1/ops/completely-unknown-id/pause").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn op_id_with_url_encoded_chars_is_accepted() {
    let app = build_app(common::test_state());
    // Register with decoded form, act via encoded URL
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op/123"})).await;
    let (status, body) = post_empty(app, "/api/v1/ops/op%2F123/pause").await;
    assert_eq!(status, StatusCode::OK);
    // axum's Path extractor decodes the path segment.
    assert_eq!(body["op_id"], "op/123");
}

#[tokio::test]
async fn whitespace_only_op_id_returns_400() {
    let app = build_app(common::test_state());
    let (status, body) = post_empty(app, "/api/v1/ops/%20%20/pause").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("Operation id must not be empty"));
}

#[tokio::test]
async fn unknown_action_falls_through_to_404() {
    let app = build_app(common::test_state());
    let (status, _body) = post_empty(app, "/api/v1/ops/op-1/delete").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
