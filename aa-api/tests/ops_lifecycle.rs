//! Unit tests for the per-op lifecycle endpoints
//! (`GET /api/v1/ops`, `POST /api/v1/ops`, `POST /api/v1/ops/{id}/{pause,resume,terminate}`).
//!
//! State machine is now backed by OpsRegistry on AppState (AAASM-1525).
//! Each lifecycle test registers an op first via POST /api/v1/ops.

mod common;

use aa_api::auth::scope::Scope;
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

#[tokio::test]
async fn list_ops_returns_200_with_all_registered_ops() {
    let app = build_app(common::test_state());
    // Register two ops then list them.
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-list-a"})).await;
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-list-b"})).await;

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/ops")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let ops = body.as_array().unwrap();
    assert_eq!(ops.len(), 2);
}

#[tokio::test]
async fn register_op_empty_op_id_returns_400() {
    let app = build_app(common::test_state());
    let (status, body) = post_json(app, "/api/v1/ops", json!({"op_id": "   "})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("op_id must not be empty"));
}

#[tokio::test]
async fn invalid_transition_returns_409() {
    let app = build_app(common::test_state());
    // Register then immediately try to resume — resume from running is invalid.
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-conflict"})).await;
    let (status, body) = post_empty(app, "/api/v1/ops/op-conflict/resume").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("state does not permit"));
}

// ── AAASM-3881: operator agent-wide / global halt endpoints ────────────────

#[tokio::test]
async fn halt_agent_unknown_op_returns_404() {
    let app = build_app(common::test_state());
    let (status, _body) = post_json(app, "/api/v1/ops/no-such-op/halt-agent", json!({"action": "terminate"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn halt_agent_unknown_action_returns_400() {
    let app = build_app(common::test_state());
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-h1"})).await;
    let (status, body) = post_json(app, "/api/v1/ops/op-h1/halt-agent", json!({"action": "explode"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("Unknown halt action"));
}

#[tokio::test]
async fn halt_agent_op_without_owning_agent_returns_409() {
    // An op registered via POST /api/v1/ops carries no agent identity, so there
    // is no server-side agent to address an agent-wide halt to.
    let app = build_app(common::test_state());
    post_json(app.clone(), "/api/v1/ops", json!({"op_id": "op-h2"})).await;
    let (status, body) = post_json(app, "/api/v1/ops/op-h2/halt-agent", json!({"action": "terminate"})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("no resolvable owning agent"));
}

#[tokio::test]
async fn halt_global_unknown_action_returns_400() {
    let app = build_app(common::test_state());
    let (status, body) = post_json(app, "/api/v1/ops/global/halt", json!({"action": "explode"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("Unknown halt action"));
}

#[tokio::test]
async fn halt_global_without_publisher_returns_503() {
    // The default test state attaches no op-control publisher, so the channel
    // is unavailable and the endpoint must say so explicitly.
    let app = build_app(common::test_state());
    let (status, _body) = post_json(app, "/api/v1/ops/global/halt", json!({"action": "terminate"})).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn halt_global_requires_admin_scope() {
    // A write-but-not-admin caller may drive per-op lifecycle, but the
    // fleet-wide kill switch is gated to admins.
    let (plaintext, entry) = common::generate_test_api_key("writer", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/ops/global/halt")
                .header("authorization", format!("Bearer {plaintext}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"action":"terminate"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
