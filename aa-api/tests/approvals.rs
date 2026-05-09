//! Integration tests for the approval endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_runtime::approval::ApprovalRequest;

fn make_approval_request(timeout_secs: u64) -> ApprovalRequest {
    ApprovalRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_id: "test-agent".to_string(),
        action: "read_file /etc/passwd".to_string(),
        condition_triggered: "sensitive-file-access".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: None,
    }
}

#[tokio::test]
async fn list_approvals_returns_empty_when_no_pending() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/approvals").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_approvals_returns_pending_requests() {
    let state = common::test_state();

    let req = make_approval_request(600);
    let expected_id = req.request_id.to_string();
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/approvals").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], expected_id);
    assert_eq!(items[0]["agent_id"], "test-agent");
    assert_eq!(items[0]["status"], "pending");
}

#[tokio::test]
async fn approve_action_succeeds_for_pending_request() {
    let state = common::test_state();

    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "alice"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "approved");
}

#[tokio::test]
async fn approve_action_returns_404_for_unknown_id() {
    let app = common::test_app();

    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{fake_id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "alice"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reject_action_succeeds_for_pending_request() {
    let state = common::test_state();

    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{id}/reject"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "bob", "reason": "not allowed"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "rejected");
}

#[tokio::test]
async fn reject_action_returns_404_for_unknown_id() {
    let app = common::test_app();

    let fake_id = uuid::Uuid::new_v4();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{fake_id}/reject"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "bob", "reason": "denied"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_action_returns_400_for_invalid_uuid() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/approvals/not-a-uuid/approve")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "alice"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
