//! Integration tests for the approval endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_runtime::approval::{ApprovalRequest, RoutingHistoryEntry};

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
        timeout_override_secs: None,
        escalation_role_override: None,
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
    // `created_at` = submitted_at = 1_700_000_000 → RFC 3339 → 2023-11-14T22:13:20+00:00
    // `expires_at` = submitted_at + timeout_secs (600) = 1_700_000_600 → 22:23:20+00:00
    assert_eq!(items[0]["created_at"], "2023-11-14T22:13:20+00:00");
    assert_eq!(items[0]["expires_at"], "2023-11-14T22:23:20+00:00");
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

// =============================================================================
// GET /api/v1/approvals/:id (AAASM-1477)
// =============================================================================

#[tokio::test]
async fn get_approval_returns_pending_when_id_is_in_queue() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id.to_string();
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/approvals/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], id);
    assert_eq!(json["status"], "pending");
    assert_eq!(json["agent_id"], "test-agent");
}

#[tokio::test]
async fn get_approval_returns_resolved_after_decide() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let uuid = req.request_id;
    let id = uuid.to_string();
    let (_rid, _fut) = state.approval_queue.submit(req);
    state
        .approval_queue
        .decide(
            uuid,
            aa_runtime::approval::ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: Some("looks good".to_string()),
            },
        )
        .expect("decide should succeed");

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/approvals/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], id);
    assert_eq!(json["status"], "approved");
    assert_eq!(json["agent_id"], "test-agent");
    // `expires_at` is intentionally empty for resolved records.
    assert_eq!(json["expires_at"], "");
}

#[tokio::test]
async fn get_approval_returns_404_for_unknown_id() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/approvals/{}", uuid::Uuid::new_v4()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// =============================================================================
// GET /api/v1/approvals?status=…&agent=… (AAASM-1477)
// =============================================================================

#[tokio::test]
async fn list_approvals_with_status_pending_returns_pending_requests() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id.to_string();
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/approvals?status=PENDING")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["items"][0]["id"], id);
    assert_eq!(json["items"][0]["status"], "pending");
}

#[tokio::test]
async fn list_approvals_with_status_approved_returns_resolved_records() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let uuid = req.request_id;
    let id = uuid.to_string();
    let (_rid, _fut) = state.approval_queue.submit(req);
    state
        .approval_queue
        .decide(
            uuid,
            aa_runtime::approval::ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: None,
            },
        )
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/approvals?status=approved")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["items"][0]["id"], id);
    assert_eq!(json["items"][0]["status"], "approved");
}

#[tokio::test]
async fn list_approvals_with_agent_filter_narrows_pending() {
    let state = common::test_state();
    let mut alice_req = make_approval_request(600);
    alice_req.agent_id = "alice-agent".to_string();
    let alice_id = alice_req.request_id.to_string();
    let mut bob_req = make_approval_request(600);
    bob_req.agent_id = "bob-agent".to_string();
    let (_rid_a, _) = state.approval_queue.submit(alice_req);
    let (_rid_b, _) = state.approval_queue.submit(bob_req);

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/approvals?agent=alice-agent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);
    assert_eq!(json["items"][0]["id"], alice_id);
    assert_eq!(json["items"][0]["agent_id"], "alice-agent");
}

#[tokio::test]
async fn list_approvals_with_unknown_status_returns_empty_page() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let (_rid, _fut) = state.approval_queue.submit(req);

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/approvals?status=bogus")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_approval_returns_400_for_invalid_uuid() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/approvals/not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// =============================================================================
// AlreadyDecided + empty-reason edge cases (AAASM-3805)
// =============================================================================

#[tokio::test]
async fn approve_action_returns_409_when_already_decided() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);
    let app = aa_api::server::build_app(state);

    // First approval succeeds.
    app.clone()
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

    // Second approval on the same id → 409 AlreadyDecided.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{id}/approve"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "bob"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("already been decided"));
}

#[tokio::test]
async fn reject_action_returns_400_for_whitespace_reason() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);
    let app = aa_api::server::build_app(state);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{id}/reject"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "alice", "reason": "   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["detail"].as_str().unwrap_or_default().contains("non-empty reason"));
}

#[tokio::test]
async fn reject_action_returns_409_when_already_decided() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);
    let app = aa_api::server::build_app(state);

    // Approve first.
    app.clone()
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

    // Now try to reject the already-approved request → 409.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/approvals/{id}/reject"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"by": "bob", "reason": "changed mind"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("already been decided"));
}

#[tokio::test]
async fn list_approvals_includes_routing_status_when_recorded() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);

    // Record routing metadata so pending_to_response surfaces routing_status.
    let recorded = state.approval_queue.record_routing(
        id,
        "routed".to_string(),
        Some("oncall".to_string()),
        Some(1_700_000_100),
        Some(1_700_000_900),
        Some(RoutingHistoryEntry {
            at: 1_700_000_100,
            action: "routed".to_string(),
            from_role: None,
            to_role: "oncall".to_string(),
        }),
    );
    assert!(recorded);

    let app = aa_api::server::build_app(state);
    let resp = app
        .oneshot(Request::builder().uri("/api/v1/approvals").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let item = &json["items"][0];
    assert_eq!(item["routing_status"]["status"], "routed");
    assert_eq!(item["routing_status"]["target_role"], "oncall");
    assert_eq!(item["routing_status"]["routed_at"], 1_700_000_100);
    assert_eq!(item["routing_status"]["escalate_at"], 1_700_000_900);
    let history = item["routing_status"]["history"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["action"], "routed");
    assert_eq!(history[0]["to_role"], "oncall");
}

#[tokio::test]
async fn get_approval_includes_routing_status_when_recorded() {
    let state = common::test_state();
    let req = make_approval_request(600);
    let id = req.request_id;
    let (_rid, _fut) = state.approval_queue.submit(req);

    state.approval_queue.record_routing(
        id,
        "escalated".to_string(),
        Some("manager".to_string()),
        None,
        None,
        Some(RoutingHistoryEntry {
            at: 1_700_000_200,
            action: "escalated".to_string(),
            from_role: Some("oncall".to_string()),
            to_role: "manager".to_string(),
        }),
    );

    let app = aa_api::server::build_app(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/approvals/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["routing_status"]["status"], "escalated");
    assert_eq!(json["routing_status"]["target_role"], "manager");
    let history = json["routing_status"]["history"].as_array().unwrap();
    assert_eq!(history[0]["from_role"], "oncall");
}

// ── AAASM-4104 — per-operation authz regression coverage ────────────────────
//
// The approval decision endpoints (approve, reject) gate the mutation behind the
// compile-time `RequireWrite` scope extractor, which runs before the handler
// body. These tests lock in that a read-scoped caller is rejected with 403 so a
// future refactor that drops the extractor is caught.

use aa_api::auth::scope::Scope;

#[tokio::test]
async fn approve_action_with_read_only_scope_is_forbidden() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/approvals/00000000-0000-0000-0000-000000000000/approve")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reject_action_with_read_only_scope_is_forbidden() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/approvals/00000000-0000-0000-0000-000000000000/reject")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
