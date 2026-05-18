//! Live-gateway HTTP integration tests for `/api/v1/approvals/*` (AAASM-1488 / F122 ST-G).
//!
//! Exercises the HITL approval workflow end-to-end via a real running
//! `TopologyTestEnv` and `reqwest` HTTP calls. State is seeded directly
//! through `env.approval_queue` — no mocking.
//!
//! Test matrix:
//! - List ×3: empty, pending-only default, agent filter
//! - Inspect ×2: full request shape, unknown id 404
//! - Approve ×3: happy path + state update, already-decided 409, unknown 404
//! - Reject ×3: with reason 200, without reason 400, after approve 409
//! - Expiry ×1: timed-out request appears in `?status=timed_out`

mod common;

use std::time::Duration;

use aa_core::PolicyResult;
use aa_runtime::approval::{ApprovalDecision, ApprovalRequest};
use common::TopologyTestEnv;
use uuid::Uuid;

fn make_approval(agent_id: &str, action: &str) -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: agent_id.to_string(),
        action: action.to_string(),
        condition_triggered: "f122-approvals-it".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 3600,
        fallback: PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

// =============================================================================
// List (3 tests)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_list_empty_returns_200_and_empty_array() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/approvals", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_list_pending_only_by_default() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let pending_req = make_approval("f122-approvals-it-list-pending", "tool.invoke");
    let pending_id = pending_req.request_id;
    env.approval_queue.submit(pending_req);

    // Seed a second request and approve it immediately so it leaves the pending queue.
    let approved_req = make_approval("f122-approvals-it-list-approved", "tool.invoke");
    let approved_id = approved_req.request_id;
    env.approval_queue.submit(approved_req);
    env.approval_queue
        .decide(
            approved_id,
            ApprovalDecision::Approved {
                by: "f122-approvals-it-approver".to_string(),
                reason: None,
            },
        )
        .expect("decide should succeed");

    let resp = client
        .get(format!("{}/api/v1/approvals", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 1, "default list must return only pending");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], pending_id.to_string());
    assert_eq!(items[0]["status"], "pending");
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_list_filter_by_agent() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req_a = make_approval("f122-approvals-it-alice", "tool.invoke");
    let id_a = req_a.request_id;
    env.approval_queue.submit(req_a);

    let req_b = make_approval("f122-approvals-it-bob", "tool.invoke");
    env.approval_queue.submit(req_b);

    let resp = client
        .get(format!(
            "{}/api/v1/approvals?agent=f122-approvals-it-alice",
            env.base_url()
        ))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 1, "agent filter must narrow to alice only");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items[0]["id"], id_a.to_string());
    assert_eq!(items[0]["agent_id"], "f122-approvals-it-alice");
}

// =============================================================================
// Inspect (2 tests)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_inspect_returns_full_request() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-inspect-agent", "sensitive.action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    let resp = client
        .get(format!("{}/api/v1/approvals/{id}", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["id"], id.to_string());
    assert_eq!(json["agent_id"], "f122-approvals-it-inspect-agent");
    assert_eq!(json["action"], "sensitive.action");
    assert_eq!(json["status"], "pending");
    assert!(
        !json["created_at"].as_str().unwrap_or("").is_empty(),
        "created_at must be present"
    );
    assert!(
        !json["expires_at"].as_str().unwrap_or("").is_empty(),
        "expires_at must be present for pending"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_inspect_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let fake_id = Uuid::new_v4();
    let resp = client
        .get(format!("{}/api/v1/approvals/{fake_id}", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 404);
}

// =============================================================================
// Approve (3 tests)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_approve_pending_returns_200_and_updates_state() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-approve-agent", "delete.action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    let resp = client
        .post(format!("{}/api/v1/approvals/{id}/approve", env.base_url()))
        .json(&serde_json::json!({"by": "f122-approvals-it-approver", "reason": "ok"}))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "approved");

    // Subsequent GET must show approved (moved from pending to resolved history).
    let inspect = client
        .get(format!("{}/api/v1/approvals/{id}", env.base_url()))
        .send()
        .await
        .expect("inspect request should succeed");
    assert_eq!(inspect.status(), 200);
    let inspect_json: serde_json::Value = inspect.json().await.unwrap();
    assert_eq!(inspect_json["status"], "approved");
    assert_eq!(inspect_json["id"], id.to_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_approve_already_decided_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-double-approve-agent", "action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    // Pre-approve via the queue directly (first decision).
    env.approval_queue
        .decide(
            id,
            ApprovalDecision::Approved {
                by: "f122-approvals-it-first".to_string(),
                reason: None,
            },
        )
        .expect("first decide should succeed");

    // Second approve attempt via HTTP must return 409 Conflict.
    let resp = client
        .post(format!("{}/api/v1/approvals/{id}/approve", env.base_url()))
        .json(&serde_json::json!({"by": "f122-approvals-it-second"}))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 409);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("already been decided"),
        "error body should mention current state: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_approve_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let fake_id = Uuid::new_v4();
    let resp = client
        .post(format!("{}/api/v1/approvals/{fake_id}/approve", env.base_url()))
        .json(&serde_json::json!({"by": "f122-approvals-it-approver"}))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 404);
}

// =============================================================================
// Reject (3 tests)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_with_reason_returns_200() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-reject-agent", "dangerous.action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    let resp = client
        .post(format!("{}/api/v1/approvals/{id}/reject", env.base_url()))
        .json(&serde_json::json!({"by": "f122-approvals-it-reviewer", "reason": "violates policy X"}))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "rejected");
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_without_reason_returns_400() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-reject-no-reason-agent", "action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    let resp = client
        .post(format!("{}/api/v1/approvals/{id}/reject", env.base_url()))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("reason"),
        "error body should mention missing reason: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_after_approve_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let req = make_approval("f122-approvals-it-reject-after-approve-agent", "action");
    let id = req.request_id;
    env.approval_queue.submit(req);

    let approve_resp = client
        .post(format!("{}/api/v1/approvals/{id}/approve", env.base_url()))
        .json(&serde_json::json!({"by": "f122-approvals-it-approver"}))
        .send()
        .await
        .expect("approve request should succeed");
    assert_eq!(approve_resp.status(), 200);

    // Reject after approve is a terminal-state violation — must return 409.
    let reject_resp = client
        .post(format!("{}/api/v1/approvals/{id}/reject", env.base_url()))
        .json(&serde_json::json!({"reason": "changed mind"}))
        .send()
        .await
        .expect("reject request should succeed");

    assert_eq!(reject_resp.status(), 409);
}

// =============================================================================
// Expiry (1 test)
// =============================================================================

// Seeds a request with a 1-second timeout, waits 1.5 s for the ApprovalQueue's
// internal tokio timer to fire, then asserts the request appears under
// `?status=timed_out`. The 50 ms ordering sleep mentioned in the subtask is
// absorbed into the 1.5 s wait here; no additional sleep needed.
#[tokio::test(flavor = "multi_thread")]
async fn approvals_expired_request_listed_with_status_timed_out() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let mut req = make_approval("f122-approvals-it-expiry-agent", "expire.action");
    req.timeout_secs = 1;
    let id = req.request_id;
    env.approval_queue.submit(req);

    tokio::time::sleep(Duration::from_millis(1500)).await;

    let resp = client
        .get(format!("{}/api/v1/approvals?status=timed_out", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(
        json["total"].as_u64().unwrap_or(0) >= 1,
        "timed_out list should contain at least one entry"
    );
    let items = json["items"].as_array().unwrap();
    let found = items.iter().any(|item| item["id"] == id.to_string());
    assert!(found, "expired request {id} must appear in timed_out list");
}
