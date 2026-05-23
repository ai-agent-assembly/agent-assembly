//! E2E acceptance sweep for the Human-in-the-loop approval gate
//! (AAASM-1571 / F116 ST-P).
//!
//! The five `e2e_hitl_*` tests drive the production [`ApprovalQueue`] and the
//! `/api/v1/approvals/*` REST surface together on a single
//! [`TopologyTestEnv`] instance. Each test spawns a background task that
//! submits an [`ApprovalRequest`] to the queue and awaits the returned
//! [`ApprovalFuture`] — exactly the wait that
//! `aa-gateway/src/service/policy_service.rs::maybe_submit_approval`
//! performs in production. The test body then drives the REST handlers
//! (`POST /approve`, `POST /reject`, `GET /approvals?status=…`) as the
//! "human approver" and asserts the resolved [`ApprovalDecision`] together
//! with the queue's [`ResolvedRecord`] book-keeping fields named in the
//! ticket AC (`agent_id`, `action`, `status`, `decided_by`, `decision_reason`).
//!
//! Lower-level coverage of the policy-engine → queue handshake lives in
//! `aa-gateway/tests/approval_flow_test.rs`; the REST surface in isolation
//! lives in `aa-integration-tests/tests/api_approvals.rs` and
//! `aa-api/tests/approvals.rs`. This file's value is the cohesive sweep.

mod common;

use std::time::Duration;

use aa_core::PolicyResult;
use aa_runtime::approval::{ApprovalDecision, ApprovalFuture, ApprovalRequest, ApprovalRequestId};
use common::TopologyTestEnv;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Build the [`ApprovalRequest`] that the production policy engine emits when
/// a rule's `requires_approval_if` condition matches a tool call. `tool_name`
/// is the agent-visible action label; `timeout_secs` is the per-request
/// expiry budget; `fallback` is the [`PolicyResult`] the queue applies on
/// timeout (carried through to `ApprovalDecision::TimedOut`).
#[allow(dead_code)]
fn make_pending_request(tool_name: &str, timeout_secs: u64, fallback: PolicyResult) -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "agent-st-p".to_string(),
        action: format!("tool.{tool_name}"),
        condition_triggered: "AAASM-1571 / F116 ST-P".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs,
        fallback,
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

/// Submit `request` to the queue and spawn a task that awaits its oneshot.
/// Returns the request id (for driving REST endpoints) and a [`JoinHandle`]
/// that resolves to the final [`ApprovalDecision`] once the queue produces
/// one — by REST `approve`, REST `reject`, or `timeout_secs` elapsing.
/// Mirrors the await in `policy_service.rs::maybe_submit_approval` before
/// the decision is mapped back to a [`PolicyResult`].
#[allow(dead_code)]
fn spawn_blocking_wait(
    env: &TopologyTestEnv,
    request: ApprovalRequest,
) -> (ApprovalRequestId, JoinHandle<ApprovalDecision>) {
    let (id, rx): (ApprovalRequestId, ApprovalFuture) = env.approval_queue.submit(request);
    let handle = tokio::spawn(async move { rx.await.expect("approval oneshot sender dropped") });
    (id, handle)
}

/// Maximum time a "blocking decision" task is given to resolve after the
/// triggering REST call (or timeout). Generous on slow CI hosts; tightens
/// the timeout-fallback tests' upper bound without making them flaky.
#[allow(dead_code)]
const RESOLVE_DEADLINE: Duration = Duration::from_secs(10);

// =============================================================================
// ST-P-1 — Happy path: human approves; the blocked waiter receives `Approved`.
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn e2e_hitl_approve_releases_blocked_waiter() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let request = make_pending_request(
        "send_email",
        30,
        PolicyResult::Deny {
            reason: "fallback-deny (unused on approve path)".to_string(),
        },
    );
    let (id, handle) = spawn_blocking_wait(&env, request);

    // Pending listing observes the request before any decision arrives.
    let pending: serde_json::Value = client
        .get(format!("{}/api/v1/approvals?status=pending", env.base_url()))
        .send()
        .await
        .expect("list pending succeeds")
        .json()
        .await
        .expect("pending body is JSON");
    assert_eq!(pending["total"], 1, "exactly one pending entry");
    assert_eq!(pending["items"][0]["id"], id.to_string());

    // The waiter has NOT resolved yet — confirm it stays pending until the
    // operator decides. 200 ms is generous; the queue only resolves on
    // `decide()` or timeout (30 s here, much later).
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!handle.is_finished(), "waiter must block until decide()");

    // Operator approves via REST.
    let resp = client
        .post(format!("{}/api/v1/approvals/{}/approve", env.base_url(), id))
        .json(&serde_json::json!({ "by": "ops-1", "reason": "approved by ST-P-1" }))
        .send()
        .await
        .expect("approve POST succeeds");
    assert_eq!(resp.status(), 200);

    // The blocked waiter resolves with `Approved` carrying the operator's
    // identity and reason — the exact handshake `policy_service.rs::
    // maybe_submit_approval` maps back to `PolicyResult::Allow`.
    let decision = tokio::time::timeout(RESOLVE_DEADLINE, handle)
        .await
        .expect("waiter resolves within deadline")
        .expect("waiter task did not panic");
    match decision {
        ApprovalDecision::Approved { by, reason } => {
            assert_eq!(by, "ops-1");
            assert_eq!(reason.as_deref(), Some("approved by ST-P-1"));
        }
        other => panic!("expected Approved, got {other:?}"),
    }

    // Resolved-history book-keeping carries the AC-mandated fields
    // (agent_id, action, status, decided_by, decision_reason).
    let resolved = env.approval_queue.list_resolved(Some("approved"), None);
    assert_eq!(resolved.len(), 1);
    let record = &resolved[0];
    assert_eq!(record.request_id, id);
    assert_eq!(record.agent_id, "agent-st-p");
    assert_eq!(record.action, "tool.send_email");
    assert_eq!(record.status, "approved");
    assert_eq!(record.decided_by, "ops-1");
    assert_eq!(record.decision_reason.as_deref(), Some("approved by ST-P-1"));
}

// =============================================================================
// ST-P-2 — Human rejects; the blocked waiter receives `Rejected` with reason.
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn e2e_hitl_reject_returns_deny_with_reason() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let request = make_pending_request(
        "send_email",
        30,
        PolicyResult::Deny {
            reason: "fallback-deny (unused on reject path)".to_string(),
        },
    );
    let (id, handle) = spawn_blocking_wait(&env, request);

    // Operator rejects with a mandatory non-empty reason.
    let resp = client
        .post(format!("{}/api/v1/approvals/{}/reject", env.base_url(), id))
        .json(&serde_json::json!({ "by": "ops-2", "reason": "not authorised" }))
        .send()
        .await
        .expect("reject POST succeeds");
    assert_eq!(resp.status(), 200);

    // The waiter resolves with `Rejected` carrying the operator's reason —
    // production maps this to `PolicyResult::Deny` so the tool does not run.
    let decision = tokio::time::timeout(RESOLVE_DEADLINE, handle)
        .await
        .expect("waiter resolves within deadline")
        .expect("waiter task did not panic");
    match decision {
        ApprovalDecision::Rejected { by, reason } => {
            assert_eq!(by, "ops-2");
            assert_eq!(reason, "not authorised");
        }
        other => panic!("expected Rejected, got {other:?}"),
    }

    let resolved = env.approval_queue.list_resolved(Some("rejected"), None);
    assert_eq!(resolved.len(), 1);
    let record = &resolved[0];
    assert_eq!(record.request_id, id);
    assert_eq!(record.action, "tool.send_email");
    assert_eq!(record.status, "rejected");
    assert_eq!(record.decided_by, "ops-2");
    assert_eq!(record.decision_reason.as_deref(), Some("not authorised"));
}
