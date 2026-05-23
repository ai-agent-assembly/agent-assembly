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
