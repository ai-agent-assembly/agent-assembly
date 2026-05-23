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

// =============================================================================
// ST-P-3 — Timeout fallback `Deny`: no human action, waiter receives `TimedOut`
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn e2e_hitl_timeout_with_deny_fallback() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let fallback_reason = "fallback-deny on timeout".to_string();
    let request = make_pending_request(
        "deploy_prod",
        2,
        PolicyResult::Deny {
            reason: fallback_reason.clone(),
        },
    );
    let (id, handle) = spawn_blocking_wait(&env, request);

    // No human action — the queue's internal timeout spawner resolves the
    // waiter to `TimedOut` after `timeout_secs`. RESOLVE_DEADLINE > 2 s.
    let decision = tokio::time::timeout(RESOLVE_DEADLINE, handle)
        .await
        .expect("timeout fires within deadline")
        .expect("waiter task did not panic");
    match decision {
        ApprovalDecision::TimedOut { fallback } => match fallback {
            PolicyResult::Deny { reason } => assert_eq!(reason, fallback_reason),
            other => panic!("expected Deny fallback, got {other:?}"),
        },
        other => panic!("expected TimedOut, got {other:?}"),
    }

    // Resolved-history records the timeout with operator id `"timeout"`
    // (the sentinel the queue stamps for auto-expiry).
    let resolved = env.approval_queue.list_resolved(Some("timed_out"), None);
    assert_eq!(resolved.len(), 1);
    let record = &resolved[0];
    assert_eq!(record.request_id, id);
    assert_eq!(record.action, "tool.deploy_prod");
    assert_eq!(record.status, "timed_out");
    assert_eq!(record.decided_by, "timeout");
}

// =============================================================================
// ST-P-4 — Timeout fallback `Allow`: no human action, waiter receives `TimedOut`
//          carrying an Allow fallback (the genuinely uncovered scenario; the
//          other approval tests in this workspace only exercise Deny fallback).
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn e2e_hitl_timeout_with_allow_fallback() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let request = make_pending_request("send_marketing_email", 2, PolicyResult::Allow);
    let (id, handle) = spawn_blocking_wait(&env, request);

    // No human action — the queue resolves to `TimedOut { fallback: Allow }`
    // after ~2 s. Production maps this to `PolicyResult::Allow` so the
    // agent proceeds with the action (timeout_action: approve semantics).
    let decision = tokio::time::timeout(RESOLVE_DEADLINE, handle)
        .await
        .expect("timeout fires within deadline")
        .expect("waiter task did not panic");
    match decision {
        ApprovalDecision::TimedOut { fallback } => {
            assert!(
                matches!(fallback, PolicyResult::Allow),
                "fallback must be Allow, got {fallback:?}"
            );
        }
        other => panic!("expected TimedOut, got {other:?}"),
    }

    let resolved = env.approval_queue.list_resolved(Some("timed_out"), None);
    assert_eq!(resolved.len(), 1);
    let record = &resolved[0];
    assert_eq!(record.request_id, id);
    assert_eq!(record.action, "tool.send_marketing_email");
    assert_eq!(record.status, "timed_out");
    assert_eq!(record.decided_by, "timeout");
}

// =============================================================================
// ST-P-5 — REST list transitions: pending entry → approved entry after decide.
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn e2e_hitl_list_transitions_pending_to_approved() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let request = make_pending_request(
        "wire_transfer",
        60,
        PolicyResult::Deny {
            reason: "fallback unused".to_string(),
        },
    );
    let (id, _handle) = spawn_blocking_wait(&env, request);

    // Before any decision: the pending list returns the new entry.
    let pending: serde_json::Value = client
        .get(format!("{}/api/v1/approvals?status=pending", env.base_url()))
        .send()
        .await
        .expect("list pending succeeds")
        .json()
        .await
        .expect("pending body is JSON");
    assert_eq!(pending["total"], 1, "one pending entry before approve");
    assert_eq!(pending["items"][0]["id"], id.to_string());
    assert_eq!(pending["items"][0]["agent_id"], "agent-st-p");
    assert_eq!(pending["items"][0]["action"], "tool.wire_transfer");

    // Approved list is empty before the decision.
    let approved_empty: serde_json::Value = client
        .get(format!("{}/api/v1/approvals?status=approved", env.base_url()))
        .send()
        .await
        .expect("list approved succeeds")
        .json()
        .await
        .expect("approved body is JSON");
    assert_eq!(approved_empty["total"], 0, "no approved entries before decide");

    // Operator approves.
    let approve_resp = client
        .post(format!("{}/api/v1/approvals/{}/approve", env.base_url(), id))
        .json(&serde_json::json!({ "by": "ops-5", "reason": "transfer pre-authorised" }))
        .send()
        .await
        .expect("approve POST succeeds");
    assert_eq!(approve_resp.status(), 200);

    // After decision: pending list is empty …
    let pending_after: serde_json::Value = client
        .get(format!("{}/api/v1/approvals?status=pending", env.base_url()))
        .send()
        .await
        .expect("list pending after decide succeeds")
        .json()
        .await
        .expect("pending body is JSON");
    assert_eq!(pending_after["total"], 0, "no pending entries after approve");

    // … and the same id now appears under `?status=approved`, satisfying the
    // ticket AC: "After approval, entry moves to `approved` status in the list".
    let approved_after: serde_json::Value = client
        .get(format!("{}/api/v1/approvals?status=approved", env.base_url()))
        .send()
        .await
        .expect("list approved after decide succeeds")
        .json()
        .await
        .expect("approved body is JSON");
    assert_eq!(approved_after["total"], 1, "one approved entry after decide");
    assert_eq!(approved_after["items"][0]["id"], id.to_string());
}

// =============================================================================
// External fixture: long-running test that boots a real gateway and idles.
// Invoked by `dashboard/tests/e2e/global-setup.ts` to give the Playwright
// spec (`hitl-approval.spec.ts`) a live `/api/v1/approvals/*` surface to
// proxy through `page.route()`. Marked `#[ignore]` so `cargo nextest run`
// skips it by default; runs only via `--run-ignored only` or `-- --ignored`.
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore = "long-running fixture spawned by the Playwright globalSetup; idles until killed"]
async fn e2e_fixture_main() {
    use std::io::Write;

    let env = TopologyTestEnv::start().await.expect("fixture: harness should start");

    // Seed two pending approvals so the Playwright spec can both observe
    // a row and approve one to assert the transition.
    let long_timeout = 3600_u64;
    let _ = env.approval_queue.submit(make_pending_request(
        "send_email",
        long_timeout,
        PolicyResult::Deny {
            reason: "fallback unused".to_string(),
        },
    ));
    let _ = env.approval_queue.submit(make_pending_request(
        "wire_transfer",
        long_timeout,
        PolicyResult::Deny {
            reason: "fallback unused".to_string(),
        },
    ));

    // Single READY line on stdout, flushed immediately, so the Node-side
    // globalSetup can parse the URL via the spawned child's stdout pipe.
    println!("READY {}", env.base_url());
    std::io::stdout().flush().expect("flush stdout");

    // Idle until killed (Playwright globalSetup terminates this process at
    // teardown). Production graceful shutdown is unneeded — the harness's
    // `Drop` impl tears down the axum task on process exit.
    tokio::signal::ctrl_c().await.expect("listen for SIGINT");
}
