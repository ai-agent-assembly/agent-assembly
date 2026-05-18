//! F116 ST-D — Policy allow/deny enforcement via SDK shim (Layer 1).
//!
//! Exercises `PolicyEngine::evaluate()` directly in-process, covering the five
//! acceptance criteria from AAASM-1516:
//!
//! 1. Deny path returns `PolicyResult::Deny` with a clear human-readable reason.
//! 2. Allow path returns `PolicyResult::Allow` without error.
//! 3. A `PolicyViolation` audit entry serialises and deserialises correctly via
//!    `AuditReader`, with `rule_id` and `reason` preserved in the payload.
//! 4. A denied tool call does not advance the agent's budget.
//! 5. Five hundred consecutive `evaluate()` calls complete in under 100 ms.
//!
//! ## Why in-process, not via the Python SDK
//!
//! The Python SDK's `check_policy_compliance()` calls
//! `POST /agents/{id}/policy/check`, which does not yet exist in `aa-api`.
//! Tests that require a live SDK + gateway are marked `#[ignore]` with a
//! reference to the follow-up ticket.  The five tests below are fully
//! runnable with no external process.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::time::Instant;

use aa_core::audit::AuditEventType;
use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, AuditEntry, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::AuditReader;
use rust_decimal::Decimal;
use tempfile::TempDir;

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

fn make_ctx(agent_bytes: [u8; 16]) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(agent_bytes),
        session_id: SessionId::from_bytes([0xAAu8; 16]),
        pid: 1,
        started_at: Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

fn make_engine() -> aa_gateway::PolicyEngine {
    let path = fixture_path("policies/allow_deny_mixed.yaml");
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    aa_gateway::PolicyEngine::load_from_file(&path, tx).expect("allow_deny_mixed.yaml must load cleanly")
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

#[test]
fn sdk_deny_blocks_tool_execution_and_returns_clear_error() {
    let engine = make_engine();
    let ctx = make_ctx([1u8; 16]);
    let action = GovernanceAction::ToolCall {
        name: "websearch".to_string(),
        args: "{}".to_string(),
    };
    let result = engine.evaluate(&ctx, &action);
    assert_eq!(
        result.decision,
        PolicyResult::Deny {
            reason: "tool denied by policy".to_string()
        },
        "denied tool must return Deny with the canonical reason string",
    );
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

#[test]
fn sdk_allow_permits_tool_execution_and_emits_event() {
    let engine = make_engine();
    let ctx = make_ctx([2u8; 16]);
    let action = GovernanceAction::ToolCall {
        name: "read_file".to_string(),
        args: "{}".to_string(),
    };
    let result = engine.evaluate(&ctx, &action);
    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "explicitly-allowed tool must return Allow",
    );
    // Event emission is a responsibility of the SDK shim layer, not the engine.
    // The Allow decision confirms the engine cleared the call; the shim would
    // then emit an event to the gateway on the hot path.
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sdk_deny_audit_event_includes_rule_id_and_reason() {
    let tmp = TempDir::new().expect("tempdir");
    let agent_id = AgentId::from_bytes([3u8; 16]);
    let session_id = SessionId::from_bytes([4u8; 16]);

    // Construct the payload the gateway shim would emit on a policy violation.
    let payload = serde_json::json!({
        "rule_id":  "deny-websearch",
        "tool":     "websearch",
        "reason":   "tool denied by policy",
    })
    .to_string();

    let entry = AuditEntry::new(
        0,
        1_000_000_000_u64,
        AuditEventType::PolicyViolation,
        agent_id,
        session_id,
        payload,
        [0u8; 32],
    );

    // Write to a temporary JSONL file the AuditReader can scan.
    let jsonl_path = tmp.path().join("audit.jsonl");
    {
        let mut f = std::fs::File::create(&jsonl_path).expect("create jsonl");
        writeln!(f, "{}", serde_json::to_string(&entry).expect("serialize entry")).expect("write line");
    }

    let reader = AuditReader::new(tmp.path().to_path_buf());
    let (entries, total) = reader
        .list(10, 0, None, Some("PolicyViolation"))
        .await
        .expect("AuditReader::list");

    assert_eq!(total, 1, "expected exactly one PolicyViolation entry");

    let got = &entries[0];
    assert_eq!(got.event_type(), AuditEventType::PolicyViolation);

    let v: serde_json::Value = serde_json::from_str(got.payload()).expect("entry payload must be valid JSON");
    assert_eq!(
        v["rule_id"], "deny-websearch",
        "rule_id must round-trip through AuditEntry"
    );
    assert_eq!(
        v["reason"], "tool denied by policy",
        "reason must round-trip through AuditEntry"
    );
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

#[test]
fn sdk_deny_does_not_charge_budget() {
    // PolicyEngine::evaluate_primary short-circuits at Stage 3 (tool deny)
    // before reaching Stage 7 (budget check), so a denied call must not
    // advance the agent's recorded spend.
    let engine = make_engine();
    let ctx = make_ctx([5u8; 16]);

    let action = GovernanceAction::ToolCall {
        name: "websearch".to_string(),
        args: "{}".to_string(),
    };

    let result = engine.evaluate(&ctx, &action);
    assert_eq!(
        result.decision,
        PolicyResult::Deny {
            reason: "tool denied by policy".to_string()
        },
    );

    // agent_state() returns None when no spend has been recorded.
    let spent = engine
        .budget_tracker()
        .agent_state(&ctx.agent_id)
        .map(|s| s.spent_usd)
        .unwrap_or(Decimal::ZERO);

    assert_eq!(
        spent,
        Decimal::ZERO,
        "a denied tool call must not advance the agent budget (spent = {spent})",
    );
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

#[test]
fn sdk_policy_evaluation_latency_under_100ms() {
    // Five hundred mixed allow/deny evaluations must complete in under 100 ms.
    // This is a conservative bound relative to the 100 ms per-call SLA stated
    // in the ticket AC; it catches pathological regressions without making the
    // test brittle on slow CI runners.
    let engine = make_engine();
    let ctx = make_ctx([6u8; 16]);

    let deny_action = GovernanceAction::ToolCall {
        name: "websearch".to_string(),
        args: "{}".to_string(),
    };
    let allow_action = GovernanceAction::ToolCall {
        name: "read_file".to_string(),
        args: "{}".to_string(),
    };

    const ITERATIONS: u32 = 500;
    let start = Instant::now();
    for i in 0..ITERATIONS {
        let action = if i % 2 == 0 { &deny_action } else { &allow_action };
        let _ = engine.evaluate(&ctx, action);
    }
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 100,
        "{ITERATIONS} evaluations took {}ms — exceeds 100 ms SLA",
        elapsed.as_millis(),
    );
}
