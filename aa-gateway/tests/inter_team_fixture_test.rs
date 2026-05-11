//! Fixture-driven tests for inter-team message channel condition variables (AAASM-1017).
//!
//! Each YAML in `tests/fixtures/policies/inter-team/` exercises the load-time
//! validation path (expression accepted) and the end-to-end null-safety path
//! (non-SendMessage action resolves to false → Allow).

use std::collections::BTreeMap;
use std::sync::Arc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::decision::{merge_decisions, PolicyDecision};
use aa_gateway::policy::validator::PolicyValidator;

fn send_message_action(src: &str, tgt: &str, ch: &str) -> GovernanceAction {
    GovernanceAction::SendMessage {
        source_team_id: Some(src.to_string()),
        target_team_id: Some(tgt.to_string()),
        channel_id: Some(ch.to_string()),
    }
}

fn make_ctx() -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([1u8; 16]),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
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

fn tool_action(name: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: name.to_string(),
        args: String::new(),
    }
}

fn load_inter_team_fixture(filename: &str) -> Arc<aa_gateway::policy::document::PolicyDocument> {
    let path = format!(
        "{}/tests/fixtures/policies/inter-team/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let out = PolicyValidator::from_yaml(&yaml)
        .unwrap_or_else(|errs| panic!("fixture {filename} failed validation: {errs:?}"));
    Arc::new(out.document)
}

// ── cross_team_deny fixture ───────────────────────────────────────────────────

#[test]
fn cross_team_deny_fixture_loads_without_errors() {
    let _doc = load_inter_team_fixture("cross_team_deny.yaml");
}

#[test]
fn cross_team_deny_produces_allow_for_non_message_action() {
    // A ToolCall action is not a SendMessage; target.team_id resolves to None
    // (null-safe no-match) so no approval fires → Allow.
    let doc = load_inter_team_fixture("cross_team_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("message");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

// ── same_team_allow fixture ───────────────────────────────────────────────────

#[test]
fn same_team_allow_fixture_loads_without_errors() {
    let _doc = load_inter_team_fixture("same_team_allow.yaml");
}

#[test]
fn same_team_allow_produces_allow_for_non_message_action() {
    // A ToolCall action is not a SendMessage; target.team_id resolves to None
    // (null-safe no-match) so no approval fires → Allow.
    let doc = load_inter_team_fixture("same_team_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("message");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

#[test]
fn same_team_send_message_produces_allow() {
    // target.team_id == "team-alpha" → expression "target.team_id != \"team-alpha\""
    // evaluates to false → Stage 5b does not fire → Allow.
    let doc = load_inter_team_fixture("same_team_allow.yaml");
    let ctx = make_ctx();
    let action = send_message_action("team-alpha", "team-alpha", "ops");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

#[test]
fn cross_team_send_message_requires_approval() {
    // target.team_id == "team-beta" → expression "target.team_id != \"team-alpha\""
    // evaluates to true → Stage 5b fires → RequireApproval.
    let doc = load_inter_team_fixture("same_team_allow.yaml");
    let ctx = make_ctx();
    let action = send_message_action("team-alpha", "team-beta", "ops");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert!(
        matches!(result, PolicyDecision::RequireApproval { .. }),
        "expected RequireApproval, got {result:?}"
    );
}

// ── allowed_channel_in fixture (in / not_in operator) ────────────────────────

#[test]
fn allowed_channel_in_fixture_loads_without_errors() {
    let _doc = load_inter_team_fixture("allowed_channel_in.yaml");
}

#[test]
fn allowed_channel_in_list_produces_allow_for_send_message_action() {
    // "ops" is in ["ops", "general"], so the not_in expression returns false →
    // Stage 5b approval gate does not fire → Allow.
    let doc = load_inter_team_fixture("allowed_channel_in.yaml");
    let ctx = make_ctx();
    let action = send_message_action("team-alpha", "team-beta", "ops");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

#[test]
fn allowed_channel_in_produces_allow_for_non_message_action() {
    // A ToolCall is not a SendMessage; target.channel_id resolves to None (null-safe
    // no-match) so not_in returns false → approval not triggered → Allow.
    let doc = load_inter_team_fixture("allowed_channel_in.yaml");
    let ctx = make_ctx();
    let action = tool_action("message");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

#[test]
fn disallowed_channel_triggers_approval_via_message_router() {
    use aa_core::AuditEventType;
    use aa_gateway::message_router::MessageRouter;

    let doc = load_inter_team_fixture("allowed_channel_in.yaml");
    let ctx = make_ctx();
    // "private" not in ["ops", "general"] → expression true → RequireApproval
    let action = send_message_action("team-alpha", "team-beta", "private");

    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(8);
    let router = MessageRouter::new().with_audit_tx(audit_tx);

    let decision = merge_decisions(&[doc], &ctx, &action, None);
    let result = router.enforce(decision, ctx.agent_id, &action);

    assert!(result.is_err(), "disallowed channel should be blocked");
    let entry = audit_rx.try_recv().expect("MessageBlocked audit entry expected");
    assert_eq!(entry.event_type(), AuditEventType::MessageBlocked);
    assert!(entry.payload().contains("cross_team_unallowed_channel"));
    assert!(entry.payload().contains("private"));
    assert!(entry.payload().contains("team-alpha"));
    assert!(entry.payload().contains("team-beta"));
}

// ── load-time validation: typo rejection ─────────────────────────────────────

#[test]
fn typo_in_source_team_id_rejected_at_load_time() {
    let yaml = "scope: global\ntools:\n  message:\n    allow: true\n    requires_approval_if: \"source.team_d == \\\"team-alpha\\\"\"\n";
    let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
    assert!(
        errs.iter().any(|e| e.message.contains("source.team_d")),
        "expected typo error for 'source.team_d', got: {errs:?}"
    );
}
