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
    GovernanceAction::ToolCall { name: name.to_string(), args: String::new() }
}

fn load_inter_team_fixture(filename: &str) -> Arc<aa_gateway::policy::document::PolicyDocument> {
    let path = format!(
        "{}/tests/fixtures/policies/inter-team/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
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
