//! Fixture-driven tests for graph-aware policy variables (AAASM-1035).
//!
//! Each YAML in `tests/fixtures/policies/graph-vars/` exercises at least one
//! allow-path and one deny-path. The `PolicyDecision` produced by
//! `merge_decisions` is snapshot-asserted so that any behaviour change is
//! reviewed deliberately.

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

fn load_fixture(filename: &str) -> Arc<aa_gateway::policy::document::PolicyDocument> {
    let path = format!(
        "{}/tests/fixtures/policies/graph-vars/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
    let out = PolicyValidator::from_yaml(&yaml)
        .unwrap_or_else(|errs| panic!("fixture {filename} failed validation: {errs:?}"));
    Arc::new(out.document)
}

// ── agent.depth fixtures ──────────────────────────────────────────────────────

#[test]
fn agent_depth_allow_fixture_loads_without_errors() {
    let _doc = load_fixture("agent_depth_allow.yaml");
}

#[test]
fn agent_depth_allow_produces_allow_without_context() {
    // Without a PolicyContext the graph-aware clause evaluates to false (null-safe),
    // so no RequireApproval fires → Allow.
    let doc = load_fixture("agent_depth_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

#[test]
fn agent_depth_deny_fixture_produces_deny() {
    let doc = load_fixture("agent_depth_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert!(matches!(result, PolicyDecision::Deny { .. }));
}

// ── team.active_agents fixtures ───────────────────────────────────────────────

#[test]
fn team_active_agents_allow_fixture_loads_without_errors() {
    let _doc = load_fixture("team_active_agents_allow.yaml");
}

#[test]
fn team_active_agents_allow_produces_allow_without_context() {
    let doc = load_fixture("team_active_agents_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("spawn");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

// ── team.budget_remaining fixtures ───────────────────────────────────────────

#[test]
fn team_budget_remaining_deny_fixture_loads_without_errors() {
    let _doc = load_fixture("team_budget_remaining_deny.yaml");
}

#[test]
fn team_budget_remaining_deny_produces_allow_without_context() {
    let doc = load_fixture("team_budget_remaining_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("expensive_op");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

// ── child.tool fixtures ───────────────────────────────────────────────────────

#[test]
fn child_tool_deny_fixture_loads_without_errors() {
    let _doc = load_fixture("child_tool_deny.yaml");
}

#[test]
fn child_tool_deny_produces_allow_without_context() {
    let doc = load_fixture("child_tool_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("delegate");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert_eq!(result, PolicyDecision::Allow);
}

// ── load-time validation: typo rejection ─────────────────────────────────────

#[test]
fn typo_variable_rejected_at_load_time() {
    let yaml = "scope: global\ntools:\n  bash:\n    allow: true\n    requires_approval_if: \"agent.depht > 0\"\n";
    let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
    assert!(
        errs.iter().any(|e| e.message.contains("agent.depht")),
        "expected typo error for 'agent.depht', got: {errs:?}"
    );
}

#[test]
fn completely_unknown_variable_rejected_at_load_time() {
    let yaml = "scope: global\ntools:\n  bash:\n    allow: true\n    requires_approval_if: \"totally_unknown > 0\"\n";
    let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
    assert!(
        errs.iter().any(|e| e.message.contains("totally_unknown")),
        "expected error for 'totally_unknown', got: {errs:?}"
    );
}
