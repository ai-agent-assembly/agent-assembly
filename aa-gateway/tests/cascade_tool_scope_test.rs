//! Regression tests for AAASM-3981: `scope: tool:<name>` policies must actually
//! be evaluated.
//!
//! Before the fix the cascade builder walked only Global → Org → Team → Agent
//! and never appended the Tool tier, so a `scope: tool:X` deny loaded, validated,
//! and index-loaded cleanly yet was never consulted — a fail-open by omission
//! that left the tool allowed. These tests exercise the full
//! `load_policy` → `evaluate` path and assert the Tool tier is now consulted at
//! the most-restrictive end of the cascade (after Agent).

use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::{PolicyDocument, ToolPolicy};
use aa_gateway::policy::scope::PolicyScope;

const AGENT_BYTES: [u8; 16] = [1u8; 16];

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

fn make_ctx() -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(AGENT_BYTES),
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

/// A policy with no sections — allows every action.
fn empty_doc(scope: PolicyScope) -> PolicyDocument {
    PolicyDocument {
        name: None,
        policy_version: None,
        version: None,
        scope,
        network: None,
        schedule: None,
        budget: None,
        data: None,
        approval_timeout_secs: 300,
        approval_policy: None,
        tools: HashMap::new(),
        capabilities: None,
    }
}

/// A policy carrying a single per-tool `allow` decision for `tool`.
fn tool_doc(scope: PolicyScope, tool: &str, allow: bool) -> PolicyDocument {
    let mut tools = HashMap::new();
    tools.insert(
        tool.to_string(),
        ToolPolicy {
            allow,
            limit_per_hour: None,
            requires_approval_if: None,
        },
    );
    PolicyDocument {
        tools,
        ..empty_doc(scope)
    }
}

fn tool_call(name: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: name.to_string(),
        args: String::new(),
    }
}

/// A `scope: tool:slack-mcp` deny must block a `slack-mcp` call for an agent that
/// the broader (Global) policy would otherwise allow. This is the core
/// regression: before the fix the Tool tier was never in the cascade.
#[test]
fn tool_scoped_deny_blocks_matching_tool_call() {
    let mut engine = make_engine();
    engine.load_policy(empty_doc(PolicyScope::Global)); // allow-all baseline
    engine.load_policy(tool_doc(PolicyScope::Tool("slack-mcp".into()), "slack-mcp", false));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("slack-mcp")).decision;

    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "tool-scoped deny must block the matching tool call, got {result:?}"
    );
}

/// Without the tool-scoped deny loaded, the same call is allowed — proving the
/// baseline is permissive and the deny above is what does the blocking.
#[test]
fn tool_call_allowed_without_tool_scoped_deny() {
    let mut engine = make_engine();
    engine.load_policy(empty_doc(PolicyScope::Global));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("slack-mcp")).decision;

    assert_eq!(
        result,
        PolicyResult::Allow,
        "baseline global policy allows the tool call"
    );
}

/// A `scope: tool:slack-mcp` deny must not affect calls to a different tool: the
/// Tool tier is keyed by the action's own tool name.
#[test]
fn tool_scoped_deny_does_not_affect_other_tools() {
    let mut engine = make_engine();
    engine.load_policy(empty_doc(PolicyScope::Global));
    engine.load_policy(tool_doc(PolicyScope::Tool("slack-mcp".into()), "slack-mcp", false));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("github-mcp")).decision;

    assert_eq!(
        result,
        PolicyResult::Allow,
        "tool-scoped deny for slack-mcp must not affect github-mcp"
    );
}

/// The Tool tier is appended at the most-restrictive end (after Agent): a
/// `scope: tool:slack-mcp` deny overrides an explicit Agent-scoped allow for the
/// same tool.
#[test]
fn tool_scoped_deny_overrides_agent_scoped_allow() {
    let mut engine = make_engine();
    engine.load_policy(tool_doc(
        PolicyScope::Agent(AgentId::from_bytes(AGENT_BYTES)),
        "slack-mcp",
        true,
    ));
    engine.load_policy(tool_doc(PolicyScope::Tool("slack-mcp".into()), "slack-mcp", false));

    let ctx = make_ctx();
    let result = engine.evaluate(&ctx, &tool_call("slack-mcp")).decision;

    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "tool tier is most-restrictive: its deny must override an agent-scoped allow, got {result:?}"
    );
}

/// An action with no resolvable tool (e.g. a network request) skips the Tool
/// tier rather than fabricating one — a loaded tool-scoped deny leaves it
/// unaffected.
#[test]
fn non_tool_action_skips_tool_tier() {
    let mut engine = make_engine();
    engine.load_policy(empty_doc(PolicyScope::Global));
    engine.load_policy(tool_doc(PolicyScope::Tool("slack-mcp".into()), "slack-mcp", false));

    let ctx = make_ctx();
    let action = GovernanceAction::NetworkRequest {
        url: "https://example.com".into(),
        method: "GET".into(),
    };
    let result = engine.evaluate(&ctx, &action).decision;

    assert_eq!(
        result,
        PolicyResult::Allow,
        "a non-tool action derives no tool name and must skip the tool tier"
    );
}
