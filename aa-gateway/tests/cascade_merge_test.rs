//! Integration tests for merge_decisions most-restrictive-wins semantics (AAASM-961).

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::decision::{merge_decisions, PolicyDecision};
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;

fn allow_doc(scope: PolicyScope) -> Arc<PolicyDocument> {
    Arc::new(PolicyDocument {
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
    })
}

fn deny_tool_doc(scope: PolicyScope, tool_name: &str) -> Arc<PolicyDocument> {
    use aa_gateway::policy::document::ToolPolicy;
    let mut tools = HashMap::new();
    tools.insert(
        tool_name.to_string(),
        ToolPolicy {
            allow: false,
            requires_approval_if: None,
            limit_per_hour: None,
        },
    );
    Arc::new(PolicyDocument {
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
        tools,
        capabilities: None,
    })
}

fn approval_tool_doc(scope: PolicyScope, tool_name: &str, timeout: u32) -> Arc<PolicyDocument> {
    use aa_gateway::policy::document::ToolPolicy;
    let mut tools = HashMap::new();
    tools.insert(
        tool_name.to_string(),
        ToolPolicy {
            allow: true,
            requires_approval_if: Some("true".to_string()),
            limit_per_hour: None,
        },
    );
    Arc::new(PolicyDocument {
        name: None,
        policy_version: None,
        version: None,
        scope,
        network: None,
        schedule: None,
        budget: None,
        data: None,
        approval_timeout_secs: timeout,
        approval_policy: None,
        tools,
        capabilities: None,
    })
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

// 1. Empty cascade returns fail-closed Deny.
#[test]
fn empty_cascade_is_deny_fail_closed() {
    let ctx = make_ctx();
    let action = tool_action("bash");
    let result = merge_decisions(&[], &ctx, &action);
    assert!(
        matches!(result, PolicyDecision::Deny { .. }),
        "empty cascade must be fail-closed Deny"
    );
}

// 2. Single Allow doc returns Allow.
#[test]
fn single_allow_doc_returns_allow() {
    let ctx = make_ctx();
    let action = tool_action("bash");
    let cascade = vec![allow_doc(PolicyScope::Global)];
    let result = merge_decisions(&cascade, &ctx, &action);
    assert_eq!(result, PolicyDecision::Allow);
}

// 3. Deny in any scope short-circuits and wins over Allow docs.
#[test]
fn deny_in_any_scope_wins_over_allow() {
    let ctx = make_ctx();
    let action = tool_action("bash");
    let cascade = vec![
        allow_doc(PolicyScope::Global),
        deny_tool_doc(PolicyScope::Org("acme".into()), "bash"),
        allow_doc(PolicyScope::Agent(AgentId::from_bytes([1u8; 16]))),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    assert!(
        matches!(result, PolicyDecision::Deny { .. }),
        "Deny must win over Allow"
    );
}

// 4. RequireApproval upgrades Allow; most-specific (narrowest) scope wins.
#[test]
fn require_approval_most_specific_scope_wins() {
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let cascade = vec![
        allow_doc(PolicyScope::Global),
        approval_tool_doc(PolicyScope::Org("acme".into()), "deploy", 600),
        approval_tool_doc(PolicyScope::Team("platform".into()), "deploy", 120),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    match result {
        PolicyDecision::RequireApproval { timeout_secs, .. } => {
            assert_eq!(
                timeout_secs, 120,
                "most-specific RequireApproval (Team scope, 120s) must win over broader scope"
            );
        }
        other => panic!("expected RequireApproval, got {other:?}"),
    }
}

// 5. Deny overrides RequireApproval — most restrictive wins.
#[test]
fn deny_overrides_require_approval() {
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let cascade = vec![
        allow_doc(PolicyScope::Global),
        approval_tool_doc(PolicyScope::Org("acme".into()), "deploy", 300),
        deny_tool_doc(PolicyScope::Team("platform".into()), "deploy"),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    assert!(
        matches!(result, PolicyDecision::Deny { .. }),
        "Deny must beat RequireApproval"
    );
}

// 6. source_scope on Deny identifies which scope produced the verdict.
// AC: "Global allow + Team deny -> Deny(source_scope=Team)"
#[test]
fn deny_source_scope_identifies_denying_scope() {
    let ctx = make_ctx();
    let action = tool_action("bash");
    let cascade = vec![
        allow_doc(PolicyScope::Global),
        deny_tool_doc(PolicyScope::Team("platform".into()), "bash"),
        allow_doc(PolicyScope::Agent(AgentId::from_bytes([1u8; 16]))),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    match result {
        PolicyDecision::Deny { source_scope, .. } => {
            assert_eq!(
                source_scope,
                PolicyScope::Team("platform".into()),
                "source_scope must identify the Team scope that produced the Deny"
            );
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

// 7. Agent-level Allow must not override a broader-scope RequireApproval.
// AC: "Org require_approval + Agent allow → RequireApproval"
#[test]
fn agent_allow_does_not_override_org_require_approval() {
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let cascade = vec![
        allow_doc(PolicyScope::Global),
        approval_tool_doc(PolicyScope::Org("acme".into()), "deploy", 300),
        allow_doc(PolicyScope::Agent(AgentId::from_bytes([1u8; 16]))),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    assert!(
        matches!(result, PolicyDecision::RequireApproval { .. }),
        "Agent Allow must not downgrade Org's RequireApproval; got {result:?}"
    );
}

// 8. Deny at Global scope short-circuits regardless of Agent-level Allow.
// AC: "Deny at Global beats Allow at Agent"
#[test]
fn deny_at_global_beats_allow_at_agent() {
    let ctx = make_ctx();
    let action = tool_action("bash");
    let cascade = vec![
        deny_tool_doc(PolicyScope::Global, "bash"),
        allow_doc(PolicyScope::Agent(AgentId::from_bytes([1u8; 16]))),
    ];
    let result = merge_decisions(&cascade, &ctx, &action);
    assert!(
        matches!(result, PolicyDecision::Deny { .. }),
        "Global Deny must win over Agent Allow; got {result:?}"
    );
}
