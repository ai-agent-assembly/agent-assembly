//! Integration tests for per-level capability policy restrictions (AAASM-226 / AAASM-1126).
//!
//! These tests exercise the full path from YAML → `PolicyValidator` →
//! `PolicyEngine::load_policy` → `PolicyEngine::evaluate`, verifying that
//! capability allow/deny sets are correctly enforced across the cascade.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, Capability, CapabilitySet, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::policy::PolicyValidator;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
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

fn cap_doc(scope: PolicyScope, allow: &[Capability], deny: &[Capability]) -> PolicyDocument {
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
        capabilities: Some(CapabilitySet {
            allow: allow.iter().cloned().collect::<BTreeSet<_>>(),
            deny: deny.iter().cloned().collect::<BTreeSet<_>>(),
        }),
    }
}

fn no_cap_doc(scope: PolicyScope) -> PolicyDocument {
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

// ── Test 1 ────────────────────────────────────────────────────────────────────

/// Parse the canonical capability YAML fixture and verify the round-trip through
/// `PolicyValidator`. Ensures the envelope format, allow list, deny list, and
/// named MCP tool capabilities are all correctly parsed.
#[test]
fn capability_policy_yaml_round_trip_via_validator() {
    let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: capability-example
  version: "1.0.0"
spec:
  scope: global
  capabilities:
    allow:
      - file_read
      - network_outbound
      - mcp_tool:git
      - mcp_tool:bash
    deny:
      - terminal_exec
      - file_write
"#;

    let output = PolicyValidator::from_yaml(yaml);
    assert!(output.is_ok(), "expected Ok, got: {:?}", output.err());

    let doc = output.unwrap().document;
    let caps = doc.capabilities.as_ref().expect("capabilities must be Some");

    assert!(caps.allow.contains(&Capability::FileRead));
    assert!(caps.allow.contains(&Capability::NetworkOutbound));
    assert!(caps.allow.contains(&Capability::McpTool("git".to_string())));
    assert!(caps.allow.contains(&Capability::McpTool("bash".to_string())));
    assert!(caps.deny.contains(&Capability::TerminalExec));
    assert!(caps.deny.contains(&Capability::FileWrite));
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

/// Two-policy cascade (Global: allow=[file_read]; Team: allow=[file_read], deny=[file_write])
/// must deny a `FileAccess(Write)` action because `FileWrite` is explicitly denied at the
/// team scope.
#[test]
fn full_cascade_capability_policy_denies_disallowed_file_write() {
    let mut engine = make_engine();
    // Global policy: allow file_read only
    engine.load_policy(cap_doc(PolicyScope::Global, &[Capability::FileRead], &[]));
    // Team policy: allow file_read, deny file_write
    engine.load_policy(cap_doc(
        PolicyScope::Team("alpha".to_string()),
        &[Capability::FileRead],
        &[Capability::FileWrite],
    ));

    let ctx = make_ctx();
    let action = GovernanceAction::FileAccess {
        path: "/tmp/secret.txt".into(),
        mode: aa_core::FileMode::Write,
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "expected Deny for FileWrite denied in two-policy cascade, got {:?}",
        result
    );
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

/// Two-policy cascade (Global: allow=[file_read]; Team: allow=[file_read], deny=[file_write])
/// must allow a `FileAccess(Read)` action because `FileRead` is in the allow set at both
/// scopes and is not denied anywhere.
#[test]
fn full_cascade_capability_policy_allows_permitted_file_read() {
    let mut engine = make_engine();
    // Global policy: allow file_read only
    engine.load_policy(cap_doc(PolicyScope::Global, &[Capability::FileRead], &[]));
    // Team policy: allow file_read, deny file_write
    engine.load_policy(cap_doc(
        PolicyScope::Team("alpha".to_string()),
        &[Capability::FileRead],
        &[Capability::FileWrite],
    ));

    let ctx = make_ctx();
    let action = GovernanceAction::FileAccess {
        path: "/tmp/readme.txt".into(),
        mode: aa_core::FileMode::Read,
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert_eq!(
        result,
        PolicyResult::Allow,
        "expected Allow for FileRead in two-policy cascade allow set, got {:?}",
        result
    );
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

/// A Global-scoped policy with `capabilities.allow = {FileRead}` only must deny
/// a `FileAccess(Write)` action because `FileWrite` is not in the allow list.
#[test]
fn full_cascade_capability_denies_file_write_when_not_in_allow_set() {
    let mut engine = make_engine();
    engine.load_policy(cap_doc(PolicyScope::Global, &[Capability::FileRead], &[]));

    let ctx = make_ctx();
    let action = GovernanceAction::FileAccess {
        path: "/tmp/data.txt".into(),
        mode: aa_core::FileMode::Write,
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "expected Deny for FileWrite not in allow set, got {:?}",
        result
    );
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

/// Two cascade policies with `capabilities: None` must not block any action
/// through the capability guard. The evaluation result must be `Allow` when no
/// other policy section (tool deny, budget, etc.) restricts the action.
#[test]
fn cascade_empty_capabilities_does_not_block_any_action() {
    let mut engine = make_engine();
    engine.load_policy(no_cap_doc(PolicyScope::Global));
    let agent_id = AgentId::from_bytes([1u8; 16]);
    engine.load_policy(no_cap_doc(PolicyScope::Agent(agent_id)));

    // agent_id matches the policy scope above — make_ctx() also uses [1u8; 16]
    let ctx = make_ctx();
    let action = GovernanceAction::FileAccess {
        path: "/tmp/file.txt".into(),
        mode: aa_core::FileMode::Write,
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert_eq!(
        result,
        PolicyResult::Allow,
        "expected Allow when no capabilities are configured, got {:?}",
        result
    );
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

/// A Global-level deny must override an agent-level allow for the same capability.
///
/// Setup:
/// - Global policy: `capabilities.deny = {TerminalExec}`
/// - Agent-scoped policy: `capabilities.allow = {TerminalExec, FileRead}`
///
/// Expected: `ProcessExec` is denied because parent deny wins.
#[test]
fn parent_deny_overrides_child_allow_in_full_cascade() {
    let agent_id = AgentId::from_bytes([1u8; 16]);

    let mut engine = make_engine();
    engine.load_policy(cap_doc(PolicyScope::Global, &[], &[Capability::TerminalExec]));
    engine.load_policy(cap_doc(
        PolicyScope::Agent(agent_id),
        &[Capability::TerminalExec, Capability::FileRead],
        &[],
    ));

    let ctx = make_ctx();
    let action = GovernanceAction::ProcessExec { command: "ls".into() };

    let result = engine.evaluate(&ctx, &action).decision;
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "expected Deny: global deny of TerminalExec must override agent allow, got {:?}",
        result
    );
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

/// A `capabilities.deny = {McpTool("bash")}` policy must deny a `ToolCall` for
/// the "bash" tool through the full evaluation path.
#[test]
fn mcp_tool_capability_denied_blocks_tool_call() {
    let mut engine = make_engine();
    engine.load_policy(cap_doc(
        PolicyScope::Global,
        &[],
        &[Capability::McpTool("bash".to_string())],
    ));

    let ctx = make_ctx();
    let action = GovernanceAction::ToolCall {
        name: "bash".into(),
        args: "{}".into(),
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert!(
        matches!(result, PolicyResult::Deny { .. }),
        "expected Deny: McpTool(bash) denied by capability policy, got {:?}",
        result
    );
}

// ── Test 8 ────────────────────────────────────────────────────────────────────

/// A `capabilities.allow = {McpTool("git")}` policy (no deny entries) must deny
/// a `ToolCall` for "bash" (not in allowlist) and allow a `ToolCall` for "git"
/// (in allowlist).
#[test]
fn mcp_tool_capability_allowlist_permits_only_listed_tools() {
    let mut engine = make_engine();
    engine.load_policy(cap_doc(
        PolicyScope::Global,
        &[Capability::McpTool("git".to_string())],
        &[],
    ));

    let ctx = make_ctx();

    // bash is NOT in the allowlist → must be denied
    let bash_result = engine
        .evaluate(
            &ctx,
            &GovernanceAction::ToolCall {
                name: "bash".into(),
                args: "{}".into(),
            },
        )
        .decision;
    assert!(
        matches!(bash_result, PolicyResult::Deny { .. }),
        "expected Deny for bash (not in MCP tool allowlist), got {:?}",
        bash_result
    );

    // git IS in the allowlist → must be allowed
    let git_result = engine
        .evaluate(
            &ctx,
            &GovernanceAction::ToolCall {
                name: "git".into(),
                args: "{}".into(),
            },
        )
        .decision;
    assert_eq!(
        git_result,
        PolicyResult::Allow,
        "expected Allow for git (in MCP tool allowlist), got {:?}",
        git_result
    );
}
