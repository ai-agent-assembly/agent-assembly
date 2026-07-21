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
use aa_gateway::engine::decision::{merge_decisions, merge_decisions_audited, PolicyDecision};
use aa_gateway::policy::validator::PolicyValidator;
use aa_gateway::policy::{evaluate_clause, ClauseKind, ContextError, PolicyContext, ResolutionFailure};

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

fn load_fixture(filename: &str) -> Arc<aa_gateway::policy::document::PolicyDocument> {
    let path = format!(
        "{}/tests/fixtures/policies/graph-vars/{}",
        env!("CARGO_MANIFEST_DIR"),
        filename
    );
    let yaml = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {path}: {e}"));
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
fn agent_depth_allow_requires_approval_without_context() {
    // AAASM-3995(b): without a PolicyContext the graph-aware approval clause is
    // unresolvable, so it now FAILS CLOSED — RequireApproval fires rather than
    // letting the action run unguarded.
    let doc = load_fixture("agent_depth_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert!(matches!(result, PolicyDecision::RequireApproval { .. }));
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
fn team_active_agents_allow_requires_approval_without_context() {
    // AAASM-3995(b): unresolved team.active_agents in an approval clause fails closed.
    let doc = load_fixture("team_active_agents_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("spawn");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert!(matches!(result, PolicyDecision::RequireApproval { .. }));
}

// ── team.budget_remaining fixtures ───────────────────────────────────────────

#[test]
fn team_budget_remaining_deny_fixture_loads_without_errors() {
    let _doc = load_fixture("team_budget_remaining_deny.yaml");
}

#[test]
fn team_budget_remaining_deny_requires_approval_without_context() {
    // AAASM-3995(b): a sole-clause requires_approval_if on team.budget_remaining
    // must not become an implicit Allow when context is unresolved — fail closed.
    let doc = load_fixture("team_budget_remaining_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("expensive_op");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    assert!(matches!(result, PolicyDecision::RequireApproval { .. }));
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

// ── null-safety snapshot tests ───────────────────────────────────────────────
//
// These snapshots lock the `PolicyDecision` produced when a graph-aware
// variable is absent (PolicyContext = None). Changing null-safety semantics
// requires an explicit snapshot review, which is the intent per AAASM-1035.

#[test]
fn snapshot_unconditional_deny_unaffected_by_null_ctx() {
    // `agent_depth_deny.yaml` uses `allow: false` — an unconditional deny.
    // Null-safety only suppresses graph-aware *conditional* clauses; it does
    // not bypass an explicit deny rule. Snapshot confirms the distinction.
    let doc = load_fixture("agent_depth_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    insta::assert_debug_snapshot!(result);
}

#[test]
fn snapshot_null_ctx_team_active_agents_fixture_requires_approval() {
    let doc = load_fixture("team_active_agents_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("spawn");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    insta::assert_debug_snapshot!(result);
}

#[test]
fn snapshot_null_ctx_team_budget_remaining_fixture_requires_approval() {
    let doc = load_fixture("team_budget_remaining_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("expensive_op");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    insta::assert_debug_snapshot!(result);
}

#[test]
fn snapshot_null_ctx_child_tool_deny_fixture_yields_allow() {
    let doc = load_fixture("child_tool_deny.yaml");
    let ctx = make_ctx();
    let action = tool_action("delegate");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    insta::assert_debug_snapshot!(result);
}

#[test]
fn snapshot_null_ctx_agent_depth_fixture_requires_approval() {
    let doc = load_fixture("agent_depth_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("deploy");
    let result = merge_decisions(&[doc], &ctx, &action, None);
    insta::assert_debug_snapshot!(result);
}

// ── ADR 0015 §4: resolution failure vs. legitimate absence (AAASM-4947) ───────
//
// These fixtures exercise the deterministic §4 table: a graph-context variable
// that *fails to resolve* (registry/backend/lookup error, modelled here by
// `FailingCtx`) fails **closed** according to the clause polarity, whereas a
// *legitimate absence* keeps the historical null-as-no-match behavior (its
// snapshots above stay byte-identical). Every resolution failure is recorded as
// audit evidence; legitimate absence records nothing.

/// A `PolicyContext` whose every getter reports a resolution failure — the
/// backend/lookup-error case ADR 0015 §4 distinguishes from `Ok(None)`.
struct FailingCtx;

impl PolicyContext for FailingCtx {
    fn agent_depth(&self) -> Result<Option<u32>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn team_active_agents(&self) -> Result<Option<u64>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn team_budget_remaining(&self) -> Result<Option<f64>, ContextError> {
        Err(ContextError::new("budget backend unavailable"))
    }
    fn child_tools(&self) -> Result<Vec<String>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn agent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn parent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn child_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn agent_age_secs(&self) -> Result<Option<u64>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn agent_parent_id(&self) -> Result<Option<String>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn agent_team_id(&self) -> Result<Option<String>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
    fn agent_children_count(&self) -> Result<Option<u32>, ContextError> {
        Err(ContextError::new("registry unavailable"))
    }
}

// (1) Legitimate absence — no context object at all — is null-as-no-match and,
// crucially, is NOT a resolution failure: it records zero audit evidence. This
// is the invariant that separates "absent" from "failed" (and the frozen
// snapshots above prove the decision itself is unchanged).
#[test]
fn legitimate_absence_is_not_a_resolution_failure() {
    let action = tool_action("deploy");
    let mut failures = Vec::new();
    // Numeric legit-absence still fails closed (fires) as before AAASM-4947...
    let fired = evaluate_clause(
        "agent.depth >= 2",
        &action,
        None,
        None,
        ClauseKind::RequireApproval,
        &mut failures,
    );
    assert!(fired, "legitimate absence of a numeric guard still fires (unchanged)");
    // ...but it emits NO audit record, because nothing failed to resolve.
    assert!(
        failures.is_empty(),
        "legitimate absence must not record a resolution failure"
    );
}

// (2) Resolution failure + `deny` (conditional) ⇒ DENY (clause fires).
#[test]
fn resolution_failure_denies_for_deny_clause() {
    let action = tool_action("deploy");
    let mut failures = Vec::new();
    let fired = evaluate_clause(
        "agent.depth >= 2",
        &action,
        None,
        Some(&FailingCtx),
        ClauseKind::Deny,
        &mut failures,
    );
    assert!(fired, "a deny clause must fire (deny) on resolution failure");
    // (5) audit evidence for this failure.
    assert_eq!(
        failures,
        vec![ResolutionFailure {
            variable: "agent.depth".to_string(),
            clause: ClauseKind::Deny,
        }]
    );
    assert_eq!(failures[0].fail_safe_action(), "deny");
}

// (3) Resolution failure + `requires_approval_if` ⇒ REQUIRE APPROVAL, end-to-end
// through the merge layer, with audit evidence surfaced.
#[test]
fn resolution_failure_requires_approval_end_to_end() {
    // Fixture guard: `requires_approval_if: "team.active_agents > 10"`.
    let doc = load_fixture("team_active_agents_allow.yaml");
    let ctx = make_ctx();
    let action = tool_action("spawn");
    let mut failures = Vec::new();
    let result = merge_decisions_audited(&[doc], &ctx, &action, Some(&FailingCtx), &mut failures);
    assert!(
        matches!(result, PolicyDecision::RequireApproval { .. }),
        "resolution failure on an approval guard must escalate, got {result:?}"
    );
    // (5) audit evidence for this failure.
    assert_eq!(
        failures,
        vec![ResolutionFailure {
            variable: "team.active_agents".to_string(),
            clause: ClauseKind::RequireApproval,
        }]
    );
    assert_eq!(failures[0].fail_safe_action(), "require_approval");
}

// (4) Resolution failure + conditional `allow` ⇒ no match, MUST NEVER grant
// (clause does NOT fire), with audit evidence.
#[test]
fn resolution_failure_never_grants_for_allow_clause() {
    let action = tool_action("spawn");
    let mut failures = Vec::new();
    let fired = evaluate_clause(
        "team.active_agents > 10",
        &action,
        None,
        Some(&FailingCtx),
        ClauseKind::Allow,
        &mut failures,
    );
    assert!(
        !fired,
        "a conditional allow must NOT fire on resolution failure — a failure can never grant"
    );
    // (5) audit evidence: the failure is recorded even though the clause did not fire.
    assert_eq!(
        failures,
        vec![ResolutionFailure {
            variable: "team.active_agents".to_string(),
            clause: ClauseKind::Allow,
        }]
    );
    assert_eq!(failures[0].fail_safe_action(), "no_grant");
}

// AAASM-4950 / ADR 0015 §4 (forward-conformance): a tokenize/parse anomaly must
// follow the SAME clause polarity as a resolution failure. Firing unconditionally
// on an anomaly would GRANT a conditional `Allow` — the exact fail-open §4 forbids
// ("allow + failure ⇒ never grant"). A guard (`Deny`/`RequireApproval`) still fires.
#[test]
fn parse_anomaly_never_grants_for_allow_clause() {
    let action = tool_action("spawn");

    // Both a tokenize anomaly (unknown char) and a structural anomaly (a bare
    // field with no operator/literal) must never fire an `Allow` clause.
    for bad_expr in ["not valid @@@ expr", "tool"] {
        let mut failures = Vec::new();
        let fired = evaluate_clause(bad_expr, &action, None, None, ClauseKind::Allow, &mut failures);
        assert!(
            !fired,
            "a conditional allow must NOT fire on a parse anomaly ({bad_expr:?}) — an anomaly can never grant"
        );
        // A parse anomaly is not a graph-variable resolution failure, so it
        // records no ResolutionFailure audit evidence.
        assert!(
            failures.is_empty(),
            "a parse anomaly records no resolution-failure evidence"
        );

        // The guard polarities still fail closed by firing.
        let mut deny_failures = Vec::new();
        assert!(
            evaluate_clause(bad_expr, &action, None, None, ClauseKind::Deny, &mut deny_failures),
            "a deny clause must fire (deny) on a parse anomaly ({bad_expr:?})"
        );
        let mut approval_failures = Vec::new();
        assert!(
            evaluate_clause(
                bad_expr,
                &action,
                None,
                None,
                ClauseKind::RequireApproval,
                &mut approval_failures,
            ),
            "a requires_approval clause must fire on a parse anomaly ({bad_expr:?})"
        );
    }
}
