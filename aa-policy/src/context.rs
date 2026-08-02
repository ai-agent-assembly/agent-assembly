//! The data a topology-aware policy condition needs, as a contract.
//!
//! [`PolicyContext`] abstracts the runtime state behind condition variables
//! (`agent.depth`, `team.active_agents`, …) so the expression evaluator in
//! [`crate::expr`] can be exercised without a live registry — and, since
//! AAASM-5349, so that this crate can define policy semantics without
//! depending on whichever process happens to hold that state.
//!
//! The production implementation lives in `aa-gateway`, which owns the agent
//! registry and budget tracker it reads. Only the contract belongs here.

/// A graph-context variable could not be resolved because of a
/// registry/backend/lookup error — as distinct from the variable being
/// *legitimately absent* (which the getters express as `Ok(None)`).
///
/// ADR 0015 §4 requires the evaluator to tell these two causes apart: a
/// legitimate absence is `null-as-no-match` (unchanged behavior), whereas a
/// resolution failure fails **closed** — `deny` ⇒ deny, `requires_approval_if`
/// ⇒ require approval, conditional `allow` ⇒ never grant — and emits audit
/// evidence. This error type is the "failure" arm the getters return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextError {
    /// Human-readable detail of what failed (which backend / lookup). Must never
    /// contain secret material — it is surfaced in audit evidence.
    pub detail: String,
}

impl ContextError {
    /// Construct a resolution failure with a human-readable `detail`.
    pub fn new(detail: impl Into<String>) -> Self {
        Self { detail: detail.into() }
    }
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "graph-context resolution failure: {}", self.detail)
    }
}

impl std::error::Error for ContextError {}

/// Provides runtime values for graph-aware policy condition variables.
///
/// Production code wires this to `AgentRegistry` and `BudgetTracker` via
/// [`ProductionPolicyContext`]. Unit tests inject a `FakePolicyContext` that
/// returns canned values.
///
/// # Absence vs. resolution failure (ADR 0015 §4)
///
/// Every getter returns `Result<Option<T>, ContextError>`, encoding **three**
/// outcomes the evaluator treats differently:
///
/// | Getter outcome | Meaning | Evaluator behavior |
/// |----------------|---------|--------------------|
/// | `Ok(Some(v))`  | resolved value | clause compares against `v` |
/// | `Ok(None)`     | **legitimate absence** (no team, root agent, unknown-but-valid) | `null-as-no-match` — unchanged from prior behavior |
/// | `Err(_)`       | **resolution failure** (backend/lookup error) | fails **closed** per clause polarity + emits audit evidence |
///
/// The `Ok(None)` path is the historical *null-as-no-match* contract and is
/// preserved byte-for-byte (its snapshots in `tests/graph_vars_fixture_test.rs`
/// are frozen). The `Err(_)` path is the ADR 0015 §4 addition: a variable that
/// *fails to resolve* must never silently no-match a `deny`/approval clause or
/// be laundered into an `allow` grant. The in-memory production context never
/// returns `Err` (its registry lookups cannot fail); the arm exists so a
/// backend-backed context can surface a genuine outage and have it fail closed.
pub trait PolicyContext: Send + Sync {
    /// Delegation depth of the current agent (0 = root).
    fn agent_depth(&self) -> Result<Option<u32>, ContextError>;
    /// Number of currently registered agents that belong to the current agent's
    /// team. `Ok(None)` when the agent has no team.
    fn team_active_agents(&self) -> Result<Option<u64>, ContextError>;
    /// Remaining monthly budget in USD for the current agent's team. `Ok(None)`
    /// when the agent has no team, no budget entry, or no monthly limit is
    /// configured.
    fn team_budget_remaining(&self) -> Result<Option<f64>, ContextError>;
    /// Union of `tool_names` across all direct children of the current agent.
    /// An agent with no children resolves to `Ok(vec![])` (legitimate absence);
    /// `Err` is a lookup failure.
    fn child_tools(&self) -> Result<Vec<String>, ContextError>;
    /// Risk tier of the current agent. `Ok(None)` when the agent is not found in
    /// the registry or has an unspecified (0) risk tier.
    fn agent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError>;
    /// Risk tier of the current agent's parent. `Ok(None)` when the agent has no
    /// parent or the parent is not in the registry.
    fn parent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError>;
    /// Proposed risk tier of the child agent being spawned, supplied in the
    /// spawn action payload. `Ok(None)` when the evaluation is not for a spawn
    /// action or no tier was specified.
    fn child_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError>;
    /// Age of the current agent in seconds, computed as `now_secs - registered_at`.
    /// `Ok(None)` when the agent is not found in the registry.
    fn agent_age_secs(&self) -> Result<Option<u64>, ContextError>;
    /// Parent agent ID string of the current agent. `Ok(None)` when the agent
    /// has no parent (i.e. it is a root agent).
    fn agent_parent_id(&self) -> Result<Option<String>, ContextError>;
    /// Team ID of the current agent. `Ok(None)` when the agent has no team.
    fn agent_team_id(&self) -> Result<Option<String>, ContextError>;
    /// Number of direct children of the current agent. `Ok(None)` when the agent
    /// is not found in the registry.
    fn agent_children_count(&self) -> Result<Option<u32>, ContextError>;
}

/// Minimal test double for [`PolicyContext`] that returns canned values.
#[cfg(test)]
#[derive(Default)]
pub struct FakePolicyContext {
    pub depth: Option<u32>,
    pub team_active: Option<u64>,
    pub team_budget: Option<f64>,
    pub child_tools: Vec<String>,
    pub agent_risk_tier: Option<aa_core::RiskTier>,
    pub parent_risk_tier: Option<aa_core::RiskTier>,
    pub child_risk_tier: Option<aa_core::RiskTier>,
    pub agent_age_secs: Option<u64>,
    pub agent_parent_id: Option<String>,
    pub agent_team_id: Option<String>,
    pub agent_children_count: Option<u32>,
}

#[cfg(test)]
impl PolicyContext for FakePolicyContext {
    fn agent_depth(&self) -> Result<Option<u32>, ContextError> {
        Ok(self.depth)
    }

    fn team_active_agents(&self) -> Result<Option<u64>, ContextError> {
        Ok(self.team_active)
    }

    fn team_budget_remaining(&self) -> Result<Option<f64>, ContextError> {
        Ok(self.team_budget)
    }

    fn child_tools(&self) -> Result<Vec<String>, ContextError> {
        Ok(self.child_tools.clone())
    }

    fn agent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok(self.agent_risk_tier)
    }

    fn parent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok(self.parent_risk_tier)
    }

    fn child_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok(self.child_risk_tier)
    }

    fn agent_age_secs(&self) -> Result<Option<u64>, ContextError> {
        Ok(self.agent_age_secs)
    }

    fn agent_parent_id(&self) -> Result<Option<String>, ContextError> {
        Ok(self.agent_parent_id.clone())
    }

    fn agent_team_id(&self) -> Result<Option<String>, ContextError> {
        Ok(self.agent_team_id.clone())
    }

    fn agent_children_count(&self) -> Result<Option<u32>, ContextError> {
        Ok(self.agent_children_count)
    }
}
