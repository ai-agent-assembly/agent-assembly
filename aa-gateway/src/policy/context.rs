//! Graph-aware policy evaluation context.
//!
//! [`PolicyContext`] abstracts the runtime data needed to evaluate topology-aware
//! condition variables (`agent.depth`, `team.active_agents`, etc.) so that the
//! expression evaluator remains testable without a live registry.

use rust_decimal::prelude::ToPrimitive;

use crate::budget::BudgetTracker;
use crate::registry::AgentRegistry;

/// Production implementation of [`PolicyContext`] backed by [`AgentRegistry`]
/// and [`BudgetTracker`]. Constructed per `evaluate()` call in [`PolicyEngine`].
pub struct ProductionPolicyContext<'a> {
    registry: &'a AgentRegistry,
    budget: &'a BudgetTracker,
    agent_key: [u8; 16],
    team_id: Option<String>,
}

impl<'a> ProductionPolicyContext<'a> {
    pub fn new(
        registry: &'a AgentRegistry,
        budget: &'a BudgetTracker,
        agent_key: [u8; 16],
        team_id: Option<String>,
    ) -> Self {
        Self {
            registry,
            budget,
            agent_key,
            team_id,
        }
    }
}

impl<'a> PolicyContext for ProductionPolicyContext<'a> {
    fn agent_depth(&self) -> Option<u32> {
        self.registry.get(&self.agent_key).map(|r| r.depth)
    }

    fn team_active_agents(&self) -> Option<u64> {
        let team_id = self.team_id.as_deref()?;
        Some(self.registry.team_members(team_id).len() as u64)
    }

    fn team_budget_remaining(&self) -> Option<f64> {
        let team_id = self.team_id.as_deref()?;
        let state = self.budget.team_state(team_id)?;
        let limit = self.budget.monthly_limit_usd()?;
        let spent = state.monthly_spent_usd.unwrap_or(state.spent_usd);
        let remaining = (limit - spent).max(rust_decimal::Decimal::ZERO);
        remaining.to_f64()
    }

    fn child_tools(&self) -> Vec<String> {
        self.registry
            .children_of(&self.agent_key)
            .into_iter()
            .flat_map(|key| {
                self.registry
                    .get(&key)
                    .map(|r| r.tool_names.clone())
                    .unwrap_or_default()
            })
            .collect()
    }

    fn agent_risk_tier(&self) -> Option<aa_core::RiskTier> {
        let record = self.registry.get(&self.agent_key)?;
        aa_core::RiskTier::from_proto_i32(record.risk_tier)
    }

    fn parent_risk_tier(&self) -> Option<aa_core::RiskTier> {
        let record = self.registry.get(&self.agent_key)?;
        let parent_key = record.parent_key?;
        let parent = self.registry.get(&parent_key)?;
        aa_core::RiskTier::from_proto_i32(parent.risk_tier)
    }
}

/// Minimal test double for [`PolicyContext`] that returns canned values.
#[cfg(test)]
pub struct FakePolicyContext {
    pub depth: Option<u32>,
    pub team_active: Option<u64>,
    pub team_budget: Option<f64>,
    pub child_tools: Vec<String>,
    pub agent_risk_tier: Option<aa_core::RiskTier>,
    pub parent_risk_tier: Option<aa_core::RiskTier>,
}

#[cfg(test)]
impl PolicyContext for FakePolicyContext {
    fn agent_depth(&self) -> Option<u32> {
        self.depth
    }

    fn team_active_agents(&self) -> Option<u64> {
        self.team_active
    }

    fn team_budget_remaining(&self) -> Option<f64> {
        self.team_budget
    }

    fn child_tools(&self) -> Vec<String> {
        self.child_tools.clone()
    }

    fn agent_risk_tier(&self) -> Option<aa_core::RiskTier> {
        self.agent_risk_tier
    }

    fn parent_risk_tier(&self) -> Option<aa_core::RiskTier> {
        self.parent_risk_tier
    }
}

/// Provides runtime values for graph-aware policy condition variables.
///
/// Production code wires this to `AgentRegistry` and `BudgetTracker` via
/// [`super::super::engine::ProductionPolicyContext`]. Unit tests inject a
/// `FakePolicyContext` that returns canned values.
///
/// # Null-safety semantics
///
/// Every getter returns `Option<T>`. When a variable cannot be resolved (the
/// getter returns `None`), the expression clause that references it
/// short-circuits to `false`. The effect on the overall policy decision is:
///
/// | Clause type          | Variable resolves `Some(_)` | Variable is `None`     |
/// |----------------------|-----------------------------|------------------------|
/// | `requires_approval_if` | fires when expression is `true` | **does not fire** |
/// | `deny` condition     | denies when expression is `true` | **does not deny**  |
/// | `allow`              | always allows               | always allows          |
///
/// In every case an unresolvable variable contributes **nothing** to the
/// decision: it neither allows nor denies. A request that references an absent
/// graph-variable is evaluated as if the condition clause were absent from the
/// policy. This is sometimes called *null-as-no-match* or *fail-open on
/// missing context*.
///
/// The fixture tests in `tests/graph_vars_fixture_test.rs` snapshot the
/// `PolicyDecision` produced for each variable in both the null and non-null
/// paths to guard against accidental semantics changes.
pub trait PolicyContext: Send + Sync {
    /// Delegation depth of the current agent (0 = root).
    fn agent_depth(&self) -> Option<u32>;
    /// Number of currently registered agents that belong to the current agent's
    /// team. Returns `None` when the agent has no team.
    fn team_active_agents(&self) -> Option<u64>;
    /// Remaining monthly budget in USD for the current agent's team. Returns
    /// `None` when the agent has no team, no budget entry, or no monthly limit
    /// is configured.
    fn team_budget_remaining(&self) -> Option<f64>;
    /// Union of `tool_names` across all direct children of the current agent.
    fn child_tools(&self) -> Vec<String>;
    /// Risk tier of the current agent. Returns `None` when the agent is not
    /// found in the registry or has an unspecified (0) risk tier.
    fn agent_risk_tier(&self) -> Option<aa_core::RiskTier>;
    /// Risk tier of the current agent's parent. Returns `None` when the agent
    /// has no parent or the parent is not in the registry.
    fn parent_risk_tier(&self) -> Option<aa_core::RiskTier>;
}
