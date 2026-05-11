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
        Self { registry, budget, agent_key, team_id }
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
}

/// Provides runtime values for graph-aware policy condition variables.
///
/// Production code wires this to `AgentRegistry` and `BudgetTracker` via
/// [`super::super::engine::ProductionPolicyContext`]. Unit tests inject a
/// `FakePolicyContext` that returns canned values.
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
}
