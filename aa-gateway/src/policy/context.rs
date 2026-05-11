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
        todo!("AAASM-1032: implement via registry lookup")
    }

    fn team_active_agents(&self) -> Option<u64> {
        todo!("AAASM-1032: implement via team_index count")
    }

    fn team_budget_remaining(&self) -> Option<f64> {
        todo!("AAASM-1032: implement via BudgetTracker::team_state")
    }

    fn child_tools(&self) -> Vec<String> {
        todo!("AAASM-1032: implement via registry children_of")
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
