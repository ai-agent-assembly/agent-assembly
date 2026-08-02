//! Graph-aware policy evaluation context, backed by live gateway state.
//!
//! The [`PolicyContext`] contract itself lives in [`aa_policy::context`]; this
//! is the implementation that reads the [`AgentRegistry`] and
//! [`BudgetTracker`] this crate owns. That split is why `aa-policy` can be a
//! leaf crate: policy semantics do not depend on who holds the runtime state
//! (AAASM-5349).

use rust_decimal::prelude::ToPrimitive;

// Re-exported, not merely imported: callers reach the contract as
// `crate::policy::context::PolicyContext`, and that path must keep resolving
// now that the trait itself lives in `aa-policy`.
pub use aa_policy::context::{ContextError, PolicyContext};

use crate::budget::BudgetTracker;
use crate::registry::AgentRegistry;

/// Production implementation of [`PolicyContext`] backed by [`AgentRegistry`]
/// and [`BudgetTracker`]. Constructed per `evaluate()` call in [`PolicyEngine`].
pub struct ProductionPolicyContext<'a> {
    registry: &'a AgentRegistry,
    budget: &'a BudgetTracker,
    agent_key: [u8; 16],
    team_id: Option<String>,
    /// Proposed risk tier of the child agent being spawned (from the spawn
    /// request payload). `None` when the evaluation is not for a spawn action.
    proposed_child_risk_tier: Option<aa_core::RiskTier>,
    /// Unix timestamp in seconds captured at context construction time, used to compute agent.age.
    now_secs: u64,
}

impl<'a> ProductionPolicyContext<'a> {
    pub fn new(
        registry: &'a AgentRegistry,
        budget: &'a BudgetTracker,
        agent_key: [u8; 16],
        team_id: Option<String>,
        now_secs: u64,
    ) -> Self {
        Self {
            registry,
            budget,
            agent_key,
            team_id,
            proposed_child_risk_tier: None,
            now_secs,
        }
    }
}

impl<'a> PolicyContext for ProductionPolicyContext<'a> {
    // The in-memory [`AgentRegistry`] / [`BudgetTracker`] lookups cannot fail —
    // an unknown agent/team is a legitimate `Ok(None)` (null-as-no-match), not a
    // resolution failure. These methods therefore never return `Err`; the
    // `Result` return type exists so a future backend-backed context (registry
    // over a remote store) can surface a genuine lookup error as `Err`, which the
    // evaluator then fails **closed** per ADR 0015 §4.
    fn agent_depth(&self) -> Result<Option<u32>, ContextError> {
        Ok(self.registry.get(&self.agent_key).map(|r| r.depth))
    }

    fn team_active_agents(&self) -> Result<Option<u64>, ContextError> {
        Ok(self
            .team_id
            .as_deref()
            .map(|team_id| self.registry.team_members(team_id).len() as u64))
    }

    fn team_budget_remaining(&self) -> Result<Option<f64>, ContextError> {
        Ok((|| {
            let team_id = self.team_id.as_deref()?;
            let state = self.budget.team_state(team_id)?;
            let limit = self.budget.monthly_limit_usd()?;
            let spent = state.monthly_spent_usd.unwrap_or(state.spent_usd);
            let remaining = (limit - spent).max(rust_decimal::Decimal::ZERO);
            remaining.to_f64()
        })())
    }

    fn child_tools(&self) -> Result<Vec<String>, ContextError> {
        Ok(self
            .registry
            .children_of(&self.agent_key)
            .into_iter()
            .flat_map(|key| {
                self.registry
                    .get(&key)
                    .map(|r| r.tool_names.clone())
                    .unwrap_or_default()
            })
            .collect())
    }

    fn agent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok(self
            .registry
            .get(&self.agent_key)
            .and_then(|record| aa_core::RiskTier::from_proto_i32(record.risk_tier)))
    }

    fn parent_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok((|| {
            let record = self.registry.get(&self.agent_key)?;
            let parent_key = record.parent_key?;
            let parent = self.registry.get(&parent_key)?;
            aa_core::RiskTier::from_proto_i32(parent.risk_tier)
        })())
    }

    fn child_risk_tier(&self) -> Result<Option<aa_core::RiskTier>, ContextError> {
        Ok(self.proposed_child_risk_tier)
    }

    fn agent_age_secs(&self) -> Result<Option<u64>, ContextError> {
        Ok(self.registry.get(&self.agent_key).map(|record| {
            let registered_unix = record.registered_at.timestamp() as u64;
            self.now_secs.saturating_sub(registered_unix)
        }))
    }

    fn agent_parent_id(&self) -> Result<Option<String>, ContextError> {
        Ok(self
            .registry
            .get(&self.agent_key)
            .and_then(|record| record.parent_agent_id.clone()))
    }

    fn agent_team_id(&self) -> Result<Option<String>, ContextError> {
        Ok(self.team_id.clone())
    }

    fn agent_children_count(&self) -> Result<Option<u32>, ContextError> {
        Ok(self
            .registry
            .get(&self.agent_key)
            .map(|record| record.children.len() as u32))
    }
}

#[cfg(test)]
mod production_context_tests {
    //! Direct tests for the registry/budget-backed [`ProductionPolicyContext`].
    //!
    //! The graph-variable getters are normally exercised only through a full
    //! `PolicyEngine::evaluate` call, which left this impl's individual
    //! resolution paths thinly covered. These tests build a real
    //! [`AgentRegistry`] + [`BudgetTracker`] and assert each getter resolves
    //! the topology fact it claims to — both the present and the absent
    //! (`None`) branch that drives the null-as-no-match policy semantics.

    use super::*;
    use crate::budget::{BudgetTracker, PricingTable};
    use crate::registry::{AgentRecord, AgentRegistry, AgentStatus};
    use rust_decimal::Decimal;

    fn dec(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    /// Build an `AgentRecord` with the fields the graph-variable getters read;
    /// the rest are inert defaults. Children are linked automatically by
    /// `AgentRegistry::register`, so callers never set them here.
    #[allow(clippy::too_many_arguments)]
    fn rec(
        id: [u8; 16],
        parent_key: Option<[u8; 16]>,
        team_id: Option<&str>,
        depth: u32,
        risk_tier: i32,
        tool_names: Vec<String>,
        registered_at_unix: i64,
        parent_agent_id: Option<&str>,
    ) -> AgentRecord {
        AgentRecord {
            agent_id: id,
            name: "test".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier,
            tool_names,
            public_key: "deadbeef".into(),
            // Empty so repeated registrations don't share a credential index key.
            credential_token: String::new(),
            metadata: Default::default(),
            registered_at: chrono::DateTime::from_timestamp(registered_at_unix, 0).unwrap(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            active_sessions: vec![],
            recent_events: Default::default(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: parent_agent_id.map(|s| s.to_string()),
            team_id: team_id.map(|s| s.to_string()),
            depth,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
            children: vec![],
            parent_key,
            enforcement_mode: None,
            enforcement_mode_expires_at: None,
            org_id: None,
        }
    }

    const T0: i64 = 1_000_000;
    const PARENT: [u8; 16] = [1u8; 16];
    const CHILD: [u8; 16] = [2u8; 16];

    /// Registry with a root parent (High tier) and one child (Medium tier) on
    /// team `eng`. `register` links the child into the parent's `children` and
    /// the team index automatically.
    fn registry_with_family() -> AgentRegistry {
        let reg = AgentRegistry::new();
        reg.register(rec(PARENT, None, Some("eng"), 0, 3, vec!["search".into()], T0, None))
            .unwrap();
        reg.register(rec(
            CHILD,
            Some(PARENT),
            Some("eng"),
            1,
            2,
            vec!["write".into(), "exec".into()],
            T0,
            Some("parent-str"),
        ))
        .unwrap();
        reg
    }

    #[test]
    fn parent_context_resolves_topology_facts() {
        let reg = registry_with_family();
        let budget = BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC);
        let ctx = ProductionPolicyContext::new(&reg, &budget, PARENT, Some("eng".into()), (T0 + 500) as u64);

        assert_eq!(ctx.agent_depth(), Ok(Some(0)));
        // Both agents share team "eng".
        assert_eq!(ctx.team_active_agents(), Ok(Some(2)));
        // Parent's sole child contributes its declared tools.
        let mut tools = ctx.child_tools().unwrap();
        tools.sort();
        assert_eq!(tools, vec!["exec".to_string(), "write".to_string()]);
        assert_eq!(ctx.agent_risk_tier(), Ok(Some(aa_core::RiskTier::High)));
        // A root has no parent, so parent_risk_tier is absent.
        assert_eq!(ctx.parent_risk_tier(), Ok(None));
        // child_risk_tier is the proposed-spawn tier, unset on a plain context.
        assert_eq!(ctx.child_risk_tier(), Ok(None));
        // now_secs - registered_at = 500.
        assert_eq!(ctx.agent_age_secs(), Ok(Some(500)));
        assert_eq!(ctx.agent_parent_id(), Ok(None));
        assert_eq!(ctx.agent_team_id(), Ok(Some("eng".to_string())));
        assert_eq!(ctx.agent_children_count(), Ok(Some(1)));
    }

    #[test]
    fn child_context_resolves_parent_facts() {
        let reg = registry_with_family();
        let budget = BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC);
        let ctx = ProductionPolicyContext::new(&reg, &budget, CHILD, Some("eng".into()), (T0 + 10) as u64);

        assert_eq!(ctx.agent_depth(), Ok(Some(1)));
        assert_eq!(ctx.agent_risk_tier(), Ok(Some(aa_core::RiskTier::Medium)));
        // The child's parent is the High-tier root.
        assert_eq!(ctx.parent_risk_tier(), Ok(Some(aa_core::RiskTier::High)));
        assert_eq!(ctx.agent_parent_id(), Ok(Some("parent-str".to_string())));
        assert_eq!(ctx.agent_children_count(), Ok(Some(0)));
        assert_eq!(ctx.agent_age_secs(), Ok(Some(10)));
    }

    #[test]
    fn team_budget_remaining_subtracts_recorded_spend_from_limit() {
        let reg = registry_with_family();
        // Global monthly limit 100; team "eng" has spent 30.
        let budget = BudgetTracker::new(PricingTable::default_table(), None, Some(dec("100")), chrono_tz::UTC);
        budget.record_raw_spend(aa_core::AgentId::from_bytes(PARENT), Some("eng"), None, dec("30"));

        let ctx = ProductionPolicyContext::new(&reg, &budget, PARENT, Some("eng".into()), T0 as u64);
        assert_eq!(ctx.team_budget_remaining(), Ok(Some(70.0)));
    }

    #[test]
    fn team_budget_remaining_is_none_without_a_monthly_limit() {
        let reg = registry_with_family();
        // No global monthly limit configured, but the team has recorded spend.
        let budget = BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC);
        budget.record_raw_spend(aa_core::AgentId::from_bytes(PARENT), Some("eng"), None, dec("5"));

        let ctx = ProductionPolicyContext::new(&reg, &budget, PARENT, Some("eng".into()), T0 as u64);
        // `monthly_limit_usd()` is None → the whole getter short-circuits.
        assert_eq!(ctx.team_budget_remaining(), Ok(None));
    }

    #[test]
    fn missing_agent_resolves_every_registry_getter_to_none() {
        // An agent_key that was never registered must make every
        // registry-backed getter return None (null-as-no-match), and the
        // child-tools union must be empty rather than panic.
        let reg = AgentRegistry::new();
        let budget = BudgetTracker::new(PricingTable::default_table(), None, Some(dec("100")), chrono_tz::UTC);
        let ctx = ProductionPolicyContext::new(&reg, &budget, [9u8; 16], None, T0 as u64);

        assert_eq!(ctx.agent_depth(), Ok(None));
        assert_eq!(ctx.agent_risk_tier(), Ok(None));
        assert_eq!(ctx.parent_risk_tier(), Ok(None));
        assert_eq!(ctx.agent_age_secs(), Ok(None));
        assert_eq!(ctx.agent_parent_id(), Ok(None));
        assert_eq!(ctx.agent_children_count(), Ok(None));
        assert!(ctx.child_tools().unwrap().is_empty());
        // No team on the context → the team-scoped getters are all None.
        assert_eq!(ctx.team_active_agents(), Ok(None));
        assert_eq!(ctx.team_budget_remaining(), Ok(None));
        assert_eq!(ctx.agent_team_id(), Ok(None));
    }

    #[test]
    fn agent_risk_tier_is_none_for_unspecified_tier() {
        // risk_tier 0 is the proto UNSPECIFIED sentinel; from_proto_i32 maps it
        // to None so an undeclared tier never silently reads as Low.
        let reg = AgentRegistry::new();
        reg.register(rec([7u8; 16], None, None, 0, 0, vec![], T0, None))
            .unwrap();
        let budget = BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC);
        let ctx = ProductionPolicyContext::new(&reg, &budget, [7u8; 16], None, T0 as u64);
        assert_eq!(ctx.agent_risk_tier(), Ok(None));
    }
}
