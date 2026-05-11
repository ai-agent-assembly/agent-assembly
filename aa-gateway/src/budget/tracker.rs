//! Per-agent and global LLM spend tracker.

use std::sync::Mutex;

use dashmap::DashMap;
use rust_decimal::Decimal;
use tokio::sync::broadcast;

use aa_core::AgentId;

use rust_decimal::prelude::ToPrimitive;

use crate::budget::{
    pricing::PricingTable,
    types::{BudgetAlert, BudgetState, BudgetStatus},
};

/// Per-agent daily limit entry stored in `BudgetTracker::agent_limits`.
#[derive(Debug, Clone)]
pub(crate) struct AgentLimit {
    /// Per-day spend cap in USD for this agent.
    pub daily_usd: Option<Decimal>,
    /// Per-month spend cap in USD for this agent.
    pub monthly_usd: Option<Decimal>,
}

const ALERT_CHANNEL_CAPACITY: usize = 64;
const ALERT_PCT_HIGH: u8 = 95;
const ALERT_PCT_LOW: u8 = 80;

fn compute_status(spent: Decimal, limit: Decimal) -> BudgetStatus {
    if spent >= limit {
        return BudgetStatus::LimitExceeded;
    }
    let pct = (spent / limit * Decimal::ONE_HUNDRED)
        .round_dp(0)
        .to_u8()
        .unwrap_or(100);
    let spent_f = spent.to_f64().unwrap_or(0.0);
    let limit_f = limit.to_f64().unwrap_or(0.0);
    if pct >= ALERT_PCT_HIGH {
        BudgetStatus::ThresholdAlert { pct: ALERT_PCT_HIGH }
    } else if pct >= ALERT_PCT_LOW {
        BudgetStatus::ThresholdAlert { pct: ALERT_PCT_LOW }
    } else {
        BudgetStatus::WithinBudget {
            spent_usd: spent_f,
            remaining_usd: limit_f - spent_f,
        }
    }
}

fn today_in_tz(tz: chrono_tz::Tz) -> chrono::NaiveDate {
    chrono::Utc::now().with_timezone(&tz).date_naive()
}

/// Per-agent and global budget tracker. All methods take `&self` — safe to share via `Arc`.
pub struct BudgetTracker {
    /// Per-agent daily spend. `pub(crate)` for test date manipulation.
    pub(crate) per_agent: DashMap<AgentId, BudgetState>,
    /// Per-team daily/monthly spend rollup. `pub(crate)` for test date manipulation.
    pub(crate) team_budgets: DashMap<String, BudgetState>,
    pub(crate) global: Mutex<BudgetState>,
    pricing: PricingTable,
    daily_limit_usd: Option<Decimal>,
    monthly_limit_usd: Option<Decimal>,
    /// Per-team daily spend limit. Applied to each team independently.
    team_daily_limit_usd: Option<Decimal>,
    /// Per-team monthly spend limit. Applied to each team independently.
    team_monthly_limit_usd: Option<Decimal>,
    /// Per-agent daily/monthly limits set via [`BudgetTracker::with_agent_limit`].
    pub(crate) agent_limits: DashMap<AgentId, AgentLimit>,
    alert_tx: broadcast::Sender<BudgetAlert>,
    timezone: chrono_tz::Tz,
}

impl BudgetTracker {
    /// Create a new tracker with no prior state.
    pub fn new(
        pricing: PricingTable,
        daily_limit_usd: Option<Decimal>,
        monthly_limit_usd: Option<Decimal>,
        timezone: chrono_tz::Tz,
    ) -> Self {
        let (alert_tx, _) = broadcast::channel(ALERT_CHANNEL_CAPACITY);
        Self::new_with_alert_sender(pricing, daily_limit_usd, monthly_limit_usd, timezone, alert_tx)
    }

    /// Create a new tracker that sends alerts on an externally-owned channel.
    ///
    /// Use this when the broadcast channel is created upstream (e.g. `main.rs`)
    /// and shared with other consumers like the webhook delivery loop.
    pub fn new_with_alert_sender(
        pricing: PricingTable,
        daily_limit_usd: Option<Decimal>,
        monthly_limit_usd: Option<Decimal>,
        timezone: chrono_tz::Tz,
        alert_tx: broadcast::Sender<BudgetAlert>,
    ) -> Self {
        Self {
            per_agent: DashMap::new(),
            team_budgets: DashMap::new(),
            global: Mutex::new(BudgetState::new_for_date(today_in_tz(timezone))),
            pricing,
            daily_limit_usd,
            monthly_limit_usd,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            agent_limits: DashMap::new(),
            alert_tx,
            timezone,
        }
    }

    /// Set the per-team daily spend limit in USD. Enforced in `record_cost` for every team.
    pub fn with_team_daily_limit(mut self, limit: Decimal) -> Self {
        self.team_daily_limit_usd = Some(limit);
        self
    }

    /// Set the per-team monthly spend limit in USD. Enforced in `record_cost` for every team.
    pub fn with_team_monthly_limit(mut self, limit: Decimal) -> Self {
        self.team_monthly_limit_usd = Some(limit);
        self
    }

    /// Register a per-agent daily and/or monthly spend cap.
    ///
    /// Used by `check_and_decrement` to validate per-agent limits before committing
    /// ancestor decrements. `daily_usd` and `monthly_usd` may each be `None` to
    /// leave that window unconstrained for this specific agent.
    pub fn with_agent_limit(
        self,
        agent_id: AgentId,
        daily_usd: Option<Decimal>,
        monthly_usd: Option<Decimal>,
    ) -> Self {
        self.agent_limits.insert(agent_id, AgentLimit { daily_usd, monthly_usd });
        self
    }

    /// Create a tracker pre-loaded with persisted state (call after `load_from_disk`).
    pub fn with_state(
        pricing: PricingTable,
        daily_limit_usd: Option<Decimal>,
        monthly_limit_usd: Option<Decimal>,
        initial: crate::budget::persistence::PersistedBudget,
    ) -> Self {
        let (alert_tx, _) = broadcast::channel(ALERT_CHANNEL_CAPACITY);
        Self::with_state_and_alert_sender(pricing, daily_limit_usd, monthly_limit_usd, initial, alert_tx)
    }

    /// Create a tracker pre-loaded with persisted state that sends alerts on an
    /// externally-owned channel.
    ///
    /// Combines [`with_state`] (restoring prior spend) with [`new_with_alert_sender`]
    /// (sharing a broadcast channel created upstream).
    pub fn with_state_and_alert_sender(
        pricing: PricingTable,
        daily_limit_usd: Option<Decimal>,
        monthly_limit_usd: Option<Decimal>,
        initial: crate::budget::persistence::PersistedBudget,
        alert_tx: broadcast::Sender<BudgetAlert>,
    ) -> Self {
        let timezone = initial.timezone;
        let per_agent: DashMap<AgentId, BudgetState> = initial
            .per_agent
            .into_iter()
            .filter_map(|e| {
                crate::budget::persistence::hex_to_agent_id(&e.agent_id_hex)
                    .ok()
                    .map(|id| (id, e.state))
            })
            .collect();
        let team_budgets: DashMap<String, BudgetState> = initial.team_budgets.into_iter().collect();
        Self {
            per_agent,
            team_budgets,
            global: Mutex::new(initial.global),
            pricing,
            daily_limit_usd,
            monthly_limit_usd,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            agent_limits: DashMap::new(),
            alert_tx,
            timezone,
        }
    }

    /// Return the effective daily or monthly limit for `agent_id`.
    ///
    /// Checks `agent_limits` first, then falls back to the global tracker limits.
    /// Returns `None` when neither per-agent nor global limit is configured for `kind`.
    fn resolve_limit(&self, agent_id: &AgentId, kind: crate::budget::types::BudgetKind) -> Option<Decimal> {
        use crate::budget::types::BudgetKind;
        match kind {
            BudgetKind::Daily => self
                .agent_limits
                .get(agent_id)
                .and_then(|l| l.daily_usd)
                .or(self.daily_limit_usd),
            BudgetKind::Monthly => self
                .agent_limits
                .get(agent_id)
                .and_then(|l| l.monthly_usd)
                .or(self.monthly_limit_usd),
            BudgetKind::Global => None,
        }
    }

    /// Subscribe to budget threshold alert events (80% and 95% crossings).
    pub fn subscribe_alerts(&self) -> broadcast::Receiver<BudgetAlert> {
        self.alert_tx.subscribe()
    }

    /// Returns the configured timezone for daily reset boundaries.
    pub fn timezone(&self) -> chrono_tz::Tz {
        self.timezone
    }

    /// Returns the configured daily budget limit in USD, if set.
    pub fn daily_limit_usd(&self) -> Option<Decimal> {
        self.daily_limit_usd
    }

    /// Returns the configured monthly budget limit in USD, if set.
    pub fn monthly_limit_usd(&self) -> Option<Decimal> {
        self.monthly_limit_usd
    }

    /// Returns `true` if the agent has met or exceeded the given daily limit.
    ///
    /// Automatically resets spend to zero when the stored date is before today
    /// in the configured timezone. Used by `PolicyEngine` Stage 7 where the
    /// per-action cost is not yet known and only a limit check is needed.
    pub fn check_daily(&self, agent_id: &AgentId, limit: Decimal) -> bool {
        if let Some(mut entry) = self.per_agent.get_mut(agent_id) {
            entry.maybe_reset(today_in_tz(self.timezone));
            entry.spent_usd >= limit
        } else {
            false
        }
    }

    /// Returns `true` if the agent has met or exceeded the given monthly limit.
    ///
    /// Automatically resets monthly spend when the stored month differs from the
    /// current month in the configured timezone.
    pub fn check_monthly(&self, agent_id: &AgentId, limit: Decimal) -> bool {
        if let Some(mut entry) = self.per_agent.get_mut(agent_id) {
            entry.maybe_reset(today_in_tz(self.timezone));
            entry.monthly_spent_usd.map(|m| m >= limit).unwrap_or(false)
        } else {
            false
        }
    }

    /// Record a pre-computed USD spend amount for an agent.
    ///
    /// Unlike [`record_usage`](Self::record_usage), this method bypasses the
    /// `PricingTable` and accepts a raw USD amount directly. Used by
    /// `PolicyEngine::record_spend()` which receives cost estimates from callers
    /// rather than raw token counts.
    ///
    /// Fires 80%/95% threshold alerts on the broadcast channel and updates the
    /// global and team spend accumulators. Returns the resulting [`BudgetStatus`].
    pub fn record_raw_spend(&self, agent_id: AgentId, team_id: Option<&str>, amount_usd: Decimal) -> BudgetStatus {
        self.record_cost(agent_id, team_id, amount_usd)
    }

    /// Record token usage and return the resulting [`BudgetStatus`].
    pub fn record_usage(
        &self,
        agent_id: AgentId,
        team_id: Option<&str>,
        provider: crate::budget::types::Provider,
        model: crate::budget::types::Model,
        input_tokens: u64,
        output_tokens: u64,
    ) -> BudgetStatus {
        let cost = self.pricing.cost_usd(provider, model, input_tokens, output_tokens);
        self.record_cost(agent_id, team_id, cost)
    }

    /// Compute status for `spent` against `limit`, emit a [`BudgetAlert`] on the broadcast
    /// channel if at a threshold, and return the resulting [`BudgetStatus`].
    fn check_limit_and_alert(
        &self,
        agent_id: AgentId,
        team_id: Option<&str>,
        spent: Decimal,
        limit: Decimal,
    ) -> BudgetStatus {
        let status = compute_status(spent, limit);
        if let BudgetStatus::ThresholdAlert { pct } = &status {
            let _ = self.alert_tx.send(BudgetAlert {
                agent_id,
                team_id: team_id.map(str::to_string),
                threshold_pct: *pct,
                spent_usd: spent.to_f64().unwrap_or(0.0),
                limit_usd: limit.to_f64().unwrap_or(0.0),
            });
        }
        status
    }

    /// Shared cost-recording logic used by both [`record_usage`](Self::record_usage)
    /// and [`record_raw_spend`](Self::record_raw_spend).
    fn record_cost(&self, agent_id: AgentId, team_id: Option<&str>, cost: Decimal) -> BudgetStatus {
        let has_monthly = self.monthly_limit_usd.is_some() || self.team_monthly_limit_usd.is_some();

        self.per_agent
            .entry(agent_id)
            .and_modify(|s| {
                s.maybe_reset(today_in_tz(self.timezone));
                s.spent_usd += cost;
                if let Some(m) = s.monthly_spent_usd.as_mut() {
                    *m += cost;
                }
            })
            .or_insert_with(|| {
                let mut s = BudgetState::new_for_date(today_in_tz(self.timezone));
                s.spent_usd += cost;
                if has_monthly {
                    s.monthly_spent_usd = Some(cost);
                }
                s
            });

        if let Some(tid) = team_id {
            self.team_budgets
                .entry(tid.to_string())
                .and_modify(|s| {
                    s.maybe_reset(today_in_tz(self.timezone));
                    s.spent_usd += cost;
                    if let Some(m) = s.monthly_spent_usd.as_mut() {
                        *m += cost;
                    }
                })
                .or_insert_with(|| {
                    let mut s = BudgetState::new_for_date(today_in_tz(self.timezone));
                    s.spent_usd += cost;
                    if has_monthly {
                        s.monthly_spent_usd = Some(cost);
                    }
                    s
                });

            // Check team monthly limit and emit alert.
            if let Some(team_monthly_limit) = self.team_monthly_limit_usd {
                if let Some(team_state) = self.team_budgets.get(tid) {
                    if let Some(team_monthly) = team_state.monthly_spent_usd {
                        let status = self.check_limit_and_alert(agent_id, Some(tid), team_monthly, team_monthly_limit);
                        if status == BudgetStatus::LimitExceeded {
                            return BudgetStatus::LimitExceeded;
                        }
                    }
                }
            }

            // Check team daily limit and emit alert.
            if let Some(team_daily_limit) = self.team_daily_limit_usd {
                if let Some(team_state) = self.team_budgets.get(tid) {
                    let status =
                        self.check_limit_and_alert(agent_id, Some(tid), team_state.spent_usd, team_daily_limit);
                    if status == BudgetStatus::LimitExceeded {
                        return BudgetStatus::LimitExceeded;
                    }
                }
            }
        }

        let (spent, monthly_spent) = self
            .per_agent
            .get(&agent_id)
            .map(|s| (s.spent_usd, s.monthly_spent_usd))
            .unwrap_or((cost, None));

        if let Ok(mut g) = self.global.lock() {
            g.maybe_reset(today_in_tz(self.timezone));
            g.spent_usd += cost;
        }

        // Check monthly limit first — monthly exceeded takes precedence.
        if let (Some(limit), Some(m_spent)) = (self.monthly_limit_usd, monthly_spent) {
            let status = self.check_limit_and_alert(agent_id, None, m_spent, limit);
            if matches!(status, BudgetStatus::LimitExceeded) {
                return BudgetStatus::LimitExceeded;
            }
        }

        match self.daily_limit_usd {
            None => BudgetStatus::WithinBudget {
                spent_usd: spent.to_f64().unwrap_or(0.0),
                remaining_usd: f64::INFINITY,
            },
            Some(limit) => self.check_limit_and_alert(agent_id, None, spent, limit),
        }
    }

    /// Check all ancestor budgets without mutating any state.
    ///
    /// `ancestors` is the chain returned by `AgentRegistry::ancestors_of` — first element
    /// is the direct parent, last is the root. Returns the first exhausted ancestor as
    /// `Err(BudgetError::AncestorBudgetExhausted)` so the caller can fast-fail without
    /// applying any spend.
    ///
    /// This is Phase 1 of the two-phase commit used by `check_and_decrement`.
    fn preflight_ancestors(
        &self,
        ancestors: &[[u8; 16]],
        amount: Decimal,
    ) -> Result<(), crate::budget::types::BudgetError> {
        use crate::budget::types::{BudgetError, BudgetKind};
        let today = today_in_tz(self.timezone);
        for &ancestor_bytes in ancestors {
            let ancestor_id = AgentId::from_bytes(ancestor_bytes);
            if let Some(limit) = self.resolve_limit(&ancestor_id, BudgetKind::Daily) {
                let spent = self
                    .per_agent
                    .get(&ancestor_id)
                    .map(|s| {
                        let mut copy = s.clone();
                        copy.maybe_reset(today);
                        copy.spent_usd
                    })
                    .unwrap_or(Decimal::ZERO);
                if spent + amount > limit {
                    return Err(BudgetError::AncestorBudgetExhausted {
                        ancestor_id: ancestor_bytes,
                        kind: BudgetKind::Daily,
                    });
                }
            }
        }
        Ok(())
    }

    /// Atomically check all ancestor budgets then record spend for `agent_id` and every ancestor.
    ///
    /// Callers supply `ancestors` from `AgentRegistry::ancestors_of(agent_id)` so this method
    /// does not require a registry reference. Returns `Err` without touching any `per_agent`
    /// entry if Phase 1 detects an exhausted ancestor.
    pub fn check_and_decrement(
        &self,
        agent_id: AgentId,
        ancestors: &[[u8; 16]],
        amount: Decimal,
    ) -> Result<(), crate::budget::types::BudgetError> {
        // Phase 1: preflight — verify all ancestors have headroom.
        self.preflight_ancestors(ancestors, amount)?;

        // Phase 2: commit — record spend on the agent and every ancestor.
        let today = today_in_tz(self.timezone);
        self.per_agent
            .entry(agent_id)
            .and_modify(|s| {
                s.maybe_reset(today);
                s.spent_usd += amount;
            })
            .or_insert_with(|| {
                let mut s = BudgetState::new_for_date(today);
                s.spent_usd = amount;
                s
            });
        for &ancestor_bytes in ancestors {
            let ancestor_id = AgentId::from_bytes(ancestor_bytes);
            self.per_agent
                .entry(ancestor_id)
                .and_modify(|s| {
                    s.maybe_reset(today);
                    s.spent_usd += amount;
                })
                .or_insert_with(|| {
                    let mut s = BudgetState::new_for_date(today);
                    s.spent_usd = amount;
                    s
                });
        }

        Ok(())
    }

    /// Return the current spend state for a specific team, or `None` if the team has no spend.
    pub fn team_state(&self, team_id: &str) -> Option<BudgetState> {
        self.team_budgets.get(team_id).map(|s| s.clone())
    }

    /// Return a snapshot of the current global (all-agents combined) budget state.
    pub fn global_state(&self) -> BudgetState {
        self.global
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| BudgetState::new_for_date(today_in_tz(self.timezone)))
    }

    /// Snapshot the full tracker state for disk persistence.
    pub fn snapshot(&self) -> crate::budget::persistence::PersistedBudget {
        let per_agent = self
            .per_agent
            .iter()
            .map(|entry| crate::budget::persistence::PersistedAgentEntry {
                agent_id_hex: crate::budget::persistence::agent_id_to_hex(entry.key()),
                state: entry.value().clone(),
            })
            .collect();
        let team_budgets = self
            .team_budgets
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        crate::budget::persistence::PersistedBudget {
            per_agent,
            team_budgets,
            global: self.global_state(),
            timezone: self.timezone,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::pricing::PricingTable;
    use rust_decimal::Decimal;

    fn new_tracker() -> BudgetTracker {
        BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC)
    }

    fn agent(b: u8) -> AgentId {
        AgentId::from_bytes([b; 16])
    }

    fn tracker_with_limit(s: &str) -> BudgetTracker {
        BudgetTracker::new(
            PricingTable::default_table(),
            Some(s.parse().unwrap()),
            None,
            chrono_tz::UTC,
        )
    }

    #[test]
    fn new_tracker_has_empty_per_agent_map() {
        let t = new_tracker();
        assert!(t.per_agent.is_empty());
    }

    #[test]
    fn daily_limit_usd_returns_configured_limit() {
        let t = tracker_with_limit("50.00");
        assert_eq!(t.daily_limit_usd(), Some(Decimal::new(5000, 2)));
    }

    #[test]
    fn daily_limit_usd_returns_none_when_unset() {
        let t = new_tracker();
        assert_eq!(t.daily_limit_usd(), None);
    }

    #[test]
    fn monthly_limit_usd_returns_configured_limit() {
        let t = BudgetTracker::new(
            PricingTable::default_table(),
            None,
            Some("1000.00".parse().unwrap()),
            chrono_tz::UTC,
        );
        assert_eq!(t.monthly_limit_usd(), Some(Decimal::new(100000, 2)));
    }

    #[test]
    fn monthly_limit_usd_returns_none_when_unset() {
        let t = new_tracker();
        assert_eq!(t.monthly_limit_usd(), None);
    }

    #[test]
    fn compute_status_returns_within_budget_below_80() {
        use crate::budget::types::BudgetStatus;
        fn d(s: &str) -> Decimal {
            s.parse().unwrap()
        }
        let status = compute_status(d("7.00"), d("10.00")); // 70%
        assert!(matches!(status, BudgetStatus::WithinBudget { .. }));
    }

    #[test]
    fn compute_status_returns_alert_at_80() {
        use crate::budget::types::BudgetStatus;
        fn d(s: &str) -> Decimal {
            s.parse().unwrap()
        }
        let status = compute_status(d("8.00"), d("10.00")); // exactly 80%
        assert_eq!(status, BudgetStatus::ThresholdAlert { pct: 80 });
    }

    #[test]
    fn compute_status_returns_alert_at_95() {
        use crate::budget::types::BudgetStatus;
        fn d(s: &str) -> Decimal {
            s.parse().unwrap()
        }
        let status = compute_status(d("9.50"), d("10.00")); // exactly 95%
        assert_eq!(status, BudgetStatus::ThresholdAlert { pct: 95 });
    }

    #[test]
    fn compute_status_returns_limit_exceeded_at_100() {
        use crate::budget::types::BudgetStatus;
        fn d(s: &str) -> Decimal {
            s.parse().unwrap()
        }
        assert_eq!(compute_status(d("10.00"), d("10.00")), BudgetStatus::LimitExceeded);
        assert_eq!(compute_status(d("11.00"), d("10.00")), BudgetStatus::LimitExceeded);
    }

    #[test]
    fn record_usage_no_limit_returns_within_budget() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        let t = new_tracker();
        let s = t.record_usage(agent(1), None, Provider::OpenAi, Model::Gpt4o, 100, 100);
        assert!(matches!(s, BudgetStatus::WithinBudget { .. }));
    }

    #[test]
    fn record_usage_over_limit_returns_limit_exceeded() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // GPT-4o: 100k input=$0.50 + 40k output=$0.60 = $1.10 > $1.00 limit
        let t = tracker_with_limit("1.00");
        let s = t.record_usage(agent(2), None, Provider::OpenAi, Model::Gpt4o, 100_000, 40_000);
        assert_eq!(s, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn record_usage_alert_at_80_pct() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // 100k input=$0.50 + 20k output=$0.30 = $0.80 = 80% of $1.00
        let t = tracker_with_limit("1.00");
        let s = t.record_usage(agent(3), None, Provider::OpenAi, Model::Gpt4o, 100_000, 20_000);
        assert_eq!(s, BudgetStatus::ThresholdAlert { pct: 80 });
    }

    #[test]
    fn record_usage_resets_on_old_date() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        let t = tracker_with_limit("1.00");
        let id = agent(4);
        t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100_000, 30_000); // $0.95
        t.per_agent.alter(&id, |_, mut s| {
            s.date = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
            s
        });
        let s = t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100, 0);
        assert!(matches!(s, BudgetStatus::WithinBudget { .. }));
    }

    #[test]
    fn subscribe_alerts_returns_receiver() {
        let t = new_tracker();
        let _rx = t.subscribe_alerts(); // compiles and doesn't panic
    }

    #[test]
    fn with_state_restores_per_agent_entries() {
        use crate::budget::persistence::{agent_id_to_hex, PersistedAgentEntry, PersistedBudget};
        use chrono::Datelike;
        let id = AgentId::from_bytes([42u8; 16]);
        let today = chrono::Utc::now().date_naive();
        let state = BudgetState {
            spent_usd: "5.00".parse::<Decimal>().unwrap(),
            date: today,
            month: today.year() as u32 * 100 + today.month(),
            monthly_spent_usd: None,
        };
        let persisted = PersistedBudget {
            per_agent: vec![PersistedAgentEntry {
                agent_id_hex: agent_id_to_hex(&id),
                state: state.clone(),
            }],
            team_budgets: Default::default(),
            global: BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        };
        let t = BudgetTracker::with_state(PricingTable::default_table(), None, None, persisted);
        let entry = t.per_agent.get(&id).unwrap();
        assert_eq!(entry.spent_usd, state.spent_usd);
        assert_eq!(t.timezone(), chrono_tz::UTC);
    }

    #[test]
    fn snapshot_includes_per_agent_and_global() {
        use crate::budget::types::{Model, Provider};
        let t = new_tracker();
        let id = agent(7);
        t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 1_000, 0);
        let snap = t.snapshot();
        assert_eq!(snap.per_agent.len(), 1);
        assert_eq!(snap.global.spent_usd, snap.per_agent[0].state.spent_usd);
    }

    #[test]
    fn global_state_accumulates_all_agents() {
        use crate::budget::types::{Model, Provider};
        let t = new_tracker();
        t.record_usage(agent(5), None, Provider::OpenAi, Model::Gpt4o, 1_000, 0); // $0.005
        t.record_usage(agent(6), None, Provider::OpenAi, Model::Gpt4o, 1_000, 0); // $0.005
        let g = t.global_state();
        let expected: Decimal = "0.010".parse().unwrap();
        assert_eq!(g.spent_usd, expected);
    }

    #[test]
    fn record_usage_timezone_offset_resets_at_local_midnight() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // Use UTC+9 (Asia/Tokyo). We simulate a stale "yesterday in Tokyo" entry
        // to verify that maybe_reset triggers when the configured timezone's date has advanced.
        let tz = chrono_tz::Asia::Tokyo;
        let t = BudgetTracker::new(PricingTable::default_table(), Some("1.00".parse().unwrap()), None, tz);
        let id = agent(10);
        // First call — establishes the agent entry
        t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100_000, 30_000); // $0.95
                                                                                   // Backdate the agent entry by 1 day in the Tokyo timezone
        let yesterday_tokyo = today_in_tz(tz) - chrono::Duration::days(1);
        t.per_agent.alter(&id, |_, mut s| {
            s.date = yesterday_tokyo;
            s
        });
        // Next call should reset (yesterday < today in Tokyo)
        let s = t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100, 0);
        assert!(
            matches!(s, BudgetStatus::WithinBudget { .. }),
            "Expected reset after Tokyo midnight, got: {:?}",
            s
        );
    }

    fn tracker_with_monthly_limit(monthly: &str) -> BudgetTracker {
        BudgetTracker::new(
            PricingTable::default_table(),
            None,
            Some(monthly.parse().unwrap()),
            chrono_tz::UTC,
        )
    }

    #[test]
    fn monthly_limit_exceeded_blocks_usage() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // Monthly limit $1.00. GPT-4o: 100k input=$0.50 + 40k output=$0.60 = $1.10 > $1.00
        let t = tracker_with_monthly_limit("1.00");
        let s = t.record_usage(agent(20), None, Provider::OpenAi, Model::Gpt4o, 100_000, 40_000);
        assert_eq!(s, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn monthly_within_budget_returns_within_budget() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // Monthly limit $10.00. Small usage should be within budget.
        let t = tracker_with_monthly_limit("10.00");
        let s = t.record_usage(agent(21), None, Provider::OpenAi, Model::Gpt4o, 1_000, 0);
        assert!(matches!(s, BudgetStatus::WithinBudget { .. }));
    }

    #[test]
    fn monthly_accumulates_across_daily_resets() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        // Monthly limit $1.00. Record $0.50 on day 1, backdate, then another $0.60 on day 2.
        let t = tracker_with_monthly_limit("1.00");
        let id = agent(22);
        // Day 1: $0.50 (100k input)
        t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100_000, 0);
        // Backdate the entry by 1 day — daily resets, monthly stays
        t.per_agent.alter(&id, |_, mut s| {
            s.date = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
            s
        });
        // Day 2: another $0.60 (40k output) — total monthly $1.10 > $1.00
        let s = t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 0, 40_000);
        assert_eq!(s, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn monthly_resets_on_month_change() {
        use crate::budget::types::{BudgetStatus, Model, Provider};
        use chrono::Datelike;
        let t = tracker_with_monthly_limit("1.00");
        let id = agent(23);
        // Record $0.95
        t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100_000, 30_000);
        // Backdate to last month — both daily and monthly should reset
        let last_month = chrono::Utc::now().date_naive() - chrono::Duration::days(32);
        t.per_agent.alter(&id, |_, mut s| {
            s.date = last_month;
            s.month = last_month.year() as u32 * 100 + last_month.month();
            s
        });
        // New usage should start fresh — well within budget
        let s = t.record_usage(id, None, Provider::OpenAi, Model::Gpt4o, 100, 0);
        assert!(
            matches!(s, BudgetStatus::WithinBudget { .. }),
            "Expected within budget after monthly reset, got: {:?}",
            s
        );
    }

    // ── check_daily / check_monthly / record_raw_spend ──────────────────

    #[test]
    fn check_daily_returns_false_for_new_agent() {
        let t = tracker_with_limit("10.00");
        assert!(!t.check_daily(&agent(30), "10.00".parse().unwrap()));
    }

    #[test]
    fn check_daily_returns_true_when_exceeded() {
        let t = tracker_with_limit("1.00");
        let id = agent(31);
        t.record_raw_spend(id, None, "1.00".parse().unwrap());
        assert!(t.check_daily(&id, "1.00".parse().unwrap()));
    }

    #[test]
    fn check_monthly_returns_false_for_new_agent() {
        let t = tracker_with_monthly_limit("100.00");
        assert!(!t.check_monthly(&agent(32), "100.00".parse().unwrap()));
    }

    #[test]
    fn check_monthly_returns_true_when_exceeded() {
        let t = tracker_with_monthly_limit("5.00");
        let id = agent(33);
        t.record_raw_spend(id, None, "5.00".parse().unwrap());
        assert!(t.check_monthly(&id, "5.00".parse().unwrap()));
    }

    #[test]
    fn record_raw_spend_accumulates() {
        let t = tracker_with_limit("10.00");
        let id = agent(34);
        t.record_raw_spend(id, None, "3.00".parse().unwrap());
        t.record_raw_spend(id, None, "4.00".parse().unwrap());
        // 7.00 >= 7.00
        assert!(t.check_daily(&id, "7.00".parse().unwrap()));
        // 7.00 < 8.00
        assert!(!t.check_daily(&id, "8.00".parse().unwrap()));
    }

    #[test]
    fn record_raw_spend_fires_80_pct_alert() {
        let t = tracker_with_limit("10.00");
        let mut rx = t.subscribe_alerts();
        let id = agent(35);
        // 8.00 / 10.00 = 80%
        t.record_raw_spend(id, None, "8.00".parse().unwrap());
        let alert = rx.try_recv().expect("expected 80% alert");
        assert_eq!(alert.threshold_pct, 80);
        assert_eq!(alert.agent_id, id);
    }

    #[test]
    fn record_raw_spend_fires_95_pct_alert() {
        let t = tracker_with_limit("10.00");
        let mut rx = t.subscribe_alerts();
        let id = agent(36);
        // 9.50 / 10.00 = 95%
        t.record_raw_spend(id, None, "9.50".parse().unwrap());
        let alert = rx.try_recv().expect("expected 95% alert");
        assert_eq!(alert.threshold_pct, 95);
    }

    #[test]
    fn new_with_alert_sender_uses_external_channel() {
        let (tx, mut rx) = broadcast::channel::<BudgetAlert>(64);
        let t = BudgetTracker::new_with_alert_sender(
            PricingTable::default_table(),
            Some("10.00".parse().unwrap()),
            None,
            chrono_tz::UTC,
            tx,
        );
        let id = agent(37);
        t.record_raw_spend(id, None, "8.00".parse().unwrap());
        let alert = rx.try_recv().expect("alert should arrive on external channel");
        assert_eq!(alert.threshold_pct, 80);
    }

    // ── Ported from engine::budget (simple tracker) ─────────────────────

    #[test]
    fn check_daily_exact_limit_is_exceeded() {
        let t = tracker_with_limit("1.00");
        let id = agent(40);
        t.record_raw_spend(id, None, "1.00".parse().unwrap());
        // 1.00 >= 1.00 is true (not strictly greater)
        assert!(t.check_daily(&id, "1.00".parse().unwrap()));
    }

    #[test]
    fn check_daily_resets_on_new_date() {
        let t = tracker_with_limit("1.00");
        let id = agent(41);
        t.record_raw_spend(id, None, "0.90".parse().unwrap());
        // Backdate the entry to yesterday
        t.per_agent.alter(&id, |_, mut s| {
            s.date = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
            s
        });
        // After date reset, spend should be 0 — not exceeded
        assert!(!t.check_daily(&id, "1.00".parse().unwrap()));
    }

    #[test]
    fn check_monthly_accumulates_raw_spend() {
        let t = tracker_with_monthly_limit("7.00");
        let id = agent(42);
        t.record_raw_spend(id, None, "3.00".parse().unwrap());
        t.record_raw_spend(id, None, "4.00".parse().unwrap());
        // 7.00 >= 7.00
        assert!(t.check_monthly(&id, "7.00".parse().unwrap()));
        // 7.00 < 8.00
        assert!(!t.check_monthly(&id, "8.00".parse().unwrap()));
    }

    #[test]
    fn check_monthly_resets_on_month_change() {
        use chrono::Datelike;
        let t = tracker_with_monthly_limit("5.00");
        let id = agent(43);
        t.record_raw_spend(id, None, "5.00".parse().unwrap());
        // Backdate to last month
        let last_month = chrono::Utc::now().date_naive() - chrono::Duration::days(32);
        t.per_agent.alter(&id, |_, mut s| {
            s.date = last_month;
            s.month = last_month.year() as u32 * 100 + last_month.month();
            s
        });
        // After month change, monthly spend resets — not exceeded
        assert!(!t.check_monthly(&id, "5.00".parse().unwrap()));
    }

    // ── Team limit enforcement (AAASM-1007) ────────────────────────────

    fn tracker_with_team_daily_limit(daily: &str) -> BudgetTracker {
        BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC)
            .with_team_daily_limit(daily.parse().unwrap())
    }

    fn tracker_with_team_monthly_limit(monthly: &str) -> BudgetTracker {
        BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC)
            .with_team_monthly_limit(monthly.parse().unwrap())
    }

    #[test]
    fn team_daily_limit_exceeded_blocks_agent_in_same_team() {
        let t = tracker_with_team_daily_limit("5.00");
        let id = agent(50);
        // Spend $5.00 — exactly at limit
        let status = t.record_raw_spend(id, Some("team-alpha"), "5.00".parse().unwrap());
        assert_eq!(status, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn team_daily_limit_not_exceeded_before_threshold() {
        let t = tracker_with_team_daily_limit("10.00");
        let id = agent(51);
        let status = t.record_raw_spend(id, Some("team-alpha"), "3.00".parse().unwrap());
        assert!(matches!(status, BudgetStatus::WithinBudget { .. }));
    }

    #[test]
    fn team_daily_limit_aggregates_across_multiple_agents() {
        let t = tracker_with_team_daily_limit("5.00");
        let id_a = agent(52);
        let id_b = agent(53);
        // Agent A spends $3.00
        t.record_raw_spend(id_a, Some("team-beta"), "3.00".parse().unwrap());
        // Agent B spends $2.00 — pushes team total to $5.00 (exactly at limit)
        let status = t.record_raw_spend(id_b, Some("team-beta"), "2.00".parse().unwrap());
        assert_eq!(status, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn team_monthly_limit_exceeded_blocks() {
        let t = tracker_with_team_monthly_limit("10.00");
        let id = agent(54);
        let status = t.record_raw_spend(id, Some("team-gamma"), "10.00".parse().unwrap());
        assert_eq!(status, BudgetStatus::LimitExceeded);
    }

    #[test]
    fn team_with_no_team_id_ignores_team_limits() {
        let t = tracker_with_team_daily_limit("1.00");
        let id = agent(55);
        // No team_id — team limit should not apply
        let status = t.record_raw_spend(id, None, "100.00".parse().unwrap());
        assert!(matches!(status, BudgetStatus::WithinBudget { .. }));
    }

    // ── Team threshold alerts (AAASM-1012) ─────────────────────────────

    #[test]
    fn team_daily_80_pct_fires_alert_with_team_id() {
        let t = tracker_with_team_daily_limit("10.00");
        let mut rx = t.subscribe_alerts();
        let id = agent(60);
        // 8.00 / 10.00 = 80%
        t.record_raw_spend(id, Some("team-delta"), "8.00".parse().unwrap());
        let alert = rx.try_recv().expect("expected 80% team alert");
        assert_eq!(alert.threshold_pct, 80);
        assert_eq!(alert.team_id.as_deref(), Some("team-delta"));
    }

    #[test]
    fn team_daily_95_pct_fires_alert_with_team_id() {
        let t = tracker_with_team_daily_limit("10.00");
        let mut rx = t.subscribe_alerts();
        let id = agent(61);
        // 9.50 / 10.00 = 95%
        t.record_raw_spend(id, Some("team-epsilon"), "9.50".parse().unwrap());
        let alert = rx.try_recv().expect("expected 95% team alert");
        assert_eq!(alert.threshold_pct, 95);
        assert_eq!(alert.team_id.as_deref(), Some("team-epsilon"));
    }

    #[test]
    fn team_monthly_80_pct_fires_alert_with_team_id() {
        let t = tracker_with_team_monthly_limit("10.00");
        let mut rx = t.subscribe_alerts();
        let id = agent(62);
        t.record_raw_spend(id, Some("team-zeta"), "8.00".parse().unwrap());
        let alert = rx.try_recv().expect("expected 80% monthly team alert");
        assert_eq!(alert.threshold_pct, 80);
        assert_eq!(alert.team_id.as_deref(), Some("team-zeta"));
    }
}
