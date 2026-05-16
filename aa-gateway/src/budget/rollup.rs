//! Budget rollup composer (AAASM-1051 / F100).
//!
//! Composes per-scope budget rows for a single agent — its own spend, the
//! team it belongs to (if any), the global / org-wide totals, and the spend
//! across its delegation subtree — using the existing read-only accessors on
//! [`BudgetTracker`]. The output drives both:
//!
//! * `GET /api/v1/agents/{id}/budget` for the dashboard and SDK clients;
//! * `aasm policy show <agent_id> --show-budget` for the CLI.

use rust_decimal::Decimal;

use aa_core::AgentId;

use super::tracker::BudgetTracker;

/// A single budget row, scoped to one tier (agent / team / org / subtree) and
/// one period (daily / monthly / today). Sortable rows for table rendering.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetRow {
    /// Human-readable scope label: `"agent"`, `"team:<id>"`, `"org"`, `"subtree"`.
    pub scope: String,
    /// Period the row covers: `"daily"`, `"monthly"`, or `"today"` (subtree only).
    pub period: String,
    /// Total USD spent in the period.
    pub spent_usd: Decimal,
    /// Configured limit for the period, if any.
    pub limit_usd: Option<Decimal>,
    /// `limit_usd - spent_usd`, clamped at zero. `None` when no limit configured.
    pub remaining_usd: Option<Decimal>,
    /// `spent_usd / limit_usd * 100`. `None` when no limit configured.
    pub percent_used: Option<f64>,
}

/// Aggregated budget view for one agent, ordered narrowest-scope first.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetRollup {
    pub rows: Vec<BudgetRow>,
}

/// Build a [`BudgetRollup`] for the given agent.
///
/// * `agent_id` — agent being inspected.
/// * `team_id` — the agent's team membership (from the registry / lineage),
///   or `None` if the agent does not belong to any team. When `None` no
///   `team:*` rows are emitted.
/// * `tracker` — the live [`BudgetTracker`] from `AppState`.
/// * `descendants` — `AgentRegistry::descendants_of(agent_id)`. Pass an empty
///   slice when the agent has no descendants — the `subtree` row is then
///   omitted.
/// * `global_daily_limit_usd` / `global_monthly_limit_usd` — org-wide limits
///   from the policy document. The tracker also exposes these via its own
///   accessors, but callers may want to override (e.g. a per-team policy that
///   tightens the org limit). Defaults to `tracker`'s configured limits when
///   `None` is passed.
pub fn compute_budget_rollup(
    agent_id: &AgentId,
    team_id: Option<&str>,
    tracker: &BudgetTracker,
    descendants: &[[u8; 16]],
    global_daily_limit_usd: Option<Decimal>,
    global_monthly_limit_usd: Option<Decimal>,
) -> BudgetRollup {
    let mut rows = Vec::with_capacity(8);

    let agent_daily_limit = global_daily_limit_usd.or_else(|| tracker.daily_limit_usd());
    let agent_monthly_limit = global_monthly_limit_usd.or_else(|| tracker.monthly_limit_usd());

    // ── Agent rows ─────────────────────────────────────────────────────────
    if let Some(state) = tracker.agent_state(agent_id) {
        rows.push(make_row("agent", "daily", state.spent_usd, agent_daily_limit));
        if let Some(monthly) = state.monthly_spent_usd {
            rows.push(make_row("agent", "monthly", monthly, agent_monthly_limit));
        }
    } else {
        // No recorded spend yet — still emit a zero-spent agent row so the
        // CLI / dashboard surface the limits to the operator.
        rows.push(make_row("agent", "daily", Decimal::ZERO, agent_daily_limit));
        rows.push(make_row("agent", "monthly", Decimal::ZERO, agent_monthly_limit));
    }

    // ── Team rows ──────────────────────────────────────────────────────────
    if let Some(team) = team_id {
        if let Some(state) = tracker.team_state(team) {
            let scope = format!("team:{team}");
            rows.push(make_row(&scope, "daily", state.spent_usd, None));
            if let Some(monthly) = state.monthly_spent_usd {
                rows.push(make_row(&scope, "monthly", monthly, None));
            }
        }
    }

    // ── Org rows ───────────────────────────────────────────────────────────
    let global = tracker.global_state();
    rows.push(make_row("org", "daily", global.spent_usd, agent_daily_limit));
    if let Some(monthly) = global.monthly_spent_usd {
        rows.push(make_row("org", "monthly", monthly, agent_monthly_limit));
    }

    // ── Subtree row ────────────────────────────────────────────────────────
    if !descendants.is_empty() {
        let subtree = tracker.subtree_spend(agent_id, descendants);
        rows.push(make_row("subtree", "today", subtree.usd, None));
    }

    BudgetRollup { rows }
}

fn make_row(scope: &str, period: &str, spent_usd: Decimal, limit_usd: Option<Decimal>) -> BudgetRow {
    let (remaining_usd, percent_used) = match limit_usd {
        Some(limit) if limit > Decimal::ZERO => {
            let remaining = (limit - spent_usd).max(Decimal::ZERO);
            // Convert to f64 only for the percent_used display value. Spend / limit are
            // tracked as Decimal everywhere else.
            let pct = (spent_usd / limit) * Decimal::from(100);
            let pct_f64 = pct.to_string().parse::<f64>().ok();
            (Some(remaining), pct_f64)
        }
        _ => (None, None),
    };

    BudgetRow {
        scope: scope.to_string(),
        period: period.to_string(),
        spent_usd,
        limit_usd,
        remaining_usd,
        percent_used,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::pricing::PricingTable;
    use rust_decimal::Decimal;

    fn agent(byte: u8) -> AgentId {
        AgentId::from_bytes([byte; 16])
    }

    /// Build a tracker with no limits and seed agent / team spend via the
    /// public `record_raw_spend` path. Mirrors the existing test fixtures in
    /// this crate.
    fn tracker_with_spend(seed: &[(AgentId, Option<&str>, Decimal)]) -> BudgetTracker {
        let tracker = BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC);
        for (agent_id, team_id, amount) in seed {
            tracker.record_raw_spend(*agent_id, *team_id, *amount);
        }
        tracker
    }

    #[test]
    fn rollup_emits_agent_org_rows_when_no_team_no_descendants() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, None, Decimal::new(125, 2))]); // 1.25 USD

        let rollup = compute_budget_rollup(&a, None, &tracker, &[], None, None);

        // `record_raw_spend` without a monthly limit leaves `monthly_spent_usd`
        // as `None`, so the rollup contains agent.daily + org.daily only.
        assert_eq!(rollup.rows.len(), 2);
        assert_eq!(rollup.rows[0].scope, "agent");
        assert_eq!(rollup.rows[0].period, "daily");
        assert_eq!(rollup.rows[0].spent_usd, Decimal::new(125, 2));
        assert!(rollup.rows.iter().any(|r| r.scope == "org" && r.period == "daily"));
        assert!(rollup.rows.iter().all(|r| r.scope != "subtree"));
        assert!(rollup.rows.iter().all(|r| !r.scope.starts_with("team:")));
    }

    #[test]
    fn rollup_with_no_recorded_spend_still_emits_agent_rows_at_zero() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[]);

        let rollup = compute_budget_rollup(&a, None, &tracker, &[], None, None);

        let agent_daily = rollup
            .rows
            .iter()
            .find(|r| r.scope == "agent" && r.period == "daily")
            .expect("zero-spend agent should still emit an agent.daily row");
        assert_eq!(agent_daily.spent_usd, Decimal::ZERO);
    }

    #[test]
    fn rollup_emits_team_rows_when_team_present() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, Some("eng-platform"), Decimal::new(2500, 2))]);

        let rollup = compute_budget_rollup(&a, Some("eng-platform"), &tracker, &[], None, None);

        assert!(
            rollup.rows.iter().any(|r| r.scope == "team:eng-platform"),
            "expected a team:eng-platform row"
        );
    }

    #[test]
    fn rollup_omits_team_rows_when_team_absent_from_tracker() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, None, Decimal::ONE)]);

        let rollup = compute_budget_rollup(&a, Some("nonexistent-team"), &tracker, &[], None, None);

        assert!(rollup.rows.iter().all(|r| !r.scope.starts_with("team:")));
    }

    #[test]
    fn rollup_emits_subtree_row_when_descendants_present() {
        let parent = agent(0xAA);
        let child = agent(0xBB);
        let tracker = tracker_with_spend(&[(child, None, Decimal::new(7500, 2))]);

        let rollup = compute_budget_rollup(&parent, None, &tracker, &[*child.as_bytes()], None, None);

        let subtree = rollup
            .rows
            .iter()
            .find(|r| r.scope == "subtree")
            .expect("subtree row should be present");
        assert_eq!(subtree.period, "today");
        // Parent has no spend; child has 75 USD; subtree reflects child only.
        assert_eq!(subtree.spent_usd, Decimal::new(7500, 2));
    }

    #[test]
    fn rollup_percent_used_and_remaining_computed_when_limit_present() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, None, Decimal::from(50))]);

        let rollup = compute_budget_rollup(
            &a,
            None,
            &tracker,
            &[],
            Some(Decimal::from(200)), // daily limit 200 USD
            None,
        );

        let daily = rollup
            .rows
            .iter()
            .find(|r| r.scope == "agent" && r.period == "daily")
            .expect("agent daily row");
        assert_eq!(daily.limit_usd, Some(Decimal::from(200)));
        assert_eq!(daily.remaining_usd, Some(Decimal::from(150)));
        assert_eq!(daily.percent_used, Some(25.0));
    }

    #[test]
    fn rollup_remaining_clamped_at_zero_when_over_limit() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, None, Decimal::from(300))]);

        let rollup = compute_budget_rollup(&a, None, &tracker, &[], Some(Decimal::from(200)), None);

        let daily = rollup
            .rows
            .iter()
            .find(|r| r.scope == "agent" && r.period == "daily")
            .unwrap();
        assert_eq!(daily.remaining_usd, Some(Decimal::ZERO));
        assert_eq!(daily.percent_used, Some(150.0));
    }

    #[test]
    fn rollup_no_limit_means_no_remaining_or_percent() {
        let a = agent(0xAA);
        let tracker = tracker_with_spend(&[(a, None, Decimal::from(10))]);

        let rollup = compute_budget_rollup(&a, None, &tracker, &[], None, None);

        let agent_daily = rollup
            .rows
            .iter()
            .find(|r| r.scope == "agent" && r.period == "daily")
            .unwrap();
        assert_eq!(agent_daily.limit_usd, None);
        assert_eq!(agent_daily.remaining_usd, None);
        assert_eq!(agent_daily.percent_used, None);
    }
}
