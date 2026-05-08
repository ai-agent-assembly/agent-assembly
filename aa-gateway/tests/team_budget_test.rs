//! Integration tests for per-team budget tracking (AAASM-223 / AAASM-1016).
//!
//! Covers the full AAASM-223 acceptance criteria:
//!   AC1 – record_usage accumulates spend under the agent's team key
//!   AC2 – record_raw_spend also participates in team rollup
//!   AC3 – Budget-check order: agent → team → org; team limit blocks call
//!   AC4 – BudgetAlert fires at 80%/95% of team limits via broadcast channel
//!   AC5 – Team budget state persists through snapshot/with_state and resets daily/monthly
//!   AC6 – Integration: two agents, one team, team limit reached

use aa_core::AgentId;
use aa_gateway::budget::{
    persistence::{load_from_disk, save_to_disk_atomic},
    pricing::PricingTable,
    tracker::BudgetTracker,
    types::{BudgetAlert, BudgetStatus, Model, Provider},
};
use rust_decimal::Decimal;
use std::str::FromStr;

fn agent(b: u8) -> AgentId {
    AgentId::from_bytes([b; 16])
}

fn base_tracker() -> BudgetTracker {
    BudgetTracker::new(PricingTable::default_table(), None, None, chrono_tz::UTC)
}

// AC1: record_usage accumulates spend under the team key.
#[test]
fn record_usage_accumulates_in_team_budgets() {
    let t = base_tracker();
    let id = agent(1);
    t.record_usage(id, Some("team-a"), Provider::OpenAi, Model::Gpt4o, 1_000, 0);
    let state = t.team_state("team-a").expect("team-a must have a state after record_usage");
    assert!(state.spent_usd > Decimal::ZERO, "team-a spend must be non-zero");
}

// AC2: record_raw_spend also rolls up to the team bucket.
#[test]
fn record_raw_spend_accumulates_in_team_budgets() {
    let t = base_tracker();
    let id = agent(2);
    t.record_raw_spend(id, Some("team-b"), Decimal::from_str("7.50").unwrap());
    let state = t.team_state("team-b").expect("team-b must have a state after record_raw_spend");
    assert_eq!(state.spent_usd, Decimal::from_str("7.50").unwrap());
}

// AC3: team limit enforced — two agents sharing a team, combined spend breaches limit.
#[test]
fn team_limit_blocks_second_agent_when_team_total_exceeded() {
    let t = base_tracker().with_team_daily_limit(Decimal::from_str("5.00").unwrap());
    let agent_a = agent(10);
    let agent_b = agent(11);
    // Agent A spends $3.00 — within budget
    let s1 = t.record_raw_spend(agent_a, Some("shared-team"), Decimal::from_str("3.00").unwrap());
    assert!(matches!(s1, BudgetStatus::WithinBudget { .. }), "agent_a should be within budget");
    // Agent B spends $2.00 — pushes team total to $5.00 (exactly at limit)
    let s2 = t.record_raw_spend(agent_b, Some("shared-team"), Decimal::from_str("2.00").unwrap());
    assert_eq!(s2, BudgetStatus::LimitExceeded, "team limit must block agent_b");
}

// AC3: individual agent spend below team limit still passes.
#[test]
fn individual_agent_below_team_limit_is_not_blocked() {
    let t = base_tracker().with_team_daily_limit(Decimal::from_str("10.00").unwrap());
    let s = t.record_raw_spend(agent(12), Some("solo-team"), Decimal::from_str("3.00").unwrap());
    assert!(matches!(s, BudgetStatus::WithinBudget { .. }));
}

// AC4: BudgetAlert fires at 80% of team daily limit with correct team_id.
#[test]
fn budget_alert_fires_at_80_pct_of_team_daily_limit() {
    let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);
    let t = BudgetTracker::new_with_alert_sender(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
        alert_tx,
    )
    .with_team_daily_limit(Decimal::from_str("10.00").unwrap());

    // 8.00 / 10.00 = 80%
    t.record_raw_spend(agent(20), Some("alert-team"), Decimal::from_str("8.00").unwrap());
    let alert = alert_rx.try_recv().expect("expected 80% alert");
    assert_eq!(alert.threshold_pct, 80);
    assert_eq!(alert.team_id.as_deref(), Some("alert-team"));
}

// AC4: BudgetAlert fires at 95% of team daily limit.
#[test]
fn budget_alert_fires_at_95_pct_of_team_daily_limit() {
    let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);
    let t = BudgetTracker::new_with_alert_sender(
        PricingTable::default_table(),
        None,
        None,
        chrono_tz::UTC,
        alert_tx,
    )
    .with_team_daily_limit(Decimal::from_str("10.00").unwrap());

    // 9.50 / 10.00 = 95%
    t.record_raw_spend(agent(21), Some("alert-team-95"), Decimal::from_str("9.50").unwrap());
    let alert = alert_rx.try_recv().expect("expected 95% alert");
    assert_eq!(alert.threshold_pct, 95);
    assert_eq!(alert.team_id.as_deref(), Some("alert-team-95"));
}

// AC5: Team budget state persists through snapshot/with_state round-trip.
#[test]
fn team_budget_persists_through_snapshot_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");

    let t = base_tracker();
    t.record_raw_spend(agent(30), Some("persist-team"), Decimal::from_str("4.20").unwrap());

    let snap = t.snapshot();
    assert!(snap.team_budgets.contains_key("persist-team"), "snapshot must include team");

    save_to_disk_atomic(&path, &snap).unwrap();
    let loaded = load_from_disk(&path).unwrap();
    let restored = BudgetTracker::with_state(PricingTable::default_table(), None, None, loaded);

    let state = restored.team_state("persist-team").expect("team must be restored");
    assert_eq!(state.spent_usd, Decimal::from_str("4.20").unwrap());
}

// AC5: Team daily spend resets when date advances (via snapshot manipulation).
#[test]
fn team_daily_spend_resets_on_date_advance() {
    let t = base_tracker().with_team_daily_limit(Decimal::from_str("5.00").unwrap());
    let id = agent(31);

    // Spend at limit — subsequent calls should be blocked
    t.record_raw_spend(id, Some("reset-team"), Decimal::from_str("5.00").unwrap());
    let before = t.record_raw_spend(agent(32), Some("reset-team"), Decimal::from_str("0.01").unwrap());
    assert_eq!(before, BudgetStatus::LimitExceeded, "should be blocked before reset");

    // Take snapshot, backdate the team entry by 1 day, restore into a new tracker
    let mut snap = t.snapshot();
    if let Some(team_state) = snap.team_budgets.get_mut("reset-team") {
        team_state.date = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
    }
    let restored = BudgetTracker::with_state(PricingTable::default_table(), None, None, snap)
        .with_team_daily_limit(Decimal::from_str("5.00").unwrap());

    // After date advance, team spend resets — new call should be within budget
    let s = restored.record_raw_spend(agent(33), Some("reset-team"), Decimal::from_str("1.00").unwrap());
    assert!(matches!(s, BudgetStatus::WithinBudget { .. }), "team spend must reset after date advance");
}
