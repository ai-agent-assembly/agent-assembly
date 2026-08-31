//! Integration tests for budget persistence round-trip:
//! tracker → snapshot → save → load → restore → verify spend.

use std::sync::Arc;

use aa_core::AgentId;
use aa_gateway::budget::persistence::{load_from_disk, save_to_disk_atomic, PersistedBudget};
use aa_gateway::budget::pricing::PricingTable;
use aa_gateway::budget::tracker::BudgetTracker;
use aa_gateway::budget::types::BudgetAlert;
use rust_decimal::Decimal;
use std::str::FromStr;

fn test_agent_id() -> AgentId {
    AgentId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
}

/// Record spend, save to disk, load back, and confirm the spend survived.
#[test]
fn round_trip_preserves_spend() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");

    let (alert_tx, _rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);

    // 1. Fresh tracker — record some spend.
    let tracker = BudgetTracker::new_with_alert_sender(
        PricingTable::default_table(),
        Some(Decimal::from_str("100.0").unwrap()),
        None,
        chrono_tz::UTC,
        alert_tx.clone(),
    );
    let agent = test_agent_id();
    tracker.record_raw_spend(agent, None, None, Decimal::from_str("42.50").unwrap());

    // 2. Snapshot and persist.
    let snapshot = tracker.snapshot();
    save_to_disk_atomic(&path, &snapshot).unwrap();

    // 3. Load from disk and restore into a new tracker.
    let persisted = load_from_disk(&path).unwrap();
    let restored = BudgetTracker::with_state_and_alert_sender(
        PricingTable::default_table(),
        Some(Decimal::from_str("100.0").unwrap()),
        None,
        persisted,
        alert_tx,
    );

    // 4. Verify the restored tracker kept the spend.
    let restored_snapshot = restored.snapshot();
    assert_eq!(restored_snapshot.per_agent.len(), 1);
    assert_eq!(
        restored_snapshot.per_agent[0].state.spent_usd,
        Decimal::from_str("42.50").unwrap()
    );
    assert_eq!(restored_snapshot.global.spent_usd, Decimal::from_str("42.50").unwrap());
}

/// After restoring, additional spend accumulates on top of the persisted total.
#[test]
fn restored_tracker_accumulates_further_spend() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");

    let (alert_tx, _rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);

    let tracker = BudgetTracker::new_with_alert_sender(
        PricingTable::default_table(),
        Some(Decimal::from_str("100.0").unwrap()),
        None,
        chrono_tz::UTC,
        alert_tx.clone(),
    );
    let agent = test_agent_id();
    tracker.record_raw_spend(agent, None, None, Decimal::from_str("10.00").unwrap());

    let snapshot = tracker.snapshot();
    save_to_disk_atomic(&path, &snapshot).unwrap();

    let persisted = load_from_disk(&path).unwrap();
    let restored = Arc::new(BudgetTracker::with_state_and_alert_sender(
        PricingTable::default_table(),
        Some(Decimal::from_str("100.0").unwrap()),
        None,
        persisted,
        alert_tx,
    ));

    // Record more spend on the restored tracker.
    restored.record_raw_spend(agent, None, None, Decimal::from_str("5.00").unwrap());

    let final_snapshot = restored.snapshot();
    assert_eq!(
        final_snapshot.per_agent[0].state.spent_usd,
        Decimal::from_str("15.00").unwrap()
    );
    assert_eq!(final_snapshot.global.spent_usd, Decimal::from_str("15.00").unwrap());
}

/// Corrupt JSON on disk returns an error from load_from_disk.
#[test]
fn corrupt_file_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");
    std::fs::write(&path, b"NOT VALID JSON {{{").unwrap();
    assert!(load_from_disk(&path).is_err());
}

/// AAASM-5647 — a corrupt file must degrade the tracker, not silently reset
/// it to an enforceable zero-spend state. A seeded/empty balance is not an
/// acceptable outcome for a spend control: it lets every agent spend freely
/// until the file is repaired. Superseded `corrupt_file_fallback_produces_empty_tracker`,
/// which asserted exactly the behaviour this ticket forbids.
#[test]
fn corrupt_file_degrades_tracker_and_denies_every_check() {
    use aa_gateway::budget::persistence::load_or_degrade;
    use aa_gateway::budget::types::BudgetStatus;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");
    std::fs::write(&path, b"NOT VALID JSON {{{").unwrap();

    let (alert_tx, _rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);
    let (degradation_tx, mut degradation_rx) = tokio::sync::broadcast::channel(4);

    let (persisted, degraded) = load_or_degrade(&path, &degradation_tx);
    assert!(degraded);
    match degradation_rx.try_recv().expect("a degradation event was broadcast") {
        aa_runtime::pipeline::PipelineEvent::LayerDegradation(info) => {
            assert_eq!(info.layer, "gateway/budget");
            assert!(info.reason.starts_with("planned="), "reason: {}", info.reason);
        }
        other => panic!("expected LayerDegradation, got {other:?}"),
    }

    let tracker =
        BudgetTracker::with_state_and_alert_sender(PricingTable::default_table(), None, None, persisted, alert_tx)
            .degraded(degraded);
    assert!(tracker.is_degraded());

    // Assert through the artifact that decides, not a seeded balance: every
    // deciding entry point must deny while degraded.
    let agent = test_agent_id();
    assert!(tracker.check_daily(&agent, Decimal::from(1000)));
    assert_eq!(
        tracker.record_raw_spend(agent, None, None, Decimal::from_str("1.00").unwrap()),
        BudgetStatus::LimitExceeded
    );
}

/// Negative control: a valid file must NOT degrade the tracker.
#[test]
fn valid_file_does_not_degrade_tracker() {
    use aa_gateway::budget::persistence::load_or_degrade;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.json");
    let (alert_tx, _rx) = tokio::sync::broadcast::channel::<BudgetAlert>(16);
    save_to_disk_atomic(
        &path,
        &PersistedBudget {
            per_agent: vec![],
            team_budgets: Default::default(),
            global: aa_gateway::budget::types::BudgetState::new_today(),
            timezone: chrono_tz::UTC,
        },
    )
    .unwrap();

    let (degradation_tx, mut degradation_rx) = tokio::sync::broadcast::channel(4);
    let (persisted, degraded) = load_or_degrade(&path, &degradation_tx);
    assert!(!degraded);
    assert!(matches!(
        degradation_rx.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    let tracker =
        BudgetTracker::with_state_and_alert_sender(PricingTable::default_table(), None, None, persisted, alert_tx)
            .degraded(degraded);
    assert!(!tracker.is_degraded());
    let agent = test_agent_id();
    assert!(!tracker.check_daily(&agent, Decimal::from(1000)));
}
