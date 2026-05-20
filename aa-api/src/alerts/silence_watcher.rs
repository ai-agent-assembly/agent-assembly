//! Background task that restores alerts when their silence expires.
//!
//! Runs every [`TICK_INTERVAL`] and drains expired records from the
//! [`SilenceStore`](super::silence_store::SilenceStore), calling
//! [`AlertStore::restore`](super::AlertStore::restore) on each so the
//! alert returns to its pre-suppression status.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use super::silence_store::SilenceStore;
use super::AlertStore;

/// Cadence of the expiry watcher. Trades off restoration latency
/// against background-task CPU cost. 1 s is fine for human-scale
/// silences (5 m / 1 h / 4 h / 24 h per the AAASM-1387 spec).
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// One pass of the expiry loop — drains all silences expired at `now`
/// and restores the underlying alerts. Pure function (modulo store
/// mutations) so tests can drive it without sleeping.
///
/// Returns the number of silences expired this tick.
pub fn tick<S, A>(silence_store: &S, alert_store: &A, now: chrono::DateTime<Utc>) -> usize
where
    S: SilenceStore + ?Sized,
    A: AlertStore + ?Sized,
{
    let expired = silence_store.expire_due(now);
    let count = expired.len();
    for record in expired {
        // Best-effort: a silence whose alert was evicted from the ring
        // buffer simply restores nothing — that's not an error.
        let _ = alert_store.restore(&record.alert_id);
    }
    count
}

/// Spawn the expiry watcher as a tokio task.
///
/// The task runs until either store handle is dropped from every
/// non-task owner (the watcher itself holds one each, so practically
/// "until shutdown"). It uses [`tokio::time::sleep`] between ticks so
/// the runtime can park it cleanly.
pub fn spawn_silence_expiry_watcher(
    silence_store: Arc<dyn SilenceStore>,
    alert_store: Arc<dyn AlertStore>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK_INTERVAL).await;
            tick(silence_store.as_ref(), alert_store.as_ref(), Utc::now());
        }
    })
}

#[cfg(test)]
mod tests {
    use aa_core::AgentId;
    use aa_gateway::budget::types::BudgetAlert;
    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::alerts::silence::SilenceRecord;
    use crate::alerts::silence_store::InMemorySilenceStore;
    use crate::alerts::store::InMemoryAlertStore;

    fn budget_alert() -> BudgetAlert {
        BudgetAlert {
            agent_id: AgentId::from_bytes([0xAA; 16]),
            team_id: None,
            threshold_pct: 80,
            spent_usd: 8.0,
            limit_usd: 10.0,
        }
    }

    #[tokio::test]
    async fn tick_restores_alert_when_silence_expires() {
        let alert_store = InMemoryAlertStore::new();
        let silence_store = InMemorySilenceStore::new();
        let alert_id = alert_store.record(&budget_alert());
        alert_store.suppress(&alert_id).unwrap();

        let expires_at = Utc::now() - ChronoDuration::seconds(1); // already expired
        silence_store.insert(SilenceRecord {
            id: "sil-1".to_string(),
            alert_id: alert_id.clone(),
            starts_at: Utc::now().to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            reason: None,
            created_by: "user_test".to_string(),
        });

        let expired = tick(&silence_store, &alert_store, Utc::now());
        assert_eq!(expired, 1);

        let restored = alert_store.get_by_id(&alert_id).unwrap();
        assert_eq!(restored.status, "unresolved", "alert must be restored");
        assert!(restored.prior_status.is_none(), "prior_status must be cleared");
    }

    #[tokio::test]
    async fn tick_does_nothing_when_no_silence_is_due() {
        let alert_store = InMemoryAlertStore::new();
        let silence_store = InMemorySilenceStore::new();
        let alert_id = alert_store.record(&budget_alert());
        alert_store.suppress(&alert_id).unwrap();

        let future = Utc::now() + ChronoDuration::hours(1);
        silence_store.insert(SilenceRecord {
            id: "sil-1".to_string(),
            alert_id: alert_id.clone(),
            starts_at: Utc::now().to_rfc3339(),
            expires_at: future.to_rfc3339(),
            reason: None,
            created_by: "user_test".to_string(),
        });

        let expired = tick(&silence_store, &alert_store, Utc::now());
        assert_eq!(expired, 0);

        let still_suppressed = alert_store.get_by_id(&alert_id).unwrap();
        assert_eq!(still_suppressed.status, "suppressed");
    }

    #[tokio::test]
    async fn tick_handles_silence_for_unknown_alert_gracefully() {
        let alert_store = InMemoryAlertStore::new();
        let silence_store = InMemorySilenceStore::new();
        // Silence references an alert that doesn't exist in the store
        // (e.g. evicted from the ring buffer between create and expiry).
        let expired_at = Utc::now() - ChronoDuration::seconds(1);
        silence_store.insert(SilenceRecord {
            id: "sil-orphan".to_string(),
            alert_id: "ghost-alert-id".to_string(),
            starts_at: Utc::now().to_rfc3339(),
            expires_at: expired_at.to_rfc3339(),
            reason: None,
            created_by: "user_test".to_string(),
        });

        // Must not panic — restore returns None and we move on.
        let expired = tick(&silence_store, &alert_store, Utc::now());
        assert_eq!(expired, 1);
    }
}
