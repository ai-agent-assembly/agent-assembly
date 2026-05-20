//! In-memory alert store backed by a bounded ring buffer.

use std::collections::VecDeque;
use std::sync::{Mutex, RwLock};

use aa_gateway::alerts::SecretAlert;
use aa_gateway::budget::types::BudgetAlert;
use tokio::sync::broadcast;
use ulid::Generator;

use super::{
    stored_alert_from, stored_rule_alert_from, stored_secret_alert_from, AlertEvent, AlertStore, RuleAlertSeed,
    StoredAlert,
};

/// Capacity of the per-store `tokio::broadcast` channel used for the
/// `AlertEvent` lifecycle bus. Subscribers that lag past this many
/// pending events get a `RecvError::Lagged` and must reconcile state
/// from the store directly.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Default maximum number of alerts retained in the ring buffer.
const DEFAULT_CAPACITY: usize = 10_000;

/// In-memory alert store using a `VecDeque` ring buffer.
///
/// When the buffer reaches capacity, the oldest alert is evicted on each
/// new insertion. Thread-safe via `RwLock`.
pub struct InMemoryAlertStore {
    alerts: RwLock<VecDeque<StoredAlert>>,
    capacity: usize,
    /// Monotonic ULID generator. The `ulid` crate's `Generator` increments
    /// the random portion within a single millisecond so IDs sort by
    /// insertion order even at sub-millisecond record rates.
    id_gen: Mutex<Generator>,
    /// Lifecycle event sender. Retained on `self` so the bus stays open
    /// even when no subscriber is currently attached — late subscribers
    /// receive events from the moment of their `subscribe()` call.
    event_tx: broadcast::Sender<AlertEvent>,
}

impl InMemoryAlertStore {
    /// Create a new store with the default capacity (10,000 alerts).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new store with the given maximum capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY))),
            capacity,
            id_gen: Mutex::new(Generator::new()),
            event_tx,
        }
    }

    fn next_id(&self) -> String {
        self.id_gen
            .lock()
            .expect("id generator lock poisoned")
            .generate()
            .expect("ULID monotonic generation overflow (impossible in normal operation)")
            .to_string()
    }
}

impl Default for InMemoryAlertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertStore for InMemoryAlertStore {
    fn record(&self, alert: &BudgetAlert) -> String {
        let id = self.next_id();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let stored = stored_alert_from(alert, id.clone(), timestamp);

        {
            let mut buf = self.alerts.write().expect("alert store lock poisoned");
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(stored.clone());
        }
        // Best-effort publish; ignore `SendError` when no subscriber is attached.
        let _ = self.event_tx.send(AlertEvent::Fire(stored));
        id
    }

    fn record_secret(&self, alert: &SecretAlert) -> String {
        let id = self.next_id();
        let timestamp = chrono::Utc::now().to_rfc3339();
        let stored = stored_secret_alert_from(alert, id.clone(), timestamp);

        {
            let mut buf = self.alerts.write().expect("alert store lock poisoned");
            if buf.len() >= self.capacity {
                buf.pop_front();
            }
            buf.push_back(stored.clone());
        }
        let _ = self.event_tx.send(AlertEvent::Fire(stored));
        id
    }

    fn record_rule_alert(&self, seed: &RuleAlertSeed) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let stored = stored_rule_alert_from(seed, id, timestamp);

        let mut buf = self.alerts.write().expect("alert store lock poisoned");
        if buf.len() >= self.capacity {
            buf.pop_front();
        }
        buf.push_back(stored);
        id
    }

    fn list(&self, limit: usize, offset: usize) -> (Vec<StoredAlert>, u64) {
        let buf = self.alerts.read().expect("alert store lock poisoned");
        let total = buf.len() as u64;

        // Return newest-first by iterating in reverse.
        let items: Vec<StoredAlert> = buf.iter().rev().skip(offset).take(limit).cloned().collect();

        (items, total)
    }

    fn get_by_id(&self, id: &str) -> Option<StoredAlert> {
        let buf = self.alerts.read().expect("alert store lock poisoned");
        buf.iter().find(|a| a.id == id).cloned()
    }

    fn resolve(&self, id: &str, _reason: Option<&str>) -> Option<StoredAlert> {
        let (snapshot, was_mutation) = {
            let mut buf = self.alerts.write().expect("alert store lock poisoned");
            let alert = buf.iter_mut().find(|a| a.id == id)?;
            // Idempotent: don't bump timestamps on subsequent resolves.
            let mutated = alert.status != "resolved";
            if mutated {
                let now = chrono::Utc::now().to_rfc3339();
                alert.status = "resolved".to_string();
                alert.updated_at = Some(now.clone());
                alert.resolved_at = Some(now);
            }
            (alert.clone(), mutated)
        };
        if was_mutation {
            let _ = self.event_tx.send(AlertEvent::Resolve(snapshot.clone()));
        }
        Some(snapshot)
    }

    fn subscribe(&self) -> broadcast::Receiver<AlertEvent> {
        self.event_tx.subscribe()
    }

    fn suppress(&self, id: &str) -> Option<StoredAlert> {
        let snapshot = {
            let mut buf = self.alerts.write().expect("alert store lock poisoned");
            let alert = buf.iter_mut().find(|a| a.id == id)?;
            if alert.status == "suppressed" {
                // Defensive: refuse to overwrite an existing prior_status.
                return None;
            }
            alert.prior_status = Some(alert.status.clone());
            alert.status = "suppressed".to_string();
            alert.updated_at = Some(chrono::Utc::now().to_rfc3339());
            alert.clone()
        };
        let _ = self.event_tx.send(AlertEvent::Silence(snapshot.clone()));
        Some(snapshot)
    }

    fn restore(&self, id: &str) -> Option<StoredAlert> {
        let mut buf = self.alerts.write().expect("alert store lock poisoned");
        let alert = buf.iter_mut().find(|a| a.id == id)?;
        if alert.status != "suppressed" {
            return None; // not currently under a silence
        }
        let prior = alert.prior_status.take().unwrap_or_else(|| "unresolved".to_string());
        alert.status = prior;
        alert.updated_at = Some(chrono::Utc::now().to_rfc3339());
        Some(alert.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::AgentId;
    use aa_core::CredentialKind;

    fn test_alert(threshold_pct: u8) -> BudgetAlert {
        BudgetAlert {
            agent_id: AgentId::from_bytes([1u8; 16]),
            team_id: None,
            threshold_pct,
            spent_usd: 8.0,
            limit_usd: 10.0,
        }
    }

    fn test_secret_alert(kind: CredentialKind) -> SecretAlert {
        SecretAlert {
            agent_id: AgentId::from_bytes([0xAB; 16]),
            team_id: Some("team-pioneer".to_string()),
            kinds: vec![kind],
            finding_count: 1,
        }
    }

    #[test]
    fn record_and_list_single_alert() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        assert_eq!(id.len(), 26, "ULID is always 26 chars");

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, id);
        assert_eq!(items[0].threshold_pct, 80);
    }

    #[test]
    fn list_returns_newest_first() {
        let store = InMemoryAlertStore::new();
        let id_old = store.record(&test_alert(80));
        let id_new = store.record(&test_alert(95));

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 2);
        assert_eq!(items[0].id, id_new); // newest
        assert_eq!(items[1].id, id_old); // oldest
    }

    #[test]
    fn list_pagination_limit_and_offset() {
        let store = InMemoryAlertStore::new();
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(store.record(&test_alert(80 + i)));
        }

        // Page 1: limit=2, offset=0 → newest two (ids[4], ids[3])
        let (items, total) = store.list(2, 0);
        assert_eq!(total, 5);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, ids[4]);
        assert_eq!(items[1].id, ids[3]);

        // Page 2: limit=2, offset=2 → ids[2], ids[1]
        let (items, _) = store.list(2, 2);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, ids[2]);
        assert_eq!(items[1].id, ids[1]);

        // Page 3: limit=2, offset=4 → ids[0]
        let (items, _) = store.list(2, 4);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, ids[0]);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = InMemoryAlertStore::with_capacity(3);
        let id1 = store.record(&test_alert(70));
        let id2 = store.record(&test_alert(80));
        let _id3 = store.record(&test_alert(90));
        let id4 = store.record(&test_alert(95)); // evicts id1

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 3);
        assert_eq!(items[0].id, id4); // newest
        assert_eq!(items[2].id, id2); // oldest still retained
        assert!(!items.iter().any(|a| a.id == id1), "id1 was evicted");
    }

    #[test]
    fn empty_store_returns_empty_list() {
        let store = InMemoryAlertStore::new();
        let (items, total) = store.list(10, 0);
        assert_eq!(total, 0);
        assert!(items.is_empty());
    }

    #[test]
    fn severity_derived_correctly() {
        let store = InMemoryAlertStore::new();
        store.record(&test_alert(50));
        store.record(&test_alert(80));
        store.record(&test_alert(95));

        let (items, _) = store.list(10, 0);
        // newest first: 95, 80, 50
        assert_eq!(items[0].severity, super::super::AlertSeverity::Critical);
        assert_eq!(items[1].severity, super::super::AlertSeverity::Warning);
        assert_eq!(items[2].severity, super::super::AlertSeverity::Info);
    }

    #[test]
    fn get_returns_some_for_known_id_and_none_for_unknown() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));

        let found = store.get_by_id(&id).expect("known id should return Some");
        assert_eq!(found.id, id);
        assert_eq!(found.threshold_pct, 95);
        assert_eq!(found.status, "unresolved");

        assert!(
            store.get_by_id("00000000000000000000000000").is_none(),
            "unknown id returns None"
        );
    }

    #[test]
    fn get_returns_none_after_eviction() {
        let store = InMemoryAlertStore::with_capacity(2);
        let id1 = store.record(&test_alert(70)); // evicted after id3 lands
        store.record(&test_alert(80));
        store.record(&test_alert(90));

        assert!(store.get_by_id(&id1).is_none(), "evicted id should return None");
    }

    #[test]
    fn resolve_flips_status_and_sets_updated_at() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));
        let before = store.get_by_id(&id).unwrap();
        assert_eq!(before.status, "unresolved");
        assert!(before.updated_at.is_none());

        let after = store.resolve(&id, Some("ack")).expect("known id resolves");
        assert_eq!(after.status, "resolved");
        assert!(after.updated_at.is_some());
        assert_eq!(
            after.resolved_at, after.updated_at,
            "resolved_at must be set in lockstep with updated_at on the first resolve",
        );

        let from_store = store.get_by_id(&id).unwrap();
        assert_eq!(from_store.status, "resolved");
        assert_eq!(from_store.updated_at, after.updated_at);
    }

    #[test]
    fn resolve_is_idempotent_on_repeat_calls() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));

        let first = store.resolve(&id, None).unwrap();
        let first_ts = first.updated_at.clone();

        // Second call: same record, same updated_at (no double-mutation).
        let second = store.resolve(&id, Some("again")).unwrap();
        assert_eq!(second.status, "resolved");
        assert_eq!(second.updated_at, first_ts);
    }

    #[test]
    fn resolve_returns_none_for_unknown_id() {
        let store = InMemoryAlertStore::new();
        store.record(&test_alert(80));
        assert!(store.resolve("00000000000000000000000000", None).is_none());
    }

    #[test]
    fn ids_are_unique_and_lexicographically_increasing() {
        let store = InMemoryAlertStore::new();
        let id1 = store.record(&test_alert(80));
        let id2 = store.record(&test_alert(90));
        let id3 = store.record(&test_alert(95));
        assert_eq!(id1.len(), 26);
        assert_eq!(id2.len(), 26);
        assert_eq!(id3.len(), 26);
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        // ULID is lexicographically ordered by timestamp.
        assert!(id1 < id2, "ids must sort by insertion order ({id1} < {id2})");
        assert!(id2 < id3, "ids must sort by insertion order ({id2} < {id3})");
    }

    #[test]
    fn record_secret_round_trips_critical_secret_detected() {
        let store = InMemoryAlertStore::new();
        let id = store.record_secret(&test_secret_alert(CredentialKind::AwsAccessKey));

        let found = store.get_by_id(&id).expect("recorded secret alert must be retrievable");
        assert_eq!(found.severity, super::super::AlertSeverity::Critical);
        assert_eq!(found.category, super::super::AlertCategory::SecretDetected);
        assert_eq!(found.detected_pattern_type.as_deref(), Some("AwsAccessKey"));
        assert_eq!(found.redacted_value.as_deref(), Some("[REDACTED:AwsAccessKey]"));
        assert_eq!(found.status, "unresolved");
    }

    #[test]
    fn legacy_alert_constructors_default_rule_context_to_none() {
        let store = InMemoryAlertStore::new();
        let budget_id = store.record(&test_alert(80));
        let secret_id = store.record_secret(&test_secret_alert(CredentialKind::AwsAccessKey));

        let budget = store.get_by_id(&budget_id).expect("budget alert");
        let secret = store.get_by_id(&secret_id).expect("secret alert");

        for stored in [&budget, &secret] {
            assert!(
                stored.rule_context.is_none(),
                "legacy alerts must not carry a rule_context",
            );
            assert!(!stored.first_fired_at.is_empty(), "first_fired_at must be populated",);
            assert_eq!(
                stored.first_fired_at, stored.timestamp,
                "first_fired_at must mirror timestamp for legacy alerts",
            );
            assert!(stored.resolved_at.is_none(), "resolved_at must be None pre-resolve");
        }
    }

    #[test]
    fn record_and_record_secret_produce_distinct_ulids() {
        let store = InMemoryAlertStore::new();
        let budget_id = store.record(&test_alert(80));
        let secret_id = store.record_secret(&test_secret_alert(CredentialKind::OpenAiKey));
        assert_ne!(budget_id, secret_id);
        assert!(budget_id < secret_id, "ULIDs sort by timestamp");
    }

    // ─── AlertEvent bus (AAASM-1645) ─────────────────────────────────────────

    #[tokio::test]
    async fn subscribe_receives_fire_on_record() {
        let store = InMemoryAlertStore::new();
        let mut rx = store.subscribe();
        let id = store.record(&test_alert(80));
        match rx.recv().await.expect("event must arrive") {
            AlertEvent::Fire(stored) => assert_eq!(stored.id, id),
            other => panic!("expected Fire, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_receives_resolve_only_on_state_change() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        let mut rx = store.subscribe();
        store.resolve(&id, None).unwrap();
        match rx.recv().await.expect("first resolve emits") {
            AlertEvent::Resolve(stored) => assert_eq!(stored.status, "resolved"),
            other => panic!("expected Resolve, got {other:?}"),
        }
        // Second (idempotent) resolve must not emit a second event.
        store.resolve(&id, None).unwrap();
        let res = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        assert!(res.is_err(), "no event should arrive on idempotent re-resolve");
    }

    // ─── suppress / restore (AAASM-1645) ─────────────────────────────────────

    #[test]
    fn suppress_flips_status_and_saves_prior_status() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));

        let suppressed = store.suppress(&id).expect("suppress must succeed");
        assert_eq!(suppressed.status, "suppressed");
        assert_eq!(suppressed.prior_status.as_deref(), Some("unresolved"));
        assert!(suppressed.updated_at.is_some());

        let from_store = store.get(&id).unwrap();
        assert_eq!(from_store.status, "suppressed");
        assert_eq!(from_store.prior_status.as_deref(), Some("unresolved"));
    }

    #[test]
    fn suppress_preserves_resolved_as_prior_status() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));
        store.resolve(&id, None).unwrap();

        let suppressed = store.suppress(&id).expect("suppress must succeed");
        assert_eq!(suppressed.status, "suppressed");
        assert_eq!(suppressed.prior_status.as_deref(), Some("resolved"));
    }

    #[test]
    fn suppress_returns_none_for_unknown_id() {
        let store = InMemoryAlertStore::new();
        store.record(&test_alert(80));
        assert!(store.suppress("00000000000000000000000000").is_none());
    }

    #[test]
    fn suppress_returns_none_when_already_suppressed() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        store.suppress(&id).expect("first suppress succeeds");

        // Second suppress must refuse so prior_status isn't overwritten.
        assert!(store.suppress(&id).is_none(), "double-suppress must return None");
    }

    #[tokio::test]
    async fn suppress_publishes_silence_event() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));
        let mut rx = store.subscribe();
        store.suppress(&id).unwrap();
        match rx.recv().await.expect("silence event must arrive") {
            AlertEvent::Silence(stored) => {
                assert_eq!(stored.id, id);
                assert_eq!(stored.status, "suppressed");
                assert_eq!(stored.prior_status.as_deref(), Some("unresolved"));
            }
            other => panic!("expected Silence, got {other:?}"),
        }
    }

    #[test]
    fn restore_returns_alert_to_prior_status() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        store.suppress(&id).unwrap();

        let restored = store.restore(&id).expect("restore must succeed");
        assert_eq!(restored.status, "unresolved");
        assert!(restored.prior_status.is_none(), "prior_status must be cleared");
    }

    #[test]
    fn restore_returns_to_resolved_when_that_was_prior_status() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(95));
        store.resolve(&id, None).unwrap();
        store.suppress(&id).unwrap();

        let restored = store.restore(&id).unwrap();
        assert_eq!(restored.status, "resolved");
        assert!(restored.prior_status.is_none());
    }

    #[test]
    fn restore_returns_none_when_not_suppressed() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        // Alert is "unresolved", not "suppressed" — restore must refuse.
        assert!(store.restore(&id).is_none());
    }

    #[test]
    fn restore_returns_none_for_unknown_id() {
        let store = InMemoryAlertStore::new();
        assert!(store.restore("00000000000000000000000000").is_none());
    }
}
