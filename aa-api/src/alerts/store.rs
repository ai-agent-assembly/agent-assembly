//! In-memory alert store backed by a bounded ring buffer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use aa_gateway::budget::types::BudgetAlert;

use super::{stored_alert_from, AlertStore, StoredAlert};

/// Default maximum number of alerts retained in the ring buffer.
const DEFAULT_CAPACITY: usize = 10_000;

/// In-memory alert store using a `VecDeque` ring buffer.
///
/// When the buffer reaches capacity, the oldest alert is evicted on each
/// new insertion. Thread-safe via `RwLock`.
pub struct InMemoryAlertStore {
    alerts: RwLock<VecDeque<StoredAlert>>,
    capacity: usize,
    next_id: AtomicU64,
}

impl InMemoryAlertStore {
    /// Create a new store with the default capacity (10,000 alerts).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a new store with the given maximum capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(capacity.min(DEFAULT_CAPACITY))),
            capacity,
            next_id: AtomicU64::new(1),
        }
    }
}

impl Default for InMemoryAlertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertStore for InMemoryAlertStore {
    fn record(&self, alert: &BudgetAlert) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let timestamp = chrono::Utc::now().to_rfc3339();
        let stored = stored_alert_from(alert, id, timestamp);

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

    fn get(&self, id: u64) -> Option<StoredAlert> {
        let buf = self.alerts.read().expect("alert store lock poisoned");
        buf.iter().find(|a| a.id == id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::AgentId;

    fn test_alert(threshold_pct: u8) -> BudgetAlert {
        BudgetAlert {
            agent_id: AgentId::from_bytes([1u8; 16]),
            team_id: None,
            threshold_pct,
            spent_usd: 8.0,
            limit_usd: 10.0,
        }
    }

    #[test]
    fn record_and_list_single_alert() {
        let store = InMemoryAlertStore::new();
        let id = store.record(&test_alert(80));
        assert_eq!(id, 1);

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 1);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, 1);
        assert_eq!(items[0].threshold_pct, 80);
    }

    #[test]
    fn list_returns_newest_first() {
        let store = InMemoryAlertStore::new();
        store.record(&test_alert(80));
        store.record(&test_alert(95));

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 2);
        assert_eq!(items[0].id, 2); // newest
        assert_eq!(items[1].id, 1); // oldest
    }

    #[test]
    fn list_pagination_limit_and_offset() {
        let store = InMemoryAlertStore::new();
        for i in 0..5 {
            store.record(&test_alert(80 + i));
        }

        // Page 1: limit=2, offset=0 → IDs 5, 4
        let (items, total) = store.list(2, 0);
        assert_eq!(total, 5);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, 5);
        assert_eq!(items[1].id, 4);

        // Page 2: limit=2, offset=2 → IDs 3, 2
        let (items, _) = store.list(2, 2);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, 3);
        assert_eq!(items[1].id, 2);

        // Page 3: limit=2, offset=4 → ID 1
        let (items, _) = store.list(2, 4);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, 1);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let store = InMemoryAlertStore::with_capacity(3);
        store.record(&test_alert(70)); // id=1
        store.record(&test_alert(80)); // id=2
        store.record(&test_alert(90)); // id=3
        store.record(&test_alert(95)); // id=4 — evicts id=1

        let (items, total) = store.list(10, 0);
        assert_eq!(total, 3);
        assert_eq!(items[0].id, 4);
        assert_eq!(items[2].id, 2);
        // id=1 was evicted
        assert!(!items.iter().any(|a| a.id == 1));
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

        let found = store.get(id).expect("known id should return Some");
        assert_eq!(found.id, id);
        assert_eq!(found.threshold_pct, 95);
        assert_eq!(found.status, "unresolved");

        assert!(store.get(9_999).is_none(), "unknown id returns None");
    }

    #[test]
    fn get_returns_none_after_eviction() {
        let store = InMemoryAlertStore::with_capacity(2);
        let id1 = store.record(&test_alert(70)); // evicted after id3 lands
        store.record(&test_alert(80));
        store.record(&test_alert(90));

        assert!(store.get(id1).is_none(), "evicted id should return None");
    }

    #[test]
    fn ids_auto_increment() {
        let store = InMemoryAlertStore::new();
        let id1 = store.record(&test_alert(80));
        let id2 = store.record(&test_alert(90));
        let id3 = store.record(&test_alert(95));
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }
}
