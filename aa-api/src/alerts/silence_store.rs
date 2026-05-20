//! In-memory store for `SilenceRecord`s and trait abstraction.
//!
//! The store is populated by `POST /api/v1/alerts/silence` and drained
//! by the silence-expiry watcher (see `silence_watcher`). It holds the
//! authoritative answer to "is this alert currently silenced?" — the
//! route handler must consult `get_active_for_alert` before suppressing
//! to honour the 409 `alert_already_silenced` contract.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};

use super::silence::SilenceRecord;

/// Trait for storing and querying silence records.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait SilenceStore: Send + Sync {
    /// Insert a fresh silence record. The caller has already enforced
    /// the 409 `alert_already_silenced` contract via
    /// `get_active_for_alert`; this method just stores the record.
    fn insert(&self, record: SilenceRecord);

    /// Return the active silence for an alert, if any. "Active" means a
    /// record exists *and* its `expires_at` is in the future.
    /// `now` is passed in so tests can advance time deterministically.
    fn get_active_for_alert(&self, alert_id: &str, now: DateTime<Utc>) -> Option<SilenceRecord>;

    /// Drain and return all silence records whose `expires_at` is at or
    /// before `now`. Called by the expiry watcher every tick — the
    /// implementation **must** remove the returned records so a second
    /// call with the same `now` returns an empty vec.
    fn expire_due(&self, now: DateTime<Utc>) -> Vec<SilenceRecord>;
}

/// Hash-map backed in-memory `SilenceStore`. Keys are silence IDs;
/// secondary lookup by `alert_id` is a linear scan over the map values,
/// which is fine at the scale of an in-memory alert store (≤10k alerts,
/// each with at most one active silence).
pub struct InMemorySilenceStore {
    records: RwLock<HashMap<String, SilenceRecord>>,
}

impl InMemorySilenceStore {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySilenceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SilenceStore for InMemorySilenceStore {
    fn insert(&self, record: SilenceRecord) {
        let mut map = self.records.write().expect("silence store lock poisoned");
        map.insert(record.id.clone(), record);
    }

    fn get_active_for_alert(&self, alert_id: &str, now: DateTime<Utc>) -> Option<SilenceRecord> {
        let map = self.records.read().expect("silence store lock poisoned");
        map.values()
            .find(|r| r.alert_id == alert_id && expires_at_after(&r.expires_at, now))
            .cloned()
    }

    fn expire_due(&self, now: DateTime<Utc>) -> Vec<SilenceRecord> {
        let mut map = self.records.write().expect("silence store lock poisoned");
        let expired_ids: Vec<String> = map
            .iter()
            .filter(|(_, r)| !expires_at_after(&r.expires_at, now))
            .map(|(id, _)| id.clone())
            .collect();
        expired_ids.into_iter().filter_map(|id| map.remove(&id)).collect()
    }
}

/// Parse an ISO 8601 `expires_at` string and report whether the silence
/// is still in effect at `now`. A malformed or unparseable timestamp is
/// treated as **expired** so a broken record can't pin an alert in the
/// `"suppressed"` state forever.
fn expires_at_after(expires_at: &str, now: DateTime<Utc>) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|t| t.with_timezone(&Utc) > now)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(silence_id: &str, alert_id: &str, expires_at: &str) -> SilenceRecord {
        SilenceRecord {
            id: silence_id.to_string(),
            alert_id: alert_id.to_string(),
            starts_at: "2026-05-20T09:00:00Z".to_string(),
            expires_at: expires_at.to_string(),
            reason: None,
            created_by: "user_test".to_string(),
        }
    }

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn insert_then_get_active_returns_record() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-1", "alert-1", "2026-05-20T10:00:00Z"));
        let now = at("2026-05-20T09:30:00Z");
        let found = store.get_active_for_alert("alert-1", now).expect("active silence");
        assert_eq!(found.id, "sil-1");
    }

    #[test]
    fn get_active_returns_none_when_expired() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-1", "alert-1", "2026-05-20T09:00:00Z"));
        let now = at("2026-05-20T09:30:00Z"); // 30 min after expiry
        assert!(store.get_active_for_alert("alert-1", now).is_none());
    }

    #[test]
    fn get_active_returns_none_for_unknown_alert() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-1", "alert-1", "2026-05-20T10:00:00Z"));
        let now = at("2026-05-20T09:30:00Z");
        assert!(store.get_active_for_alert("alert-other", now).is_none());
    }

    #[test]
    fn get_active_picks_the_record_for_the_given_alert() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-1", "alert-1", "2026-05-20T10:00:00Z"));
        store.insert(sample("sil-2", "alert-2", "2026-05-20T10:00:00Z"));
        let now = at("2026-05-20T09:30:00Z");

        let one = store.get_active_for_alert("alert-1", now).unwrap();
        let two = store.get_active_for_alert("alert-2", now).unwrap();
        assert_eq!(one.id, "sil-1");
        assert_eq!(two.id, "sil-2");
    }

    #[test]
    fn expire_due_removes_and_returns_past_records() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-old", "alert-1", "2026-05-20T09:00:00Z"));
        store.insert(sample("sil-new", "alert-2", "2026-05-20T11:00:00Z"));
        let now = at("2026-05-20T09:30:00Z");

        let expired = store.expire_due(now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, "sil-old");

        // Active record is still there.
        assert!(store.get_active_for_alert("alert-2", now).is_some());
        // Expired record is gone — second call yields empty.
        assert!(store.expire_due(now).is_empty());
    }

    #[test]
    fn expire_due_treats_unparseable_expires_at_as_expired() {
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-bad", "alert-1", "not-a-timestamp"));
        let now = at("2026-05-20T09:30:00Z");

        let expired = store.expire_due(now);
        assert_eq!(expired.len(), 1, "malformed timestamps must not pin alerts forever");
        assert_eq!(expired[0].id, "sil-bad");
    }

    #[test]
    fn expire_due_treats_exact_now_as_expired() {
        // Cleanup is inclusive on the boundary — `expires_at == now` is
        // treated as already over (the silence covered up to but not
        // including this instant).
        let store = InMemorySilenceStore::new();
        store.insert(sample("sil-edge", "alert-1", "2026-05-20T09:30:00Z"));
        let now = at("2026-05-20T09:30:00Z");

        let expired = store.expire_due(now);
        assert_eq!(expired.len(), 1);
    }
}
