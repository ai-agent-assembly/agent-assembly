//! In-process L1 policy cache, kept fresh by gateway push-invalidation.
//!
//! [`PolicyL1Cache`] is a `DashMap`-backed cache keyed by `agent_id`. It serves
//! cached policy decisions off the tool-call hot path and implements
//! [`InvalidationSink`] so the [`crate::invalidation_client::InvalidationClient`]
//! can evict a stale entry the moment the gateway pushes a `PolicyInvalidated`
//! — closing the TTL-race window where a revoked agent keeps executing.

use dashmap::DashMap;

use crate::invalidation_client::InvalidationSink;

/// A `DashMap`-backed L1 cache of per-agent values (e.g. policy decisions),
/// invalidated on demand by the push-invalidation subscriber.
pub struct PolicyL1Cache<V> {
    entries: DashMap<String, V>,
}

impl<V> Default for PolicyL1Cache<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<V> PolicyL1Cache<V> {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the cached value for `agent_id`.
    pub fn insert(&self, agent_id: impl Into<String>, value: V) {
        self.entries.insert(agent_id.into(), value);
    }

    /// Drop the cached value for `agent_id`, if present.
    pub fn invalidate(&self, agent_id: &str) {
        self.entries.remove(agent_id);
    }

    /// Drop every cached value — used for a global policy swap.
    pub fn invalidate_all(&self) {
        self.entries.clear();
    }

    /// Whether a value is currently cached for `agent_id`.
    pub fn contains(&self, agent_id: &str) -> bool {
        self.entries.contains_key(agent_id)
    }

    /// Number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<V: Clone> PolicyL1Cache<V> {
    /// Return a clone of the cached value for `agent_id`, if present.
    pub fn get(&self, agent_id: &str) -> Option<V> {
        self.entries.get(agent_id).map(|entry| entry.value().clone())
    }
}

impl<V: Send + Sync> InvalidationSink for PolicyL1Cache<V> {
    fn on_policy_invalidated(&self, agent_id: &str) {
        if agent_id.is_empty() {
            self.invalidate_all();
        } else {
            self.invalidate(agent_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_roundtrip() {
        let cache: PolicyL1Cache<bool> = PolicyL1Cache::new();
        cache.insert("agent-a", true);
        assert_eq!(cache.get("agent-a"), Some(true));
        assert!(cache.contains("agent-a"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn invalidate_drops_only_the_named_entry() {
        let cache: PolicyL1Cache<u8> = PolicyL1Cache::new();
        cache.insert("agent-a", 1);
        cache.insert("agent-b", 2);

        cache.invalidate("agent-a");

        assert!(!cache.contains("agent-a"));
        assert_eq!(cache.get("agent-b"), Some(2));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sink_named_agent_invalidates_one() {
        let cache: PolicyL1Cache<u8> = PolicyL1Cache::new();
        cache.insert("agent-a", 1);
        cache.insert("agent-b", 2);

        cache.on_policy_invalidated("agent-a");

        assert!(!cache.contains("agent-a"));
        assert!(cache.contains("agent-b"));
    }

    #[test]
    fn sink_empty_agent_invalidates_all() {
        let cache: PolicyL1Cache<u8> = PolicyL1Cache::new();
        cache.insert("agent-a", 1);
        cache.insert("agent-b", 2);

        cache.on_policy_invalidated("");

        assert!(cache.is_empty());
    }
}
