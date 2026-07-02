//! In-process L1 policy cache, kept fresh by gateway push-invalidation.
//!
//! [`PolicyL1Cache`] is a `DashMap`-backed cache keyed by `agent_id`. It serves
//! cached policy decisions off the tool-call hot path and implements
//! [`InvalidationSink`] so the [`crate::invalidation_client::InvalidationClient`]
//! can evict a stale entry the moment the gateway pushes a `PolicyInvalidated`
//! — closing the TTL-race window where a revoked agent keeps executing.

use dashmap::DashMap;

use crate::invalidation_client::InvalidationSink;

/// Default upper bound on the number of cached entries (AAASM-4020).
///
/// The cache is keyed by attacker-influenceable `agent_id`, so it must be
/// bounded before any insert path is wired — an unbounded [`DashMap`] would grow
/// with every distinct id and become a memory-exhaustion vector.
pub const DEFAULT_CAPACITY: usize = 10_000;

/// A `DashMap`-backed L1 cache of per-agent values (e.g. policy decisions),
/// invalidated on demand by the push-invalidation subscriber.
///
/// The map is bounded to [`DEFAULT_CAPACITY`] (override via
/// [`PolicyL1Cache::with_capacity`]). When full, inserting a *new* key evicts an
/// arbitrary existing entry: a policy-cache eviction is safe because a miss just
/// triggers a re-fetch, so approximate (non-LRU) eviction trades exactness for a
/// hard memory ceiling.
pub struct PolicyL1Cache<V> {
    entries: DashMap<String, V>,
    capacity: usize,
}

impl<V> Default for PolicyL1Cache<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            capacity: DEFAULT_CAPACITY,
        }
    }
}

impl<V> PolicyL1Cache<V> {
    /// Create an empty cache bounded to [`DEFAULT_CAPACITY`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an empty cache bounded to `capacity` entries.
    ///
    /// A `capacity` of `0` is treated as `1` so the cache can always hold the
    /// entry just inserted.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: DashMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Insert or replace the cached value for `agent_id`.
    ///
    /// Enforces the capacity bound (AAASM-4020): when the cache is full and the
    /// key is new, one arbitrary entry is evicted first so the map never exceeds
    /// its configured ceiling.
    pub fn insert(&self, agent_id: impl Into<String>, value: V) {
        let key = agent_id.into();
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&key) {
            // Clone the victim key so the read guard is dropped before `remove`
            // takes a write lock (a held ref + same-shard write would deadlock).
            let victim = self.entries.iter().next().map(|e| e.key().clone());
            if let Some(victim) = victim {
                self.entries.remove(&victim);
            }
        }
        self.entries.insert(key, value);
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
    fn insert_enforces_capacity_bound() {
        // AAASM-4020: the map must never exceed its configured ceiling, however
        // many distinct keys are inserted.
        let cache: PolicyL1Cache<u32> = PolicyL1Cache::with_capacity(4);
        for i in 0..100u32 {
            cache.insert(format!("agent-{i}"), i);
        }
        assert!(cache.len() <= 4, "len {} exceeded capacity", cache.len());
    }

    #[test]
    fn insert_existing_key_does_not_evict() {
        // Replacing an existing key must not trip the eviction path.
        let cache: PolicyL1Cache<u32> = PolicyL1Cache::with_capacity(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("a", 9);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("a"), Some(9));
        assert_eq!(cache.get("b"), Some(2));
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
