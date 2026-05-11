//! Decision cache for the cascade policy evaluation path.
//!
//! `DecisionCache` is a bounded sync cache keyed by `CacheKey` — a compound
//! of agent ID, policy epoch, and a hashed action representation. Entries are
//! time-to-live evicted and capacity-bounded by moka.
//!
//! The cache is consulted **only** by `evaluate_with_cascade`. The primary
//! (non-cascade) path and stateful stages (rate-limit, budget) are never cached.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use moka::sync::Cache;

use crate::engine::decision::PolicyDecision;

/// Stable key identifying one (agent, epoch, action) evaluation result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Raw 16-byte agent UUID.
    pub agent_id: [u8; 16],
    /// Policy epoch at the time of evaluation. Stale entries are invalidated
    /// when the epoch advances (via `load_policy` or `apply_yaml`).
    pub policy_epoch: u64,
    /// FNV-1a hash of a canonical `"{action_kind}:{action_discriminant}"` string.
    pub action_hash: u64,
}

impl CacheKey {
    /// Build a cache key from an agent ID, epoch, and governance action.
    pub fn new(agent_id: &[u8; 16], policy_epoch: u64, action: &aa_core::GovernanceAction) -> Self {
        Self {
            agent_id: *agent_id,
            policy_epoch,
            action_hash: action_discriminant(action),
        }
    }
}

/// Compute a stable u64 hash for the action discriminant + primary payload.
fn action_discriminant(action: &aa_core::GovernanceAction) -> u64 {
    use ahash::AHasher;
    use std::hash::{Hash, Hasher};

    let mut h = AHasher::default();
    match action {
        aa_core::GovernanceAction::ToolCall { name, .. } => {
            "tool".hash(&mut h);
            name.hash(&mut h);
        }
        aa_core::GovernanceAction::NetworkRequest { url, method } => {
            "net".hash(&mut h);
            url.hash(&mut h);
            method.hash(&mut h);
        }
        aa_core::GovernanceAction::FileAccess { path, mode } => {
            "file".hash(&mut h);
            path.hash(&mut h);
            format!("{mode:?}").hash(&mut h);
        }
        aa_core::GovernanceAction::ProcessExec { command } => {
            "exec".hash(&mut h);
            command.hash(&mut h);
        }
        aa_core::GovernanceAction::SendMessage {
            source_team_id,
            target_team_id,
            channel_id,
        } => {
            "msg".hash(&mut h);
            source_team_id.hash(&mut h);
            target_team_id.hash(&mut h);
            channel_id.hash(&mut h);
        }
    }
    h.finish()
}

/// Bounded LRU cache for `PolicyDecision` values keyed by `CacheKey`.
///
/// Backed by `moka::sync::Cache`. Thread-safe — clone-shared across callers.
/// Hit and miss counters are tracked via `AtomicU64` for observability.
#[derive(Clone)]
pub struct DecisionCache {
    inner: Cache<CacheKey, PolicyDecision>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
}

impl DecisionCache {
    /// Create a cache bounded to `capacity` entries with a 60-second TTL.
    pub fn new(capacity: u64) -> Self {
        let inner = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(std::time::Duration::from_secs(60))
            .build();
        Self {
            inner,
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Look up an existing decision. Increments hit/miss counters.
    pub fn get(&self, key: &CacheKey) -> Option<PolicyDecision> {
        let result = self.inner.get(key);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("policy_decision_cache_hits_total").increment(1);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("policy_decision_cache_misses_total").increment(1);
        }
        result
    }

    /// Insert a decision. `PolicyDecision` is `Clone` so callers can keep a copy.
    pub fn insert(&self, key: CacheKey, value: PolicyDecision) {
        self.inner.insert(key, value);
    }

    /// Evict all cached decisions immediately.
    ///
    /// TODO(F93-Phase-B): hook to PolicyVersion bump so callers don't need to
    /// call this explicitly — epoch advance already invalidates stale entries
    /// via the key, but this method allows eager eviction when needed.
    pub fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    /// Evict all cached decisions for a specific agent.
    ///
    /// TODO(F93-Phase-B): hook to PolicyVersion bump for agent-scoped eviction.
    /// Uses full cache invalidation since moka sync::Cache has no partial-key scan.
    pub fn invalidate_for_agent(&self, _agent_id: &[u8; 16]) {
        self.inner.invalidate_all();
    }

    /// Return cumulative cache hits since construction.
    pub fn cache_hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Return cumulative cache misses since construction.
    pub fn cache_misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_action(name: &str) -> aa_core::GovernanceAction {
        aa_core::GovernanceAction::ToolCall {
            name: name.to_string(),
            args: String::new(),
        }
    }

    #[test]
    fn cache_hit_after_insert() {
        let cache = DecisionCache::new(128);
        let key = CacheKey::new(&[1u8; 16], 1, &tool_action("bash"));
        cache.insert(key.clone(), PolicyDecision::Allow);
        assert_eq!(cache.get(&key), Some(PolicyDecision::Allow));
        assert_eq!(cache.cache_hits(), 1);
        assert_eq!(cache.cache_misses(), 0);
    }

    #[test]
    fn cache_miss_is_counted() {
        let cache = DecisionCache::new(128);
        let key = CacheKey::new(&[2u8; 16], 1, &tool_action("deploy"));
        assert_eq!(cache.get(&key), None);
        assert_eq!(cache.cache_misses(), 1);
        assert_eq!(cache.cache_hits(), 0);
    }

    #[test]
    fn different_tool_names_produce_different_keys() {
        let key_bash = CacheKey::new(&[1u8; 16], 1, &tool_action("bash"));
        let key_deploy = CacheKey::new(&[1u8; 16], 1, &tool_action("deploy"));
        assert_ne!(key_bash, key_deploy);
    }

    #[test]
    fn different_epochs_produce_different_keys() {
        let action = tool_action("bash");
        let key_e1 = CacheKey::new(&[1u8; 16], 1, &action);
        let key_e2 = CacheKey::new(&[1u8; 16], 2, &action);
        assert_ne!(key_e1, key_e2);
    }
}
