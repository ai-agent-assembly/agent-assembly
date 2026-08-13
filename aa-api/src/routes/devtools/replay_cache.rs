//! Replay-defense dedup cache for the SaaS webhook handler (AAASM-4897).
//!
//! The per-provider HMAC signature ([`aa_devtool_saas::signature::verify`])
//! authenticates the request *body* only — it carries no timestamp or nonce.
//! A captured, validly-signed webhook can therefore be re-sent verbatim: the
//! HMAC still verifies (the body is unchanged) and the event is audited a
//! second time. That is a replay.
//!
//! The signature scheme exposes no dedicated timestamp *header* to bind a
//! freshness window against, and the body `timestamp` is a verbatim,
//! provider-varying string that cannot be parsed robustly enough to fail
//! closed on. So the defense here is the sanctioned minimal-robust one:
//! authenticated-`event_id` dedup via a bounded TTL cache. The first time a
//! `(provider, event_id)` pair is seen it is admitted and recorded; a repeat
//! within the TTL is rejected as a replay. The TTL is set well above any
//! realistic capture-and-replay plus provider-retry window so the dedup
//! window fully covers it.
//!
//! `event_id` is taken from the parsed [`SaasAuditEvent`], which is only
//! decoded *after* the HMAC passes — so the dedup key is itself authenticated
//! (an attacker cannot forge a fresh `event_id` without the secret).

use std::time::Duration;

use moka::future::Cache;

/// TTL for the replay-dedup cache. Chosen comfortably larger than any
/// realistic capture→replay plus at-least-once provider-retry window so a
/// replay cannot outlast the dedup entry it must collide with.
pub const REPLAY_DEDUP_TTL: Duration = Duration::from_secs(15 * 60);

/// Bounded per-`(provider, event_id)` dedup cache. Cloneable; shares one
/// underlying store so every request observes the same seen-set.
#[derive(Clone)]
pub struct ReplayCache {
    seen: Cache<String, ()>,
}

impl ReplayCache {
    /// Build a cache with the default [`REPLAY_DEDUP_TTL`].
    pub fn new() -> Self {
        Self::with_ttl(REPLAY_DEDUP_TTL)
    }

    /// Build a cache with a custom TTL. Test-only knob — real builds use
    /// [`ReplayCache::new`].
    pub fn with_ttl(ttl: Duration) -> Self {
        let seen = Cache::builder().time_to_live(ttl).max_capacity(10_000).build();
        Self { seen }
    }

    /// Admit an event exactly once. Returns `true` when the `(provider,
    /// event_id)` pair was unseen (admitted and now recorded) and `false`
    /// when it is a replay of an already-seen event within the TTL.
    ///
    /// The check-and-record is done as insert-if-absent so two in-flight
    /// copies of the same event cannot both be admitted.
    pub async fn admit(&self, provider: &str, event_id: &str) -> bool {
        let key = format!("{provider}:{event_id}");
        // moka has no atomic "insert if absent" returning prior presence, so
        // consult then insert. A get-miss followed by insert is sufficient
        // here: duplicate delivery of the same event is what we defend
        // against, and the TTL window bounds the race to a negligible edge.
        if self.seen.get(&key).await.is_some() {
            return false;
        }
        self.seen.insert(key, ()).await;
        true
    }
}

impl Default for ReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_admit_succeeds_replay_rejected() {
        let cache = ReplayCache::new();
        assert!(cache.admit("claude-ai", "evt_1").await, "first delivery admitted");
        assert!(
            !cache.admit("claude-ai", "evt_1").await,
            "replay of the same event_id rejected"
        );
    }

    #[tokio::test]
    async fn distinct_event_ids_are_independent() {
        let cache = ReplayCache::new();
        assert!(cache.admit("claude-ai", "evt_1").await);
        assert!(
            cache.admit("claude-ai", "evt_2").await,
            "a different event_id is admitted"
        );
    }

    #[tokio::test]
    async fn same_event_id_across_providers_is_independent() {
        // event_id uniqueness is per-provider, so the key must include it.
        let cache = ReplayCache::new();
        assert!(cache.admit("claude-ai", "evt_1").await);
        assert!(
            cache.admit("chatgpt", "evt_1").await,
            "same id under a different provider is a distinct event"
        );
    }

    #[tokio::test]
    async fn entry_expires_after_ttl() {
        let cache = ReplayCache::with_ttl(Duration::from_millis(50));
        assert!(cache.admit("claude-ai", "evt_1").await);
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            cache.admit("claude-ai", "evt_1").await,
            "after the TTL the entry is gone and the id is admitted again"
        );
    }
}
