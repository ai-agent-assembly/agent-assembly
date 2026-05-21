//! Optional Redis-backed policy cache for the gateway.
//!
//! This module ships in stages across Epic-18 Story S-G:
//!
//! - First commit (this one): the [`RedisConfig`] value type that drives the
//!   feature flag.
//! - Subsequent sub-tasks: cache key derivation, the `PolicyCacheLike` trait,
//!   the `Disabled` baseline, and the Redis-backed implementation.
//!
//! The cache is **off by default** — the gateway should always be runnable
//! without a Redis process. Production deployments opt in by setting
//! `storage.redis.enabled = true` and providing a reachable URL.

/// Operator-facing knobs for the optional Redis policy cache.
///
/// All four fields are filled in by the storage config layer (Epic-18 S-H);
/// for now the struct lives here so the cache implementation can be developed
/// independently. The defaults intentionally encode the OFF posture so
/// callers that do not configure Redis observe no behaviour change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    /// Master switch — when `false` no Redis connection is attempted.
    pub enabled: bool,
    /// Connection URL (e.g. `redis://host:6379`). Required when `enabled` is `true`.
    pub url: Option<String>,
    /// TTL applied to every cached policy entry.
    pub policy_cache_ttl_secs: u64,
    /// Upper bound on concurrent Redis connections held by the cache.
    pub max_connections: u32,
}

impl Default for RedisConfig {
    /// OFF posture: cache disabled, no URL, 30-second TTL, 10-connection ceiling.
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            policy_cache_ttl_secs: 30,
            max_connections: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod config {
        use super::*;

        #[test]
        fn default_is_off_posture() {
            let cfg = RedisConfig::default();
            assert!(!cfg.enabled, "cache must default to OFF");
            assert!(cfg.url.is_none(), "no URL by default");
            assert_eq!(cfg.policy_cache_ttl_secs, 30);
            assert_eq!(cfg.max_connections, 10);
        }
    }
}
