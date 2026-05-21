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

/// Number of hex characters retained from the SHA-256 digest when building a
/// cache key. Sixty-four bits of entropy is overkill for collision avoidance
/// across a single policy namespace and keeps the Redis key short.
const POLICY_CACHE_HASH_HEX_LEN: usize = 16;

/// Build the Redis key used to store a cached policy document.
///
/// The key is content-addressed: changing a single byte of `bytes` changes
/// the hash slice and therefore the key, so a stale Redis entry can never
/// serve an outdated policy document. The format is `policy:{name}:{hex}`,
/// where `hex` is the first 16 hex characters of `sha2::Sha256(bytes)`.
pub fn policy_cache_key(name: &str, bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(POLICY_CACHE_HASH_HEX_LEN);
    for byte in digest.iter().take(POLICY_CACHE_HASH_HEX_LEN / 2) {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("policy:{name}:{hex}")
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

        #[test]
        fn explicit_url_is_preserved() {
            let cfg = RedisConfig {
                enabled: true,
                url: Some("redis://10.0.0.5:6379".into()),
                ..RedisConfig::default()
            };
            assert!(cfg.enabled);
            assert_eq!(cfg.url.as_deref(), Some("redis://10.0.0.5:6379"));
            assert_eq!(cfg.policy_cache_ttl_secs, 30);
            assert_eq!(cfg.max_connections, 10);
        }
    }

    mod key {
        use super::*;

        #[test]
        fn same_inputs_yield_identical_key() {
            let a = policy_cache_key("default", b"version-1-body");
            let b = policy_cache_key("default", b"version-1-body");
            assert_eq!(a, b);
        }

        #[test]
        fn changing_bytes_changes_key() {
            let v1 = policy_cache_key("default", b"version-1-body");
            let v2 = policy_cache_key("default", b"version-2-body");
            assert_ne!(v1, v2, "content-addressing must shift the key");
        }

        #[test]
        fn name_namespaces_the_key() {
            let same_bytes: &[u8] = b"shared-bytes";
            let a = policy_cache_key("default", same_bytes);
            let b = policy_cache_key("legacy", same_bytes);
            assert_ne!(a, b, "different names must produce different keys");
        }
    }
}
