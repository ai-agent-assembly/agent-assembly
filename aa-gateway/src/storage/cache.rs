//! Optional Redis-backed policy cache for the gateway.
//!
//! The cache ships under the `redis-cache` Cargo feature. With the feature
//! off the gateway still compiles and runs against [`PolicyCache::Disabled`],
//! a no-op implementation that lets the rest of the codebase write
//! cache-aware code unconditionally.
//!
//! The cache is **off by default** — the gateway should always be runnable
//! without a Redis process. Production deployments opt in by setting
//! `storage.redis.enabled = true` and providing a reachable URL.

use async_trait::async_trait;

#[cfg(feature = "redis-cache")]
use redis::aio::ConnectionManager;

#[cfg(feature = "redis-cache")]
use super::error::{StorageError, StorageResult};
use super::policy::PolicyDocument;

/// Behaviour every policy cache implementation must provide.
///
/// The trait is defined for two reasons:
///
/// 1. Production callers depend on the trait, not the [`PolicyCache`] enum,
///    so unit tests can substitute a stub backed by a `HashMap` (used
///    extensively in Epic-18 S-G sub-task 4).
/// 2. The `Disabled` and `Redis` variants share the same surface — keeping
///    the implementation symmetric makes adding more variants cheap.
#[async_trait]
pub trait PolicyCacheLike: Send + Sync {
    /// Return the currently cached policy for `name`, if any.
    async fn get(&self, name: &str) -> Option<PolicyDocument>;

    /// Replace the cached entry for `doc.name`. Best-effort — callers must
    /// fall through to the authoritative store on cache miss either way.
    async fn set(&self, doc: &PolicyDocument);

    /// Drop every cached version of `name`. Used immediately after a policy
    /// update so subsequent `get` calls cannot serve a stale entry.
    async fn invalidate(&self, name: &str);

    /// Whether the cache is actively backed by a remote store, as opposed to
    /// the no-op `Disabled` posture.
    fn is_enabled(&self) -> bool;
}

/// Concrete policy-cache value held by the gateway runtime.
///
/// The default constructor returns the `Disabled` variant; the `Redis`
/// variant is only available when the `redis-cache` Cargo feature is on and
/// will be added in Epic-18 S-G sub-task 4.
#[non_exhaustive]
pub enum PolicyCache {
    /// No-op cache — `get` always returns `None`, `set` and `invalidate`
    /// are no-ops, `is_enabled` returns `false`.
    Disabled,
}

#[async_trait]
impl PolicyCacheLike for PolicyCache {
    async fn get(&self, _name: &str) -> Option<PolicyDocument> {
        match self {
            Self::Disabled => None,
        }
    }

    async fn set(&self, _doc: &PolicyDocument) {
        match self {
            Self::Disabled => {}
        }
    }

    async fn invalidate(&self, _name: &str) {
        match self {
            Self::Disabled => {}
        }
    }

    fn is_enabled(&self) -> bool {
        match self {
            Self::Disabled => false,
        }
    }
}

impl Default for PolicyCache {
    /// Disabled — the safe posture when no Redis is configured.
    fn default() -> Self {
        Self::Disabled
    }
}

impl PolicyCache {
    /// Build a cache handle from `config`. When `config.enabled` is `false`
    /// (the default), this returns [`PolicyCache::Disabled`] without
    /// touching Redis. The `enabled = true` branch lands in Epic-18 S-G
    /// sub-task 4.
    pub fn from_config(config: &RedisConfig) -> Self {
        if !config.enabled {
            return Self::Disabled;
        }
        // TODO(AAASM-1716, S-G sub-task 4): attempt the Redis connection.
        // Until then, treat enabled-but-unimplemented as Disabled so the
        // gateway never tries to talk to a non-existent backend.
        Self::Disabled
    }
}

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

/// Build the Redis `SCAN MATCH` pattern that targets every cached version of
/// `name`, regardless of content hash.
///
/// Used by `PolicyCache::invalidate` (Epic-18 S-G sub-task 4) to evict every
/// historical entry for a policy in one sweep — there is no need to know the
/// previous content hash.
pub fn policy_invalidation_pattern(name: &str) -> String {
    format!("policy:{name}:*")
}

/// Redis-backed policy cache.
///
/// Only available with the `redis-cache` Cargo feature. The struct holds a
/// cloneable [`ConnectionManager`] (the redis-rs multiplexed handle) and the
/// per-entry TTL pulled from [`RedisConfig::policy_cache_ttl_secs`].
#[cfg(feature = "redis-cache")]
#[allow(dead_code)] // `conn` and `ttl_secs` are wired up by the next get/set commits.
pub struct RedisPolicyCache {
    conn: ConnectionManager,
    ttl_secs: u64,
}

#[cfg(feature = "redis-cache")]
impl RedisPolicyCache {
    /// Establish a Redis connection from `config` and wrap it in a
    /// [`ConnectionManager`].
    ///
    /// Returns [`StorageError::ConnectionFailed`] when `config.url` is `None`
    /// or the URL cannot be parsed, and when the connection manager cannot
    /// complete its initial handshake.
    pub async fn connect(config: &RedisConfig) -> StorageResult<Self> {
        let url = config.url.as_deref().ok_or_else(|| {
            StorageError::ConnectionFailed("storage.redis.url is required when redis.enabled = true".into())
        })?;
        let client = redis::Client::open(url).map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
        Ok(Self {
            conn,
            ttl_secs: config.policy_cache_ttl_secs,
        })
    }

    /// Expose the configured TTL — useful in tests and for debug introspection.
    #[cfg(test)]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }
}

#[cfg(feature = "redis-cache")]
#[async_trait]
impl PolicyCacheLike for RedisPolicyCache {
    async fn get(&self, _name: &str) -> Option<PolicyDocument> {
        // Filled in by the next commit (SCAN+GET).
        None
    }

    async fn set(&self, _doc: &PolicyDocument) {
        // Filled in by a following commit (invalidate-then-SETEX).
    }

    async fn invalidate(&self, _name: &str) {
        // Filled in by a following commit (SCAN+DEL).
    }

    fn is_enabled(&self) -> bool {
        true
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

        #[test]
        fn hash_slice_is_sixteen_hex_chars() {
            let key = policy_cache_key("default", b"any-body");
            // Format is `policy:{name}:{hex}` — slice after the last colon.
            let hex = key.rsplit(':').next().expect("key has a hex segment");
            assert_eq!(hex.len(), 16, "expected 16 hex chars, got {hex:?}");
            assert!(
                hex.bytes().all(|b| b.is_ascii_hexdigit()),
                "hex segment must be ascii hex: {hex:?}"
            );
        }

        #[test]
        fn invalidation_pattern_matches_every_version() {
            assert_eq!(policy_invalidation_pattern("default"), "policy:default:*");
            assert_eq!(policy_invalidation_pattern("legacy"), "policy:legacy:*");
        }
    }

    mod disabled {
        use super::*;

        #[test]
        fn default_is_disabled() {
            let cache = PolicyCache::default();
            assert!(matches!(cache, PolicyCache::Disabled));
            assert!(!cache.is_enabled());
        }

        #[tokio::test]
        async fn get_always_returns_none() {
            let cache = PolicyCache::Disabled;
            assert!(cache.get("default").await.is_none());
            assert!(cache.get("any-other-name").await.is_none());
        }

        #[tokio::test]
        async fn set_and_invalidate_do_not_panic() {
            let cache = PolicyCache::Disabled;
            let doc = PolicyDocument {
                name: "default".into(),
                bytes: b"any-body".to_vec(),
            };
            cache.set(&doc).await;
            cache.invalidate("default").await;
        }

        #[test]
        fn from_config_default_redis_is_disabled() {
            let cache = PolicyCache::from_config(&RedisConfig::default());
            assert!(matches!(cache, PolicyCache::Disabled));
            assert!(!cache.is_enabled());
        }
    }
}
