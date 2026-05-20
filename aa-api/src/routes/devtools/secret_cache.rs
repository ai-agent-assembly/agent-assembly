//! Per-provider HMAC secret cache for the SaaS webhook handler.
//!
//! AAASM-924 requires HMAC secrets to be fetched via `api_key_secret_ref`
//! (a Vault reference) and cached in `moka` with a 5-minute TTL. This module
//! holds the cache and a [`SecretResolver`] trait so the Vault backend can
//! be swapped in once the secret-store MCP is available.
//!
//! The default [`EnvVarResolver`] treats the secret reference as an
//! environment variable name — the same placeholder the previous webhook
//! stub used. It is intentional that the cache layer is identical whether
//! the backend is env-var or Vault: switching backends is one
//! `with_resolver` call.

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

/// TTL for cached HMAC secrets (AAASM-924 AC: 5 minutes).
pub const SECRET_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Pluggable secret-store backend.
///
/// Implementations resolve an opaque reference (e.g.
/// `"vault:secret/saas/claude-ai/hmac"`) into the actual key bytes. The
/// reference format is opaque to [`SecretCache`] — only the resolver
/// understands it.
pub trait SecretResolver: Send + Sync {
    /// Resolve a secret reference to its raw bytes.
    ///
    /// Returns `None` when the reference is not configured. Errors must be
    /// returned as `None` — the caller treats a missing secret as a 401.
    fn resolve(&self, secret_ref: &str) -> Option<Vec<u8>>;
}

/// Default resolver that reads the reference name from an environment
/// variable. Placeholder until the Vault MCP backend is wired in.
#[derive(Debug, Default)]
pub struct EnvVarResolver;

impl SecretResolver for EnvVarResolver {
    fn resolve(&self, secret_ref: &str) -> Option<Vec<u8>> {
        std::env::var(secret_ref).ok().map(String::into_bytes)
    }
}

/// Cache for resolved HMAC secrets keyed by `api_key_secret_ref`.
#[derive(Clone)]
pub struct SecretCache {
    cache: Cache<String, Arc<Vec<u8>>>,
    resolver: Arc<dyn SecretResolver>,
}

impl SecretCache {
    /// Build a cache with the default env-var resolver and the 5-min TTL.
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(EnvVarResolver))
    }

    /// Build a cache with a custom resolver and the 5-min TTL.
    pub fn with_resolver(resolver: Arc<dyn SecretResolver>) -> Self {
        Self::with_ttl_and_resolver(SECRET_CACHE_TTL, resolver)
    }

    /// Build a cache with a custom TTL and resolver. Test-only helper —
    /// real builds use [`SecretCache::new`].
    pub fn with_ttl_and_resolver(ttl: Duration, resolver: Arc<dyn SecretResolver>) -> Self {
        let cache = Cache::builder().time_to_live(ttl).max_capacity(64).build();
        Self { cache, resolver }
    }

    /// Look up a secret by reference. On miss, calls the underlying resolver
    /// and caches the result for the configured TTL.
    pub async fn get(&self, secret_ref: &str) -> Option<Arc<Vec<u8>>> {
        if let Some(v) = self.cache.get(secret_ref).await {
            return Some(v);
        }
        let resolved = Arc::new(self.resolver.resolve(secret_ref)?);
        self.cache.insert(secret_ref.to_string(), resolved.clone()).await;
        Some(resolved)
    }
}

impl Default for SecretCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingResolver {
        calls: AtomicUsize,
        value: Vec<u8>,
    }

    impl SecretResolver for CountingResolver {
        fn resolve(&self, _secret_ref: &str) -> Option<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Some(self.value.clone())
        }
    }

    #[tokio::test]
    async fn second_lookup_hits_cache_and_skips_resolver() {
        let resolver = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
            value: b"resolved-secret".to_vec(),
        });
        let cache = SecretCache::with_resolver(resolver.clone());

        let a = cache.get("vault:secret/foo").await.expect("first");
        let b = cache.get("vault:secret/foo").await.expect("second");
        assert_eq!(*a, b"resolved-secret".to_vec());
        assert_eq!(*b, b"resolved-secret".to_vec());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1, "resolver hit only once");
    }

    #[tokio::test]
    async fn ttl_expiry_triggers_re_resolution() {
        let resolver = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
            value: b"k".to_vec(),
        });
        // Very short TTL so the test doesn't sleep for minutes.
        let cache = SecretCache::with_ttl_and_resolver(Duration::from_millis(50), resolver.clone());
        let _ = cache.get("vault:secret/foo").await.expect("first");
        tokio::time::sleep(Duration::from_millis(120)).await;
        let _ = cache.get("vault:secret/foo").await.expect("second after expiry");
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            2,
            "resolver hit twice across TTL"
        );
    }

    #[tokio::test]
    async fn unresolvable_secret_returns_none() {
        struct NoneResolver;
        impl SecretResolver for NoneResolver {
            fn resolve(&self, _: &str) -> Option<Vec<u8>> {
                None
            }
        }
        let cache = SecretCache::with_resolver(Arc::new(NoneResolver));
        assert!(cache.get("vault:secret/missing").await.is_none());
    }
}
