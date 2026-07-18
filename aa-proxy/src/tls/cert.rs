//! LRU cache for dynamically generated per-domain TLS certificates.
//!
//! Generating a certificate with rcgen takes ~0.1 ms. This cache avoids
//! regenerating a cert for every connection to the same domain.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::error::ProxyError;
use crate::tls::ca::{CaStore, CertifiedKey};

/// Fallback capacity used when a caller passes `0`.
///
/// A zero-capacity LRU is meaningless and `NonZeroUsize::new(0)` would panic, so
/// a misconfiguration such as `AA_PROXY_CERT_CACHE_CAPACITY=0` must degrade to a
/// sane default rather than abort the proxy at boot. Mirrors the config-layer
/// default in `crate::config::parse_cert_cache_capacity`.
const DEFAULT_CERT_CACHE_CAPACITY: usize = 1000;

/// Thread-safe LRU cache mapping domain names to their signed [`CertifiedKey`].
pub struct CertCache {
    inner: Mutex<LruCache<String, Arc<CertifiedKey>>>,
}

impl CertCache {
    /// Create a new cache with the given `capacity` (maximum number of entries).
    ///
    /// A `capacity` of `0` is clamped up to [`DEFAULT_CERT_CACHE_CAPACITY`]
    /// rather than panicking, so an operator setting
    /// `AA_PROXY_CERT_CACHE_CAPACITY=0` gets a working (default-sized) cache
    /// instead of a crash at startup.
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).unwrap_or_else(|| {
            NonZeroUsize::new(DEFAULT_CERT_CACHE_CAPACITY).expect("default cert cache capacity is non-zero")
        });
        Self {
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Return the cached [`CertifiedKey`] for `domain`, generating and inserting
    /// a new one (via `ca.sign_cert()`) if the domain is not in the cache.
    pub fn get_or_insert(&self, domain: &str, ca: &CaStore) -> Result<Arc<CertifiedKey>, ProxyError> {
        let mut cache = self.inner.lock().expect("cert cache lock poisoned");
        if let Some(ck) = cache.get(domain) {
            return Ok(Arc::clone(ck));
        }
        let ck = Arc::new(ca.sign_cert(domain)?);
        cache.put(domain.to_string(), Arc::clone(&ck));
        Ok(ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn get_or_insert_returns_cert_on_cache_miss() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let cache = CertCache::new(10);
        let ck = cache.get_or_insert("api.openai.com", &ca).unwrap();
        assert!(!ck.cert_der.is_empty());
    }

    #[tokio::test]
    async fn get_or_insert_returns_same_arc_on_cache_hit() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let cache = CertCache::new(10);
        let ck1 = cache.get_or_insert("api.openai.com", &ca).unwrap();
        let ck2 = cache.get_or_insert("api.openai.com", &ca).unwrap();
        // Identical Arc pointer proves cache hit — no re-signing occurred.
        assert!(Arc::ptr_eq(&ck1, &ck2), "second call must return the cached Arc");
    }

    #[tokio::test]
    async fn zero_capacity_falls_back_to_default_without_panicking() {
        // AAASM-4829: an operator setting AA_PROXY_CERT_CACHE_CAPACITY=0 must not
        // crash the proxy at boot. `new(0)` clamps to the default capacity and
        // yields a working, caching store.
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let cache = CertCache::new(0);
        let ck1 = cache.get_or_insert("api.openai.com", &ca).unwrap();
        let ck2 = cache.get_or_insert("api.openai.com", &ca).unwrap();
        // A default-sized (non-zero) cache retains the entry, so the second call
        // is a hit returning the same Arc.
        assert!(Arc::ptr_eq(&ck1, &ck2), "zero-capacity must clamp to a caching default");
    }

    #[tokio::test]
    async fn get_or_insert_different_domains_get_different_certs() {
        let dir = TempDir::new().unwrap();
        let ca = CaStore::load_or_create(dir.path()).await.unwrap();
        let cache = CertCache::new(10);
        let ck1 = cache.get_or_insert("api.openai.com", &ca).unwrap();
        let ck2 = cache.get_or_insert("api.anthropic.com", &ca).unwrap();
        assert!(!Arc::ptr_eq(&ck1, &ck2));
        assert_ne!(ck1.cert_der, ck2.cert_der);
    }
}
