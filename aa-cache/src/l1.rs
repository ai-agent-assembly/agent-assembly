//! [`L1Cache`] — a `DashMap`-backed, TTL'd, cache-aside wrapper over a store.

use std::sync::Arc;
use std::time::Duration;

use aa_core::storage::Result;
use dashmap::DashMap;

use crate::cached_value::CachedValue;
use crate::source::CacheSource;

/// In-process L1 cache that fronts a [`CacheSource`] with a [`DashMap`].
///
/// `get` serves fresh keys from memory and falls back to the wrapped store on a
/// miss or once an entry's TTL elapses, repopulating the cache on the way out
/// (cache-aside).
pub struct L1Cache<S: CacheSource> {
    inner: S,
    entries: Arc<DashMap<S::Key, CachedValue<S::Value>>>,
    ttl: Duration,
}

impl<S: CacheSource> L1Cache<S> {
    /// Wrap `inner`, expiring cached entries `ttl` after insertion.
    pub fn new(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Borrow the wrapped store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Return a fresh (non-expired) cached value for `key`, if present.
    fn fresh(&self, key: &S::Key) -> Option<S::Value> {
        let entry = self.entries.get(key)?;
        if entry.is_expired(self.ttl) {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Fetch the value for `key`, serving from cache when fresh.
    ///
    /// Cache-aside: a hit clones out of the `DashMap`; a miss (or an expired
    /// entry) loads from the wrapped store, populates the cache, and returns.
    pub async fn get(&self, key: S::Key) -> Result<S::Value> {
        if let Some(value) = self.fresh(&key) {
            return Ok(value);
        }
        let value = self.inner.load(&key).await?;
        self.entries.insert(key, CachedValue::new(value.clone()));
        Ok(value)
    }
}
