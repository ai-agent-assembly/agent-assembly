//! [`L1Cache`] — a `DashMap`-backed, TTL'd, cache-aside wrapper over a store.

use std::sync::Arc;
use std::time::Duration;

use aa_core::storage::Result;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use tokio::sync::Notify;

use crate::cached_value::CachedValue;
use crate::source::CacheSource;

/// In-process L1 cache that fronts a [`CacheSource`] with a [`DashMap`].
///
/// `get` serves fresh keys from memory and falls back to the wrapped store on a
/// miss or once an entry's TTL elapses, repopulating the cache on the way out
/// (cache-aside). Concurrent misses for the same key collapse to a single
/// `load` call (stampede protection), so a burst of cold lookups never fans out
/// into N backend round-trips.
pub struct L1Cache<S: CacheSource> {
    inner: S,
    entries: Arc<DashMap<S::Key, CachedValue<S::Value>>>,
    inflight: Arc<DashMap<S::Key, Arc<Notify>>>,
    ttl: Duration,
}

impl<S: CacheSource> L1Cache<S> {
    /// Wrap `inner`, expiring cached entries `ttl` after insertion.
    pub fn new(inner: S, ttl: Duration) -> Self {
        Self {
            inner,
            entries: Arc::new(DashMap::new()),
            inflight: Arc::new(DashMap::new()),
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
    ///
    /// Stampede protection: the first caller to miss a key becomes the *leader*
    /// and performs the single `load`; concurrent callers become *followers*,
    /// wait on a shared [`Notify`], then re-read the now-populated cache. The
    /// inner store therefore sees exactly one call per key per miss window.
    pub async fn get(&self, key: S::Key) -> Result<S::Value> {
        loop {
            // Fast path: a fresh cache hit needs no coordination.
            if let Some(value) = self.fresh(&key) {
                return Ok(value);
            }

            // Miss: claim leadership for this key, or grab the in-flight signal.
            let follower = match self.inflight.entry(key.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(Arc::new(Notify::new()));
                    None
                }
                Entry::Occupied(slot) => Some(slot.get().clone()),
            };

            match follower {
                // Leader: load once, populate, then wake every waiter.
                None => {
                    let result = self.inner.load(&key).await;
                    if let Ok(ref value) = result {
                        self.entries.insert(key.clone(), CachedValue::new(value.clone()));
                    }
                    if let Some((_, notify)) = self.inflight.remove(&key) {
                        notify.notify_waiters();
                    }
                    return result;
                }
                // Follower: wait for the leader, then retry the loop.
                Some(notify) => {
                    let waiter = notify.notified();
                    tokio::pin!(waiter);
                    // Register before re-checking the cache so the leader's
                    // notification can't be missed (tokio::sync::Notify pattern):
                    // the leader always populates `entries` before notifying, so
                    // either the re-check sees the value or the wait is woken.
                    waiter.as_mut().enable();
                    if let Some(value) = self.fresh(&key) {
                        return Ok(value);
                    }
                    waiter.await;
                }
            }
        }
    }
}
