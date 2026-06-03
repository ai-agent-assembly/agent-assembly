//! [`CachedValue`] — a cache entry tagged with its insertion instant.

use std::time::{Duration, Instant};

/// A value stored in the L1 cache together with the [`Instant`] it was inserted.
///
/// The insertion time drives TTL expiry: an entry older than the cache's
/// configured TTL is treated as a miss, forcing a reload from the wrapped store.
#[derive(Debug, Clone)]
pub struct CachedValue<V> {
    /// The cached value.
    pub value: V,
    /// When this entry was inserted.
    pub inserted_at: Instant,
}

impl<V> CachedValue<V> {
    /// Wrap `value`, stamping it with the current instant.
    #[must_use]
    pub fn new(value: V) -> Self {
        Self {
            value,
            inserted_at: Instant::now(),
        }
    }

    /// Return `true` once the entry's age has reached or exceeded `ttl`.
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.inserted_at.elapsed() >= ttl
    }
}
