//! [`L1Cache`] — a `DashMap`-backed, TTL'd, cache-aside wrapper over a store.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Monotonic invalidation counter, bumped by every [`invalidate`](Self::invalidate).
    /// A leader snapshots it before loading and refuses to cache its result if the
    /// counter moved during the load window, so a push-invalidation that races an
    /// in-flight load is never silently lost (see AAASM-3985).
    epoch: AtomicU64,
    ttl: Duration,
    /// Upper bound on the number of live entries. Once an insert pushes the map
    /// past this, [`enforce_capacity`](Self::enforce_capacity) drops expired
    /// entries first, then the oldest-by-insertion entries, so the cache can
    /// never grow without bound (AAASM-3997).
    max_entries: usize,
}

/// Default entry ceiling for [`L1Cache::new`]. Large enough to be a no-op for
/// realistic agent populations, small enough to bound memory if a caller never
/// invalidates and the key space is effectively unbounded.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

impl<S: CacheSource> L1Cache<S> {
    /// Wrap `inner`, expiring cached entries `ttl` after insertion, with the
    /// default entry ceiling ([`DEFAULT_MAX_ENTRIES`]).
    pub fn new(inner: S, ttl: Duration) -> Self {
        Self::with_max_entries(inner, ttl, DEFAULT_MAX_ENTRIES)
    }

    /// Like [`new`](Self::new) but with an explicit maximum live-entry count.
    ///
    /// `max_entries` is clamped to at least 1 so the cache always retains the
    /// entry it just loaded.
    pub fn with_max_entries(inner: S, ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner,
            entries: Arc::new(DashMap::new()),
            inflight: Arc::new(DashMap::new()),
            epoch: AtomicU64::new(0),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    /// Borrow the wrapped store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Number of entries currently held (including any past their TTL but not
    /// yet evicted). Intended for diagnostics, not control flow.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every cached entry.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Drop the cached entry for `key`; returns whether one was present.
    ///
    /// This is the hook the Epic C push-invalidation channel calls when the
    /// Gateway reports that an agent's policy changed: the next `get` reloads
    /// from the source of truth rather than serving a stale entry.
    pub fn invalidate(&self, key: &S::Key) -> bool {
        // Bump the epoch *before* removing. A concurrent leader load that
        // snapshotted the old epoch will fail its post-load check and discard
        // its now-stale value; and because the leader commits its insert under
        // the same shard lock that `remove` takes, the bump-then-remove here is
        // ordered against the check-then-insert there — the eviction can't be
        // lost to a racing insert (AAASM-3985).
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.entries.remove(key).is_some()
    }

    /// Bound the live-entry count at [`max_entries`](Self::max_entries),
    /// evicting when an insert pushes the map over the ceiling (AAASM-3997).
    ///
    /// Eviction is a pure size-management concern, independent of the
    /// invalidation epoch: removing a cached entry is always safe (the worst
    /// case is a subsequent miss that reloads from the source of truth), so this
    /// never races the epoch/guarded-insert logic. It must be called *without*
    /// holding any `entries` shard guard to avoid a DashMap self-deadlock.
    fn enforce_capacity(&self) {
        if self.entries.len() <= self.max_entries {
            return;
        }
        // Cheap first pass: drop entries already past their TTL (they are misses
        // anyway) before resorting to age-based eviction of live entries.
        self.entries.retain(|_, value| !value.is_expired(self.ttl));
        let len = self.entries.len();
        if len <= self.max_entries {
            return;
        }
        // Still over budget: evict the oldest-by-insertion entries. Snapshot the
        // (inserted_at, key) pairs, sort ascending, and remove the excess.
        let mut stamped: Vec<(Instant, S::Key)> = self
            .entries
            .iter()
            .map(|entry| (entry.value().inserted_at, entry.key().clone()))
            .collect();
        stamped.sort_by_key(|(inserted_at, _)| *inserted_at);
        for (_, key) in stamped.into_iter().take(len - self.max_entries) {
            self.entries.remove(&key);
        }
    }

    /// Perform the single leader load for `key`: load from the wrapped store,
    /// commit the value under the key's shard lock (unless an `invalidate` raced
    /// the load), bound the cache size, then wake every waiting follower.
    ///
    /// Split out of [`get`](Self::get) so the leader's guarded check-and-insert
    /// reads as one unit; the epoch snapshot/re-check and shard-guard scoping are
    /// load-bearing (AAASM-3985 / AAASM-3997) — see the inline notes.
    async fn load_as_leader(&self, key: &S::Key) -> Result<S::Value> {
        // Snapshot the invalidation epoch before the load so a push
        // `invalidate` that lands mid-load is detected below.
        let epoch_before = self.epoch.load(Ordering::Acquire);
        let result = self.inner.load(key).await;
        let mut inserted = false;
        if let Ok(ref value) = result {
            // Commit under the key's shard lock, and only if no invalidation
            // raced the load. Holding the entry guard serializes this
            // check-and-insert against `invalidate`'s `remove`, so a concurrent
            // eviction is never lost: either we observe the bumped epoch and skip
            // the insert, or the remove runs after us and drops the entry we just
            // wrote. The guard is confined to this inner block so it is dropped
            // before `enforce_capacity` touches the map.
            {
                let entry = self.entries.entry(key.clone());
                if self.epoch.load(Ordering::Acquire) == epoch_before {
                    match entry {
                        Entry::Occupied(mut occupied) => {
                            occupied.insert(CachedValue::new(value.clone()));
                        }
                        Entry::Vacant(vacant) => {
                            vacant.insert(CachedValue::new(value.clone()));
                        }
                    }
                    inserted = true;
                }
            }
        }
        // Bound the cache size once the shard guard is released (AAASM-3997).
        // Only meaningful after a real insert.
        if inserted {
            self.enforce_capacity();
        }
        if let Some((_, notify)) = self.inflight.remove(key) {
            notify.notify_waiters();
        }
        result
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
                None => return self.load_as_leader(&key).await,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aa_core::storage::AgentId;

    use crate::testing::{sample_policy, MemoryPolicyStore};
    use crate::L1Cache;

    fn agent(seed: u8) -> AgentId {
        AgentId::from_bytes([seed; 16])
    }

    #[tokio::test]
    async fn miss_populates_then_serves_from_cache() {
        let id = agent(1);
        let store = MemoryPolicyStore::with_policy(id, sample_policy(1));
        let cache = L1Cache::new(store, Duration::from_secs(60));

        // First get is a miss: hits the store and populates the cache.
        let first = cache.get(id).await.expect("policy present");
        assert_eq!(first.version, 1);
        assert_eq!(cache.inner().call_count(), 1);
        assert_eq!(cache.len(), 1);

        // Second get is a hit: served from memory, the store is not touched again.
        let second = cache.get(id).await.expect("policy present");
        assert_eq!(second.version, 1);
        assert_eq!(cache.inner().call_count(), 1);
    }

    #[tokio::test]
    async fn expired_entry_is_treated_as_a_miss() {
        let id = agent(2);
        let store = MemoryPolicyStore::with_policy(id, sample_policy(1));
        let cache = L1Cache::new(store, Duration::from_millis(20));

        cache.get(id).await.expect("policy present");
        assert_eq!(cache.inner().call_count(), 1);

        // Let the entry age past its TTL; the next get must reload from the store.
        tokio::time::sleep(Duration::from_millis(40)).await;
        cache.get(id).await.expect("policy present");
        assert_eq!(cache.inner().call_count(), 2);
    }

    #[tokio::test]
    async fn invalidate_evicts_the_cached_entry() {
        let id = agent(3);
        let store = MemoryPolicyStore::with_policy(id, sample_policy(1));
        let cache = L1Cache::new(store, Duration::from_secs(60));

        cache.get(id).await.expect("policy present");
        assert_eq!(cache.len(), 1);

        // Invalidate removes the entry and reports it was present.
        assert!(cache.invalidate(&id));
        assert_eq!(cache.len(), 0);

        // Invalidating the now-absent key reports nothing was removed.
        assert!(!cache.invalidate(&id));

        // The next get is a fresh miss that reloads from the store.
        cache.get(id).await.expect("policy present");
        assert_eq!(cache.inner().call_count(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalidate_during_load_is_not_lost() {
        use std::sync::Arc;

        let id = agent(5);
        // A 50ms inner delay holds the leader inside `load` long enough for the
        // racing `invalidate` below to land in the middle of the load window.
        let store = MemoryPolicyStore::with_policy(id, sample_policy(1)).with_delay(Duration::from_millis(50));
        let cache = Arc::new(L1Cache::new(store, Duration::from_secs(60)));

        // Leader begins a miss and is now sleeping inside `load`.
        let leader = {
            let cache = Arc::clone(&cache);
            tokio::spawn(async move { cache.get(id).await })
        };

        // Let the leader enter `load`, then invalidate while it is in flight.
        // `entries` is still empty, so the old code's `remove` was a silent
        // no-op and the leader would go on to cache the value it is loading.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!cache.invalidate(&id));

        // The leader still returns the value it loaded, but must NOT have cached
        // it: the invalidation raced its load and takes precedence.
        leader.await.expect("task joined").expect("policy present");
        assert_eq!(
            cache.len(),
            0,
            "stale value must not be cached after a racing invalidate"
        );
        assert_eq!(cache.inner().call_count(), 1);

        // Because nothing was cached, the next get is a fresh miss that reloads
        // from the source of truth rather than serving the stale entry.
        cache.get(id).await.expect("policy present");
        assert_eq!(cache.inner().call_count(), 2);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn cache_is_bounded_by_max_entries() {
        // AAASM-3997: without a bound the L1 map grew once per distinct key and
        // never shrank. With a ceiling of 2, loading 5 distinct keys must leave
        // at most 2 resident, and the most-recently loaded key stays cached.
        let mut store = MemoryPolicyStore::new();
        for seed in 0..5u8 {
            store.insert(agent(seed), sample_policy(u32::from(seed)));
        }
        let cache = L1Cache::with_max_entries(store, Duration::from_secs(60), 2);

        for seed in 0..5u8 {
            cache.get(agent(seed)).await.expect("policy present");
        }

        assert!(cache.len() <= 2, "cache grew past its ceiling: {} entries", cache.len());

        // The newest key was loaded last, so it survived eviction: serving it is
        // a hit that does not touch the store again.
        let calls_before = cache.inner().call_count();
        cache.get(agent(4)).await.expect("policy present");
        assert_eq!(
            cache.inner().call_count(),
            calls_before,
            "the most-recently loaded key should still be cached"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_misses_collapse_to_one_load() {
        use std::sync::Arc;

        let id = agent(4);
        // A 50ms inner delay holds the leader long enough for all followers to
        // pile up behind it before it finishes loading.
        let store = MemoryPolicyStore::with_policy(id, sample_policy(7)).with_delay(Duration::from_millis(50));
        let cache = Arc::new(L1Cache::new(store, Duration::from_secs(60)));

        // Fire 100 concurrent gets for the same cold key.
        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let cache = Arc::clone(&cache);
            handles.push(tokio::spawn(async move { cache.get(id).await }));
        }
        for handle in handles {
            let policy = handle.await.expect("task joined").expect("policy present");
            assert_eq!(policy.version, 7);
        }

        // Every miss collapsed onto a single inner load.
        assert_eq!(cache.inner().call_count(), 1);
    }
}
