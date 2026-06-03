//! In-memory [`RateLimitCounter`] backed by a `DashMap` of windowed counters.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_storage::{RateLimitCounter, Result};
use async_trait::async_trait;
use dashmap::DashMap;

/// A single key's counter and the window it is bucketed into.
struct Window {
    count: u64,
    start: Instant,
    window: Duration,
}

/// A `DashMap`-backed [`RateLimitCounter`].
///
/// Each key tracks a count and the wall-clock start of its current window;
/// once the window elapses the count rolls over to zero on the next access.
/// `DashMap`'s per-key entry lock makes the read-modify-write in
/// [`increment`](RateLimitCounter::increment) atomic across concurrent callers.
/// Cloning shares the same underlying map.
#[derive(Clone, Default)]
pub struct MemoryRateLimitCounter {
    counters: Arc<DashMap<String, Window>>,
}

impl MemoryRateLimitCounter {
    /// Create an empty counter set.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RateLimitCounter for MemoryRateLimitCounter {
    async fn increment(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64> {
        let window = Duration::from_secs(window_secs);
        let now = Instant::now();
        let mut entry = self.counters.entry(key.to_owned()).or_insert_with(|| Window {
            count: 0,
            start: now,
            window,
        });
        if now.duration_since(entry.start) >= entry.window {
            entry.count = 0;
            entry.start = now;
            entry.window = window;
        }
        entry.count = entry.count.saturating_add(amount);
        Ok(entry.count)
    }

    async fn current(&self, key: &str) -> Result<u64> {
        match self.counters.get(key) {
            Some(entry) if Instant::now().duration_since(entry.start) < entry.window => Ok(entry.count),
            _ => Ok(0),
        }
    }

    async fn reset(&self, key: &str) -> Result<()> {
        self.counters.remove(key);
        Ok(())
    }
}
