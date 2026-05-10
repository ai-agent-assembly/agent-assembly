//! Clock abstraction for deterministic time injection in the approval router.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Provides the current Unix timestamp in seconds.
pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// Production clock backed by the system wall-clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Deterministic clock for unit tests.
pub struct FakeClock(AtomicU64);

impl FakeClock {
    pub fn new(secs: u64) -> Self {
        Self(AtomicU64::new(secs))
    }

    pub fn set(&self, secs: u64) {
        self.0.store(secs, Ordering::Relaxed);
    }
}

impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_nonzero_timestamp() {
        let c = SystemClock;
        assert!(c.now_secs() > 0);
    }

    #[test]
    fn fake_clock_initialises_and_advances() {
        let c = FakeClock::new(1000);
        assert_eq!(c.now_secs(), 1000);
        c.set(2000);
        assert_eq!(c.now_secs(), 2000);
    }
}
