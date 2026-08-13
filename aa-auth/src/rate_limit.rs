//! In-memory per-key rate limiter using token bucket algorithm.

use std::time::Instant;

use dashmap::DashMap;

/// A token bucket that refills at a fixed rate.
#[derive(Debug)]
struct TokenBucket {
    /// Current number of available tokens.
    tokens: f64,
    /// Maximum number of tokens (bucket capacity).
    capacity: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time the bucket was refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new full bucket with the given capacity (requests per minute).
    #[cfg(test)]
    fn new(rpm: u32) -> Self {
        Self::new_with_window(rpm, 60)
    }

    /// Create a new full bucket with an explicit refill window (seconds per full cycle).
    fn new_with_window(rpm: u32, window_secs: u64) -> Self {
        let capacity = f64::from(rpm);
        let window = window_secs.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity / window,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns `Ok(())` if allowed, or
    /// `Err(seconds)` with the number of seconds until the next token
    /// is available.
    fn try_consume(&mut self) -> Result<(), u64> {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate seconds until one token is available.
            let deficit = 1.0 - self.tokens;
            let wait_secs = (deficit / self.refill_rate).ceil() as u64;
            Err(wait_secs.max(1))
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = now;
    }
}

/// Concurrent per-key rate limiter.
///
/// Each API key ID gets its own [`TokenBucket`]. Buckets are created
/// on first access and cleaned up when stale.
pub struct RateLimiter {
    buckets: DashMap<String, TokenBucket>,
    rpm: u32,
    /// Refill window in seconds.  Production default: 60 (1 rpm = 1 token per
    /// 60 s).  Override via `AA_RATE_LIMIT_WINDOW_SECS` env-var or by
    /// constructing with [`RateLimiter::new_with_window`].
    window_secs: u64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given per-key requests-per-minute limit.
    ///
    /// The refill window defaults to 60 seconds unless `AA_RATE_LIMIT_WINDOW_SECS`
    /// is set in the environment.
    pub fn new(rpm: u32) -> Self {
        let window_secs = std::env::var("AA_RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        Self::new_with_window(rpm, window_secs)
    }

    /// Create a new rate limiter with an explicit refill window.
    ///
    /// Intended for tests that need a short window without setting an env-var.
    pub fn new_with_window(rpm: u32, window_secs: u64) -> Self {
        Self {
            buckets: DashMap::new(),
            rpm,
            window_secs: window_secs.max(1),
        }
    }

    /// Check whether a request from the given key ID is allowed.
    ///
    /// Returns `Ok(())` if the request is within the rate limit, or
    /// `Err(retry_after_secs)` if the rate limit is exceeded.
    pub fn check(&self, key_id: &str) -> Result<(), u64> {
        let mut bucket = self
            .buckets
            .entry(key_id.to_string())
            .or_insert_with(|| TokenBucket::new_with_window(self.rpm, self.window_secs));
        bucket.try_consume()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allows_within_limit() {
        let mut bucket = TokenBucket::new(100);
        for _ in 0..100 {
            assert!(bucket.try_consume().is_ok());
        }
    }

    #[test]
    fn test_token_bucket_rejects_over_limit() {
        let mut bucket = TokenBucket::new(10);
        for _ in 0..10 {
            bucket.try_consume().unwrap();
        }
        let result = bucket.try_consume();
        assert!(result.is_err(), "should reject when tokens exhausted");
        let retry_after = result.unwrap_err();
        assert!(retry_after >= 1, "retry_after should be at least 1 second");
    }

    #[test]
    fn test_token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(60); // 1 token per second
                                               // Exhaust all tokens.
        for _ in 0..60 {
            bucket.try_consume().unwrap();
        }
        assert!(bucket.try_consume().is_err());

        // Simulate time passing by adjusting last_refill.
        bucket.last_refill = Instant::now() - std::time::Duration::from_secs(2);
        assert!(bucket.try_consume().is_ok(), "should have tokens after refill");
    }

    #[test]
    fn test_rate_limiter_per_key_isolation() {
        let limiter = RateLimiter::new(5);

        // Exhaust key-a.
        for _ in 0..5 {
            limiter.check("key-a").unwrap();
        }
        assert!(limiter.check("key-a").is_err(), "key-a should be exhausted");

        // key-b should still have tokens.
        assert!(limiter.check("key-b").is_ok(), "key-b should be independent");
    }
}
