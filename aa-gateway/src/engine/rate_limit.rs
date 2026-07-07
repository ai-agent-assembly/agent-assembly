//! Token bucket rate limiter for per-tool call limits.

use std::time::Instant;

/// Token bucket rate limiter.
///
/// Implements a token bucket algorithm that refills at a rate of `capacity` tokens per hour.
/// Used to enforce per-tool call limits.
#[allow(dead_code)]
pub(crate) struct TokenBucket {
    capacity: u32,
    tokens: f64,
    pub(crate) last_refill: Instant,
}

impl TokenBucket {
    #[allow(dead_code)]
    /// Create a new token bucket with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens and refill rate per hour
    pub(crate) fn new(capacity: u32) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    #[allow(dead_code)]
    /// Try to consume one token from the bucket, enforcing the given limit.
    ///
    /// If `limit` is lower than the bucket's current capacity, the capacity is
    /// tightened to the new limit and tokens are clamped accordingly. This
    /// prevents a bypass when multiple policies apply: a bucket created with a
    /// higher limit (e.g., 100) must honour a later, more restrictive policy
    /// (e.g., limit 10) rather than silently ignoring it (AAASM-4190).
    ///
    /// Refills tokens based on elapsed time since last call, then attempts to consume one token.
    /// Tokens refill at a rate of `capacity` tokens per hour (3600 seconds).
    ///
    /// Returns `true` if a token was consumed, `false` if the bucket is empty.
    pub(crate) fn try_consume_with_limit(&mut self, limit: u32) -> bool {
        // Tighten capacity if the requested limit is more restrictive.
        if limit < self.capacity {
            self.capacity = limit;
            self.tokens = f64::min(self.tokens, limit as f64);
        }
        let now = Instant::now();
        let elapsed_secs = (now - self.last_refill).as_secs_f64();
        self.tokens = f64::min(
            self.capacity as f64,
            self.tokens + self.capacity as f64 * elapsed_secs / 3600.0,
        );
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    #[allow(dead_code)]
    /// Try to consume one token from the bucket.
    ///
    /// Refills tokens based on elapsed time since last call, then attempts to consume one token.
    /// Tokens refill at a rate of `capacity` tokens per hour (3600 seconds).
    ///
    /// Returns `true` if a token was consumed, `false` if the bucket is empty.
    pub(crate) fn try_consume(&mut self) -> bool {
        self.try_consume_with_limit(self.capacity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn new_bucket_allows_up_to_capacity() {
        let mut bucket = TokenBucket::new(3);
        // Should be able to consume up to capacity
        assert!(bucket.try_consume(), "First consume should succeed");
        assert!(bucket.try_consume(), "Second consume should succeed");
        assert!(bucket.try_consume(), "Third consume should succeed");
        // Fourth consume should fail (no tokens left)
        assert!(!bucket.try_consume(), "Fourth consume should fail (capacity exceeded)");
    }

    #[test]
    fn bucket_refills_proportionally_after_half_hour() {
        let mut bucket = TokenBucket::new(60);
        // Consume all tokens
        for _ in 0..60 {
            bucket.try_consume();
        }
        // Verify bucket is empty
        assert!(
            !bucket.try_consume(),
            "Bucket should be empty after consuming all tokens"
        );

        // Manually set last_refill to 30 minutes ago (1800 seconds)
        bucket.last_refill = Instant::now() - Duration::from_secs(1800);

        // Try to consume - should succeed because 30 tokens should have refilled
        assert!(
            bucket.try_consume(),
            "Should be able to consume after refill (30 tokens refilled in 30 min)"
        );
    }

    #[test]
    fn bucket_does_not_exceed_capacity_on_refill() {
        let mut bucket = TokenBucket::new(10);
        // Manually set last_refill to 2 hours ago (7200 seconds)
        // This would normally refill 20 tokens, but should be capped at capacity (10)
        bucket.last_refill = Instant::now() - Duration::from_secs(7200);

        // Consume the capped 10 tokens
        for _ in 0..10 {
            assert!(bucket.try_consume(), "Should consume token");
        }

        // 11th consume should fail
        assert!(!bucket.try_consume(), "11th consume should fail (capacity is 10)");
    }

    #[test]
    fn tighter_limit_reduces_capacity_and_clamps_tokens() {
        // AAASM-4190: when multiple policies apply, a bucket created with a
        // higher limit must honour a later, more restrictive limit.
        let mut bucket = TokenBucket::new(100);
        // Bucket starts with 100 tokens. Consume 97, leaving 3.
        for _ in 0..97 {
            assert!(bucket.try_consume(), "Should consume token");
        }
        // Now apply a tighter limit of 2. The bucket's capacity should drop
        // to 2 and the remaining 3 tokens should clamp to 2.
        assert!(
            bucket.try_consume_with_limit(2),
            "First consume with tighter limit should succeed (2 tokens clamped, now 1)"
        );
        assert!(
            bucket.try_consume_with_limit(2),
            "Second consume with tighter limit should succeed (now 0)"
        );
        // Tokens exhausted after clamping to 2 and consuming twice.
        assert!(
            !bucket.try_consume_with_limit(2),
            "Third consume should fail (capacity tightened to 2, tokens exhausted)"
        );
    }

    #[test]
    fn looser_limit_does_not_expand_capacity() {
        // Once capacity is set, a looser limit should not expand it.
        let mut bucket = TokenBucket::new(5);
        // Consume all 5 tokens.
        for _ in 0..5 {
            assert!(bucket.try_consume(), "Should consume token");
        }
        // Bucket is empty. Calling with a higher limit (100) should NOT
        // expand capacity back to 100.
        assert!(
            !bucket.try_consume_with_limit(100),
            "Should still fail (capacity remains 5, not expanded to 100)"
        );
        assert_eq!(bucket.capacity, 5, "Capacity should remain 5");
    }
}
