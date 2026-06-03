//! [`RateLimitCounter`] — read-modify-write counters for rate limiting.

use super::Result;
use async_trait::async_trait;

/// Atomic counters keyed by an arbitrary string, used for rate limiting.
///
/// The defining operation is [`increment`](RateLimitCounter::increment): it must
/// apply the read-modify-write **atomically** so two concurrent callers can never
/// observe or commit the same pre-increment value. Counters are scoped to a
/// fixed-length window; `window_secs` lets the backend bucket and expire counts
/// without the caller tracking wall-clock time.
///
/// # Example
///
/// ```
/// use aa_core::storage::{RateLimitCounter, Result};
/// use async_trait::async_trait;
///
/// /// A counter that always reports a single hit (a stand-in for a real backend).
/// struct AlwaysOne;
///
/// #[async_trait]
/// impl RateLimitCounter for AlwaysOne {
///     async fn increment(&self, _key: &str, _amount: u64, _window_secs: u64) -> Result<u64> {
///         Ok(1)
///     }
///
///     async fn current(&self, _key: &str) -> Result<u64> {
///         Ok(1)
///     }
///
///     async fn reset(&self, _key: &str) -> Result<()> {
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait RateLimitCounter: Send + Sync {
    /// Atomically add `amount` to the counter for `key` within the window of
    /// length `window_secs`, returning the new total for the current window.
    ///
    /// The read-modify-write is atomic with respect to concurrent callers.
    async fn increment(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64>;

    /// Return the current total for `key` without modifying it.
    ///
    /// Returns `0` for a key that has never been incremented (or whose window
    /// has expired).
    async fn current(&self, key: &str) -> Result<u64>;

    /// Reset the counter for `key` back to zero.
    ///
    /// Idempotent: resetting an absent key succeeds.
    async fn reset(&self, key: &str) -> Result<()>;
}
