//! Redis L2 shared-cache storage driver for Agent Assembly.
//!
//! This crate implements three of the high-frequency [`aa_storage`] traits
//! against a Redis (or Valkey) instance so multiple Assembly processes can
//! coordinate through one shared cache instead of each hitting the L3 store:
//!
//! - [`RedisSessionStore`] — [`SessionStore`](aa_storage::SessionStore)
//! - [`RedisRateLimitCounter`] — [`RateLimitCounter`](aa_storage::RateLimitCounter)
//! - [`RedisPolicyStore`] — [`PolicyStore`](aa_storage::PolicyStore), used as a
//!   read-through cache in front of the authoritative store
//!
//! Build a [`RedisBackend`] from a [`RedisStorageConfig`] and hand out the
//! individual stores, or construct each store directly over a shared [`Pool`].
//!
//! # Key layout
//!
//! Every key is namespaced under `aa:`:
//!
//! | Store | Key | Value |
//! |---|---|---|
//! | session | `aa:session:<session_id>` | hash (`agent_id`, `started_at_ns`) |
//! | rate limit | `aa:ratelimit:<key>` | integer counter |
//! | policy | `aa:policy:<agent_id>` | JSON [`PolicyDocument`](aa_storage::PolicyDocument) |
//!
//! `<session_id>` and `<agent_id>` are the lower-case hex encodings of the
//! 16-byte ids.
//!
//! # TTL and invalidation semantics
//!
//! - **Sessions** expire after [`SESSION_TTL_SECS`] seconds. The TTL is
//!   re-armed on every [`save`](aa_storage::SessionStore::save) so an actively
//!   written session never lapses; [`delete`](aa_storage::SessionStore::delete)
//!   drops it immediately and is idempotent.
//! - **Rate-limit counters** carry the window length supplied to
//!   [`increment`](aa_storage::RateLimitCounter::increment) as their TTL. The
//!   expiry is armed exactly once — on the first increment that creates the key
//!   — so the window is **fixed**: it starts at the first hit and is not pushed
//!   forward by later increments within the same window.
//!   [`reset`](aa_storage::RateLimitCounter::reset) deletes the key.
//! - **Policies** are cached with an explicit per-entry TTL via
//!   [`RedisPolicyStore::cache_policy`] ([`DEFAULT_POLICY_CACHE_TTL_SECS`] is the
//!   suggested default). [`invalidate`](aa_storage::PolicyStore::invalidate)
//!   deletes the cached key so the next read misses and reloads from the
//!   authoritative store; it is idempotent.

#![warn(missing_docs)]

mod backend;
mod config;
mod error;
pub mod factory;
mod policy;
mod pool;
mod rate_limit;
mod session;
mod util;

pub use backend::RedisBackend;
pub use config::RedisStorageConfig;
pub use policy::{RedisPolicyStore, DEFAULT_POLICY_CACHE_TTL_SECS};
pub use pool::build_pool;
pub use rate_limit::RedisRateLimitCounter;
pub use session::{RedisSessionStore, SESSION_TTL_SECS};

/// Pooled Redis connection handle, re-exported for callers that build stores
/// directly with [`RedisSessionStore::new`] and friends.
pub use deadpool_redis::Pool;

/// The name this driver registers under in storage configuration, i.e. the
/// `[storage.<name>]` subsection and the registry key (`storage.backend = "redis"`).
pub const DRIVER_NAME: &str = "redis";

#[cfg(test)]
mod tests {
    #[test]
    fn driver_name_is_redis() {
        assert_eq!(super::DRIVER_NAME, "redis");
    }
}
