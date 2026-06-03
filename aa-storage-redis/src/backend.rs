//! Aggregate handle that builds one connection pool and hands out the three
//! Redis-backed stores over it.

use aa_storage::Result;
use deadpool_redis::Pool;

use crate::config::RedisStorageConfig;
use crate::policy::RedisPolicyStore;
use crate::pool::build_pool;
use crate::rate_limit::RedisRateLimitCounter;
use crate::session::RedisSessionStore;

/// A connected Redis storage driver.
///
/// Owns a single [`Pool`] shared by every store it hands out. Cheap to
/// [`Clone`].
#[derive(Clone)]
pub struct RedisBackend {
    pool: Pool,
}

impl RedisBackend {
    /// Build the connection pool described by `config`.
    ///
    /// Connections are lazy, so this returns immediately without contacting
    /// the server (see [`build_pool`]).
    pub fn connect(config: &RedisStorageConfig) -> Result<Self> {
        Ok(Self {
            pool: build_pool(config)?,
        })
    }

    /// Borrow the shared connection pool.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// A [`SessionStore`](aa_storage::SessionStore) over this connection.
    pub fn sessions(&self) -> RedisSessionStore {
        RedisSessionStore::new(self.pool.clone())
    }

    /// A [`RateLimitCounter`](aa_storage::RateLimitCounter) over this connection.
    pub fn rate_limiter(&self) -> RedisRateLimitCounter {
        RedisRateLimitCounter::new(self.pool.clone())
    }

    /// A [`PolicyStore`](aa_storage::PolicyStore) over this connection.
    pub fn policies(&self) -> RedisPolicyStore {
        RedisPolicyStore::new(self.pool.clone())
    }
}
