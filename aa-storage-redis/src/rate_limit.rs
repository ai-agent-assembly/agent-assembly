//! [`RateLimitCounter`] using an atomic Lua `INCRBY` + `EXPIRE` script.

use aa_storage::{RateLimitCounter, Result};
use async_trait::async_trait;
use deadpool_redis::Pool;

use crate::error::backend;

/// Lua source executed atomically by Redis for each
/// [`increment`](RateLimitCounter::increment).
///
/// `INCRBY` the counter, then arm `EXPIRE` only when this call created the key
/// (the returned total equals the amount just added). Running both commands
/// inside one script makes the read-modify-write atomic with respect to
/// concurrent callers and starts a **fixed** window at the first increment.
const INCREMENT_SCRIPT: &str = r"
local current = redis.call('INCRBY', KEYS[1], ARGV[1])
if tonumber(current) == tonumber(ARGV[1]) then
    redis.call('EXPIRE', KEYS[1], ARGV[2])
end
return current
";

/// Redis-backed [`RateLimitCounter`].
///
/// Counters live at `aa:ratelimit:<key>`. Cheap to [`Clone`] — clones share
/// the underlying [`Pool`].
#[derive(Clone)]
pub struct RedisRateLimitCounter {
    pool: Pool,
}

impl RedisRateLimitCounter {
    /// Create a counter over an existing connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

// TODO(AAASM-3919): namespace this key by the verified tenant/org id
// (e.g. `aa:ratelimit:<org_id>:<key>`) once org context is threaded into the
// RateLimitCounter path. The shared L2 cache currently has no tenant boundary;
// caller-supplied keys are expected to be globally unique so there is no
// collision today, but also no isolation. Deferred here because
// RateLimitCounter::increment/current/reset carry only an opaque key — adding a
// prefix without the org id would break lookups.
fn counter_key(key: &str) -> String {
    format!("aa:ratelimit:{key}")
}

#[async_trait]
impl RateLimitCounter for RedisRateLimitCounter {
    async fn increment(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let total: i64 = redis::Script::new(INCREMENT_SCRIPT)
            .key(counter_key(key))
            .arg(amount)
            .arg(window_secs)
            .invoke_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(u64::try_from(total).unwrap_or(0))
    }

    async fn current(&self, key: &str) -> Result<u64> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let value: Option<u64> = redis::cmd("GET")
            .arg(counter_key(key))
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(value.unwrap_or(0))
    }

    async fn reset(&self, key: &str) -> Result<()> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let _: () = redis::cmd("DEL")
            .arg(counter_key(key))
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
