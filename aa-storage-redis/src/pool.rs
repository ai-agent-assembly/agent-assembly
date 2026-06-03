//! Connection-pool construction from [`RedisStorageConfig`].

use aa_storage::Result;
use deadpool_redis::{Config, PoolConfig, Runtime};

use crate::config::RedisStorageConfig;
use crate::error::backend;

/// Build a [`deadpool_redis::Pool`] sized to
/// [`pool_size`](RedisStorageConfig::pool_size).
///
/// Connections are established lazily on first use, so this only fails if the
/// URL itself is unparseable — an unreachable server surfaces later, as a
/// [`StorageError::Backend`](aa_storage::StorageError::Backend) from the first
/// store call.
pub fn build_pool(config: &RedisStorageConfig) -> Result<deadpool_redis::Pool> {
    let mut cfg = Config::from_url(config.connection_url());
    cfg.pool = Some(PoolConfig::new(config.pool_size));
    cfg.create_pool(Some(Runtime::Tokio1)).map_err(backend)
}
