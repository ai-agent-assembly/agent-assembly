//! Factories that build the Redis-backed stores for the `aa-storage` driver
//! registry.
//!
//! Redis backs the three high-frequency L2-cache kinds — policy, session, and
//! rate-limit. Audit / credential / lifecycle are durable concerns the Redis
//! driver does not implement, so [`crate::register`] registers only these three;
//! the other kinds stay on the builtin placeholder.

use std::sync::Arc;

use aa_storage::factory::{PolicyStoreFactory, RateLimitCounterFactory, SessionStoreFactory};
use aa_storage::{PolicyStore, RateLimitCounter, Result, SessionStore, StorageError};

use crate::config::RedisStorageConfig;
use crate::RedisBackend;

/// Parse a `[storage.redis]` subsection into a [`RedisStorageConfig`].
fn parse_config(config: &toml::Value) -> Result<RedisStorageConfig> {
    config
        .clone()
        .try_into()
        .map_err(|e: toml::de::Error| StorageError::Backend(format!("invalid [storage.redis] config: {e}")))
}

/// Builds a [`RedisPolicyStore`](crate::RedisPolicyStore) from `[storage.redis]`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedisPolicyStoreFactory;

impl PolicyStoreFactory for RedisPolicyStoreFactory {
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn PolicyStore>> {
        let backend = RedisBackend::connect(&parse_config(config)?)?;
        Ok(Arc::new(backend.policies()))
    }
}

/// Builds a [`RedisSessionStore`](crate::RedisSessionStore) from `[storage.redis]`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedisSessionStoreFactory;

impl SessionStoreFactory for RedisSessionStoreFactory {
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn SessionStore>> {
        let backend = RedisBackend::connect(&parse_config(config)?)?;
        Ok(Arc::new(backend.sessions()))
    }
}

/// Builds a [`RedisRateLimitCounter`](crate::RedisRateLimitCounter) from `[storage.redis]`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RedisRateLimitCounterFactory;

impl RateLimitCounterFactory for RedisRateLimitCounterFactory {
    fn build(&self, config: &toml::Value) -> Result<Arc<dyn RateLimitCounter>> {
        let backend = RedisBackend::connect(&parse_config(config)?)?;
        Ok(Arc::new(backend.rate_limiter()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redis_section() -> toml::Value {
        toml::from_str(
            r#"
url = "redis://127.0.0.1:6379"
pool_size = 4
tls = false
"#,
        )
        .unwrap()
    }

    #[test]
    fn policy_factory_builds_from_config() {
        assert!(RedisPolicyStoreFactory.build(&redis_section()).is_ok());
    }

    #[test]
    fn session_factory_builds_from_config() {
        assert!(RedisSessionStoreFactory.build(&redis_section()).is_ok());
    }

    #[test]
    fn rate_limit_factory_builds_from_config() {
        assert!(RedisRateLimitCounterFactory.build(&redis_section()).is_ok());
    }
}
