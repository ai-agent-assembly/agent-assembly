//! Redis L2 shared-cache storage driver for Agent Assembly.
//!
//! Implements the high-frequency `aa-storage` traits — `SessionStore`,
//! `RateLimitCounter`, and `PolicyStore` — against a Redis (or Valkey)
//! instance so multiple Assembly processes coordinate through one shared cache.

#![warn(missing_docs)]

mod config;
mod error;
mod pool;

pub use config::RedisStorageConfig;
pub use pool::build_pool;

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
