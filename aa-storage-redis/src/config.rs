//! Connection configuration for the Redis storage driver.
//!
//! Deserialized from the `[storage.redis]` TOML subsection.

use serde::{Deserialize, Serialize};

/// Settings for the `[storage.redis]` subsection of `agent-assembly.toml`.
///
/// ```toml
/// [storage.redis]
/// url = "redis://cache.internal:6379"
/// pool_size = 16
/// tls = false
/// ```
///
/// All fields fall back to [`Default`] when omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisStorageConfig {
    /// Redis connection URL. A `redis://` scheme connects in the clear; a
    /// `rediss://` scheme (or [`tls = true`](Self::tls)) connects over TLS.
    pub url: String,
    /// Maximum number of pooled connections.
    pub pool_size: usize,
    /// When `true`, force a TLS connection by upgrading a `redis://` URL to
    /// `rediss://` (see [`connection_url`](Self::connection_url)). A URL that is
    /// already `rediss://` connects over TLS regardless of this flag.
    pub tls: bool,
}

impl Default for RedisStorageConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_owned(),
            pool_size: 10,
            tls: false,
        }
    }
}

impl RedisStorageConfig {
    /// Return the effective connection URL, upgrading a plaintext `redis://`
    /// URL to `rediss://` when [`tls`](Self::tls) is set. URLs that already use
    /// a `rediss://` scheme, or any non-`redis://` scheme, are returned
    /// unchanged.
    pub fn connection_url(&self) -> String {
        if self.tls {
            if let Some(rest) = self.url.strip_prefix("redis://") {
                return format!("rediss://{rest}");
            }
        }
        self.url.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Storage {
        redis: RedisStorageConfig,
    }
    #[derive(serde::Deserialize)]
    struct Root {
        storage: Storage,
    }

    #[test]
    fn parses_storage_redis_subsection() {
        let src = r#"
[storage.redis]
url = "rediss://cache.internal:6380"
pool_size = 32
tls = true
"#;
        let root: Root = toml::from_str(src).unwrap();
        assert_eq!(root.storage.redis.url, "rediss://cache.internal:6380");
        assert_eq!(root.storage.redis.pool_size, 32);
        assert!(root.storage.redis.tls);
    }

    #[test]
    fn applies_defaults_for_missing_fields() {
        let cfg: RedisStorageConfig = toml::from_str("").unwrap();
        assert_eq!(cfg, RedisStorageConfig::default());
        assert_eq!(cfg.connection_url(), "redis://127.0.0.1:6379");
    }

    #[test]
    fn tls_toggle_upgrades_scheme() {
        let cfg = RedisStorageConfig {
            tls: true,
            ..Default::default()
        };
        assert_eq!(cfg.connection_url(), "rediss://127.0.0.1:6379");
    }
}
