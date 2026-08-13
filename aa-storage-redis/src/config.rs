//! Connection configuration for the Redis storage driver.
//!
//! Deserialized from the `[storage.redis]` TOML subsection.

use std::fmt;

use serde::Deserialize;

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
///
/// `Serialize` is intentionally **not** derived: the `url` carries
/// `redis://user:pass@host` credentials, and a derived `Serialize` would
/// round-trip the password in clear. `Debug` is implemented by hand below to
/// redact it for the same reason.
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

/// Custom `Debug` that redacts the password component of the connection URL.
///
/// The DSN may carry `redis://user:pass@host` credentials; the derived `Debug`
/// would print the password verbatim, so any future log of this config would
/// leak it. This impl renders the URL with the password replaced by `***`,
/// leaving every other field untouched. Diagnostic output only — the
/// unredacted [`url`](Self::url) is still what the pool connects with.
impl fmt::Debug for RedisStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisStorageConfig")
            .field("url", &redact_dsn_password(&self.url))
            .field("pool_size", &self.pool_size)
            .field("tls", &self.tls)
            .finish()
    }
}

/// Replace the password component of a `scheme://user:pass@host/...` DSN with
/// `***`, leaving the scheme, username, host, and path intact.
///
/// URLs without userinfo, or with userinfo but no password, are returned
/// unchanged. Used only for redacted diagnostic rendering — never on the value
/// handed to the connection layer.
fn redact_dsn_password(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let Some((userinfo, host_part)) = rest.split_once('@') else {
        return url.to_owned();
    };
    match userinfo.split_once(':') {
        Some((user, _password)) => format!("{scheme}://{user}:***@{host_part}"),
        None => url.to_owned(),
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
    fn debug_redacts_dsn_password() {
        let cfg = RedisStorageConfig {
            url: "redis://cacheuser:supersecret@cache.internal:6379".to_owned(),
            ..Default::default()
        };

        let rendered = format!("{cfg:?}");

        assert!(
            !rendered.contains("supersecret"),
            "password leaked in Debug: {rendered}"
        );
        assert!(
            rendered.contains("cacheuser:***@cache.internal:6379"),
            "redacted URL missing: {rendered}"
        );
    }

    #[test]
    fn debug_leaves_passwordless_dsn_untouched() {
        let cfg = RedisStorageConfig::default();
        assert!(format!("{cfg:?}").contains("redis://127.0.0.1:6379"));
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
