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
    let url = config.connection_url();

    if should_warn_plaintext(&url, config.tls) {
        tracing::warn!(
            "[storage.redis] connecting to a non-loopback Redis host in the clear (redis://); \
             enable TLS via `[storage.redis].tls = true` or a rediss:// URL to protect \
             credentials and cached data in transit"
        );
    }

    let mut cfg = Config::from_url(url);
    cfg.pool = Some(PoolConfig::new(config.pool_size));
    cfg.create_pool(Some(Runtime::Tokio1)).map_err(backend)
}

/// Decide whether [`build_pool`] should warn about plaintext transport: `true`
/// when TLS is not in effect (neither the `tls` flag nor a `rediss://` scheme)
/// and the URL points at a non-loopback host. Loopback hosts (and URLs with no
/// resolvable host) stay silent. Pure predicate so the decision is unit-testable.
fn should_warn_plaintext(url: &str, tls: bool) -> bool {
    if tls || url.starts_with("rediss://") {
        return false;
    }
    match url_host(url) {
        Some(host) => !is_loopback_host(host),
        None => false,
    }
}

/// Best-effort extraction of the host from a `scheme://[userinfo@]host[:port][/...]`
/// URL. Returns `None` when there is no authority component.
fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let authority = after_scheme.split(['/', '?']).next().unwrap_or(after_scheme);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 literal: `[::1]:6379` -> `::1`.
        return rest.split(']').next();
    }
    Some(host_port.split(':').next().unwrap_or(host_port))
}

/// `true` for loopback hosts: the literal `localhost` (any case) or any IP that
/// parses as a loopback address (`127.0.0.0/8`, `::1`).
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_plaintext_does_not_warn() {
        assert!(!should_warn_plaintext("redis://127.0.0.1:6379", false));
        assert!(!should_warn_plaintext("redis://localhost:6379", false));
        assert!(!should_warn_plaintext("redis://user:pw@[::1]:6379", false));
    }

    #[test]
    fn non_loopback_plaintext_warns() {
        assert!(should_warn_plaintext("redis://cache.internal:6379", false));
        assert!(should_warn_plaintext("redis://user:pw@10.0.0.5:6379", false));
    }

    #[test]
    fn tls_in_effect_does_not_warn() {
        // tls flag set
        assert!(!should_warn_plaintext("redis://cache.internal:6379", true));
        // rediss:// scheme already encrypts
        assert!(!should_warn_plaintext("rediss://cache.internal:6379", false));
    }
}
