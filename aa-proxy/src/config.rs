//! Runtime configuration for `aa-proxy`.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::ProxyError;

/// Runtime configuration for the proxy sidecar.
///
/// All fields can be overridden via environment variables.
#[derive(Debug)]
pub struct ProxyConfig {
    /// TCP address the proxy listens on.
    /// Env: `AA_PROXY_ADDR` — default: `127.0.0.1:8899`
    pub bind_addr: SocketAddr,

    /// Directory where the CA certificate and key are stored.
    /// Env: `AA_CA_DIR` — default: `~/.aa/ca/`
    pub ca_dir: PathBuf,

    /// Maximum number of dynamically generated certificates to cache.
    /// Default: 1000
    pub cert_cache_capacity: usize,

    /// When `true`, only LLM API traffic is intercepted; all other HTTPS is
    /// forwarded transparently.
    /// Env: `AA_PROXY_LLM_ONLY` — default: `true`
    pub llm_only: bool,

    /// Hosts that the proxy will block at the CONNECT level (HTTP 403).
    /// Comma-separated list from env var `AA_PROXY_DENIED_HOSTS`.
    /// Empty means allow all hosts.
    pub denied_hosts: Vec<String>,
}

impl ProxyConfig {
    /// Build a `ProxyConfig` from environment variables, falling back to
    /// defaults where variables are not set.
    pub fn from_env() -> Result<Self, ProxyError> {
        let bind_addr = match std::env::var("AA_PROXY_ADDR") {
            Ok(val) => val
                .parse::<SocketAddr>()
                .map_err(|e| ProxyError::Config(format!("invalid AA_PROXY_ADDR: {e}")))?,
            Err(_) => SocketAddr::from(([127, 0, 0, 1], 8899)),
        };

        let ca_dir = match std::env::var("AA_CA_DIR") {
            Ok(val) => PathBuf::from(val),
            Err(_) => dirs::home_dir()
                .ok_or_else(|| ProxyError::Config("cannot determine home directory".into()))?
                .join(".aa")
                .join("ca"),
        };

        let cert_cache_capacity = match std::env::var("AA_PROXY_CERT_CACHE_CAPACITY") {
            Ok(val) => val
                .parse::<usize>()
                .map_err(|e| ProxyError::Config(format!("invalid AA_PROXY_CERT_CACHE_CAPACITY: {e}")))?,
            Err(_) => 1000,
        };

        let llm_only = match std::env::var("AA_PROXY_LLM_ONLY") {
            Ok(val) => val != "0" && val.to_lowercase() != "false",
            Err(_) => true,
        };

        let denied_hosts = match std::env::var("AA_PROXY_DENIED_HOSTS") {
            Ok(val) if !val.is_empty() => val
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => Vec::new(),
        };

        Ok(Self {
            bind_addr,
            ca_dir,
            cert_cache_capacity,
            llm_only,
            denied_hosts,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Serialise env-var tests so they don't race each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env_vars() {
        std::env::remove_var("AA_PROXY_ADDR");
        std::env::remove_var("AA_CA_DIR");
        std::env::remove_var("AA_PROXY_CERT_CACHE_CAPACITY");
        std::env::remove_var("AA_PROXY_LLM_ONLY");
        std::env::remove_var("AA_PROXY_DENIED_HOSTS");
    }

    #[test]
    fn from_env_returns_defaults_when_no_vars_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.bind_addr, SocketAddr::from(([127, 0, 0, 1], 8899)));
        assert!(cfg.ca_dir.ends_with(".aa/ca"));
        assert_eq!(cfg.cert_cache_capacity, 1000);
        assert!(cfg.llm_only);
        assert!(cfg.denied_hosts.is_empty());
    }

    #[test]
    fn from_env_reads_aa_proxy_addr() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_ADDR", "0.0.0.0:9000");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.bind_addr, SocketAddr::from(([0, 0, 0, 0], 9000)));
    }

    #[test]
    fn from_env_invalid_addr_returns_config_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_ADDR", "not-an-addr");

        let err = ProxyConfig::from_env().unwrap_err();
        assert!(err.to_string().contains("AA_PROXY_ADDR"));
    }

    #[test]
    fn from_env_reads_aa_ca_dir() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_CA_DIR", "/tmp/custom-ca");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.ca_dir, PathBuf::from("/tmp/custom-ca"));
    }

    #[test]
    fn from_env_reads_llm_only_false() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_LLM_ONLY", "false");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(!cfg.llm_only);
    }

    #[test]
    fn from_env_reads_llm_only_zero() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_LLM_ONLY", "0");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(!cfg.llm_only);
    }

    #[test]
    fn from_env_reads_denied_hosts_csv() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_DENIED_HOSTS", "evil.com, bad.example.com");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.denied_hosts, vec!["evil.com", "bad.example.com"]);
    }

    #[test]
    fn from_env_denied_hosts_empty_string_gives_empty_vec() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_DENIED_HOSTS", "");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.denied_hosts.is_empty());
    }
}
