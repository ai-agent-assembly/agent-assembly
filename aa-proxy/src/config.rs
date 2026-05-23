//! Runtime configuration for `aa-proxy`.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::error::ProxyError;

/// Action the proxy takes when its `CredentialScanner` produces a finding
/// inside a flowing request body.
///
/// Mirrors `aa_gateway::policy::document::CredentialAction` but lives in the
/// proxy crate so the data path can enforce policy locally without taking
/// a dependency on the gateway. The variants and their semantics are
/// intentionally identical so a single YAML field can drive both layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CredentialAction {
    /// Refuse the request: the proxy returns 403 to the client and **never**
    /// dials upstream. The credential never leaves the host.
    Block,
    /// Forward a redacted form of the body upstream (default; matches the
    /// historical behaviour from before this enum existed).
    #[default]
    RedactOnly,
    /// Forward the unmodified body and raise a critical alert as a
    /// side-effect. Documented as a deliberate downgrade for audit-only modes.
    AlertOnly,
}

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

    /// When `true`, the proxy skips TLS certificate verification when
    /// connecting to upstream servers. Intended for integration tests only —
    /// never enable in production.
    /// Env: `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY` — default: `false`
    pub skip_upstream_tls_verify: bool,

    /// Action to take when the in-path credential scanner detects a secret in
    /// a flowing request body. Drives Layer 2 enforcement for LLM requests.
    ///
    /// Defaults to [`CredentialAction::RedactOnly`] which preserves the
    /// historical behaviour (the proxy forwards but the audit chain carries
    /// a redacted form).
    pub credential_action: CredentialAction,
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

        let skip_upstream_tls_verify = match std::env::var("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY") {
            Ok(val) => val == "1" || val.to_lowercase() == "true",
            Err(_) => false,
        };

        let credential_action = match std::env::var("AA_PROXY_CREDENTIAL_ACTION") {
            Ok(val) => parse_credential_action(&val)?,
            Err(_) => CredentialAction::default(),
        };

        Ok(Self {
            bind_addr,
            ca_dir,
            cert_cache_capacity,
            llm_only,
            denied_hosts,
            skip_upstream_tls_verify,
            credential_action,
        })
    }
}

/// Parse a credential action from its string representation.
///
/// Accepts `"block"`, `"redact_only"`, `"alert_only"` (case-insensitive).
/// Returns [`ProxyError::Config`] for any other value.
fn parse_credential_action(s: &str) -> Result<CredentialAction, ProxyError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "block" => Ok(CredentialAction::Block),
        "redact_only" => Ok(CredentialAction::RedactOnly),
        "alert_only" => Ok(CredentialAction::AlertOnly),
        other => Err(ProxyError::Config(format!(
            "invalid AA_PROXY_CREDENTIAL_ACTION: {other:?} (expected block | redact_only | alert_only)"
        ))),
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
        std::env::remove_var("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY");
        std::env::remove_var("AA_PROXY_CREDENTIAL_ACTION");
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
        assert!(!cfg.skip_upstream_tls_verify);
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

    #[test]
    fn from_env_skip_upstream_tls_verify_true() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.skip_upstream_tls_verify);
    }

    #[test]
    fn from_env_skip_upstream_tls_verify_false_by_default() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(!cfg.skip_upstream_tls_verify);
    }

    #[test]
    fn from_env_credential_action_defaults_to_redact_only() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.credential_action, CredentialAction::RedactOnly);
    }

    #[test]
    fn from_env_credential_action_reads_block() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_CREDENTIAL_ACTION", "block");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.credential_action, CredentialAction::Block);
    }

    #[test]
    fn from_env_credential_action_reads_alert_only_case_insensitive() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_CREDENTIAL_ACTION", "ALERT_ONLY");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.credential_action, CredentialAction::AlertOnly);
    }

    #[test]
    fn from_env_credential_action_invalid_returns_config_error() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_CREDENTIAL_ACTION", "nope");

        let err = ProxyConfig::from_env().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("AA_PROXY_CREDENTIAL_ACTION"),
            "error must name the env var, got: {msg}"
        );
    }
}
