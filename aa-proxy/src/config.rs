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

    /// AAASM-4126 — additional hosts to bring under TLS MitM + credential-DLP
    /// even when [`Self::llm_only`] is `true`.
    ///
    /// Under `llm_only` the proxy MitMs only the built-in LLM providers
    /// (`detect_api`: OpenAI/Anthropic/Cohere) and transparent-tunnels every
    /// other host — so a secret POSTed to any other provider (Google, Mistral,
    /// Groq, Azure OpenAI, Bedrock, …) was never scanned. Operators list extra
    /// providers here to extend the DLP surface without disabling `llm_only`
    /// wholesale. Body-DLP then runs on these hosts exactly as it does for the
    /// built-in providers.
    ///
    /// Patterns share the egress-allowlist grammar with
    /// [`Self::network_allowlist`] (exact case-insensitive match, leftmost-label
    /// wildcard `*.groq.com`, or universal `*`). An empty list (the default)
    /// leaves only the built-in LLM hosts under MitM when `llm_only` is `true`.
    /// Has no effect when `llm_only` is `false` — every host is already MitM'd.
    ///
    /// Comma-separated list from env var `AA_PROXY_MITM_HOSTS`.
    pub mitm_hosts: Vec<String>,

    /// Hosts that the proxy will block at the CONNECT level (HTTP 403).
    /// Comma-separated list from env var `AA_PROXY_DENIED_HOSTS`.
    /// Empty means allow all hosts.
    pub denied_hosts: Vec<String>,

    /// AAASM-1943 — network egress allowlist. When **non-empty**, the proxy
    /// permits CONNECT only to hosts matching at least one pattern; all
    /// others are blocked with HTTP 403 + `A2AImpersonationAttempted`-style
    /// audit event. When **empty** (the default), no allowlist filter is
    /// applied — the `denied_hosts` block-list continues to be the only
    /// host-level gate.
    ///
    /// Patterns share grammar with
    /// [`aa_core::policy::is_host_allowed_by_egress_allowlist`]: exact
    /// case-insensitive match, leftmost-label wildcard (`*.openai.com`), or
    /// universal `*`.
    ///
    /// Comma-separated list from env var `AA_PROXY_NETWORK_ALLOWLIST`.
    pub network_allowlist: Vec<String>,

    /// When `true`, the proxy skips TLS certificate verification when
    /// connecting to upstream servers. Intended for integration tests only.
    ///
    /// AAASM-3131: honoured **only in debug builds**. In a release build the
    /// `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY` env var is ignored and this stays
    /// `false`, so a deployed production binary can never disable upstream cert
    /// verification. When it *is* active (debug), [`crate::run`] prints a loud
    /// startup banner.
    /// Env: `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY` — default: `false`
    pub skip_upstream_tls_verify: bool,

    /// Action to take when the in-path credential scanner detects a secret in
    /// a flowing request body. Drives Layer 2 enforcement for LLM requests.
    ///
    /// Defaults to [`CredentialAction::RedactOnly`] which preserves the
    /// historical behaviour (the proxy forwards but the audit chain carries
    /// a redacted form).
    pub credential_action: CredentialAction,

    /// Override the upstream socket address the proxy dials, regardless of
    /// the CONNECT request's target host. Intended for integration tests
    /// only — production deployments leave this `None` so the proxy dials
    /// the real LLM endpoint resolved from the CONNECT line.
    ///
    /// When `Some`, the original hostname is still used for SNI and the
    /// MitM certificate so the client's TLS verification continues to work
    /// against the per-host CA chain.
    pub upstream_override: Option<SocketAddr>,

    /// Endpoint of the `aa-gateway` PolicyService gRPC server. When `Some`,
    /// the proxy connects on startup and forwards MCP `tools/call` bodies
    /// to the gateway for structured policy evaluation (AAASM-1930). When
    /// `None`, MCP enforcement is disabled and bodies pass through to the
    /// existing credential-scanner data path unchanged.
    ///
    /// Env: `AA_PROXY_GATEWAY_ENDPOINT` — e.g. `http://127.0.0.1:50051`.
    pub gateway_endpoint: Option<String>,

    /// AAASM-3357 — what to do when MCP enforcement is configured (a
    /// [`Self::gateway_endpoint`] is set) but the gateway is unreachable,
    /// either at startup or on a per-call `CheckAction` RPC.
    ///
    /// MCP enforcement is a governance path: silently forwarding when the
    /// authority is down is a fail-open security hole. The default is
    /// therefore **fail-closed** (`false`) — an MCP `tools/call` is denied
    /// with a JSON-RPC error envelope when the gateway cannot be reached.
    ///
    /// Operators who explicitly prefer availability over enforcement can set
    /// this to `true` to restore the historical soft-degradation behaviour
    /// (forward without enforcement).
    ///
    /// This knob only affects MCP `tools/call` enforcement. Non-MCP traffic
    /// is unaffected and continues to flow.
    ///
    /// Env: `AA_PROXY_MCP_FAIL_OPEN` — `1`/`true` to fail open; default `false`.
    pub mcp_fail_open: bool,

    /// When `true`, the AAASM-3130 SSRF guard permits CONNECT targets that
    /// resolve to private / loopback / link-local address ranges. Intended for
    /// integration tests **only** — they stand up an in-process mock upstream
    /// on `127.0.0.1`, which the SSRF guard would (correctly) refuse to dial in
    /// production.
    ///
    /// There is **no env var** for this knob: [`ProxyConfig::from_env`] always
    /// leaves it `false`, so a deployed binary can never be coaxed into
    /// reaching internal address space. The guard's protection is unchanged in
    /// every non-test build.
    pub allow_private_connect_targets: bool,
}

impl ProxyConfig {
    /// Build a `ProxyConfig` from environment variables, falling back to
    /// defaults where variables are not set.
    pub fn from_env() -> Result<Self, ProxyError> {
        Ok(Self {
            bind_addr: parse_bind_addr()?,
            ca_dir: parse_ca_dir()?,
            cert_cache_capacity: parse_cert_cache_capacity()?,
            llm_only: parse_llm_only(),
            mitm_hosts: env_csv("AA_PROXY_MITM_HOSTS"),
            denied_hosts: env_csv("AA_PROXY_DENIED_HOSTS"),
            network_allowlist: env_csv("AA_PROXY_NETWORK_ALLOWLIST"),
            skip_upstream_tls_verify: resolve_skip_upstream_tls_verify(),
            credential_action: parse_credential_action_env()?,
            upstream_override: None,
            gateway_endpoint: env_optional("AA_PROXY_GATEWAY_ENDPOINT"),
            // AAASM-3357: default fail-closed. Only an explicit truthy value
            // opts into the historical fail-open soft-degradation behaviour.
            mcp_fail_open: env_truthy("AA_PROXY_MCP_FAIL_OPEN"),
            // No env var: production binaries can never relax the SSRF guard.
            allow_private_connect_targets: false,
        })
    }
}

/// Parse the `AA_PROXY_ADDR` env var or return the default bind address.
fn parse_bind_addr() -> Result<SocketAddr, ProxyError> {
    match std::env::var("AA_PROXY_ADDR") {
        Ok(val) => val
            .parse::<SocketAddr>()
            .map_err(|e| ProxyError::Config(format!("invalid AA_PROXY_ADDR: {e}"))),
        Err(_) => Ok(SocketAddr::from(([127, 0, 0, 1], 8899))),
    }
}

/// Parse the `AA_CA_DIR` env var or return the default CA directory.
fn parse_ca_dir() -> Result<PathBuf, ProxyError> {
    match std::env::var("AA_CA_DIR") {
        Ok(val) => Ok(PathBuf::from(val)),
        Err(_) => dirs::home_dir()
            .ok_or_else(|| ProxyError::Config("cannot determine home directory".into()))
            .map(|h| h.join(".aa").join("ca")),
    }
}

/// Parse the `AA_PROXY_CERT_CACHE_CAPACITY` env var or return the default.
fn parse_cert_cache_capacity() -> Result<usize, ProxyError> {
    match std::env::var("AA_PROXY_CERT_CACHE_CAPACITY") {
        Ok(val) => val
            .parse::<usize>()
            .map_err(|e| ProxyError::Config(format!("invalid AA_PROXY_CERT_CACHE_CAPACITY: {e}"))),
        Err(_) => Ok(1000),
    }
}

/// Parse the `AA_PROXY_LLM_ONLY` env var (default `true`).
fn parse_llm_only() -> bool {
    match std::env::var("AA_PROXY_LLM_ONLY") {
        Ok(val) => val != "0" && val.to_lowercase() != "false",
        Err(_) => true,
    }
}

/// Resolve the skip-upstream-TLS-verify flag, enforcing debug-only semantics.
///
/// AAASM-3131: this flag disables upstream certificate verification and is for
/// integration tests only. In a release (production) build it must be
/// unreachable — silently ignore the request and shout, so a stray env var in a
/// deployed binary cannot quietly turn the proxy into a MitM that trusts any
/// upstream certificate.
fn resolve_skip_upstream_tls_verify() -> bool {
    let requested = env_truthy("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY");
    if cfg!(debug_assertions) {
        requested
    } else {
        if requested {
            tracing::error!(
                "AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY is set but IGNORED in a release build — \
                 upstream TLS verification stays ENABLED. This flag is debug-only."
            );
        }
        false
    }
}

/// Parse the `AA_PROXY_CREDENTIAL_ACTION` env var or return the default.
fn parse_credential_action_env() -> Result<CredentialAction, ProxyError> {
    match std::env::var("AA_PROXY_CREDENTIAL_ACTION") {
        Ok(val) => parse_credential_action(&val),
        Err(_) => Ok(CredentialAction::default()),
    }
}

/// Read an env var as `Some(value)` when set and non-empty, otherwise `None`.
fn env_optional(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(val) if !val.is_empty() => Some(val),
        _ => None,
    }
}

/// Read an env var as an opt-in boolean: `true` only for an explicit `1`/`true`
/// (case-insensitive). Unset or any other value is `false` — these flags relax
/// a security default, so they must fail closed unless deliberately enabled.
fn env_truthy(name: &str) -> bool {
    match std::env::var(name) {
        Ok(val) => val == "1" || val.to_lowercase() == "true",
        Err(_) => false,
    }
}

/// Read an env var as a comma-separated list, trimming each entry and dropping
/// empties. An unset or empty var yields an empty `Vec`.
fn env_csv(name: &str) -> Vec<String> {
    match std::env::var(name) {
        Ok(val) if !val.is_empty() => val
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
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
        std::env::remove_var("AA_PROXY_MITM_HOSTS");
        std::env::remove_var("AA_PROXY_DENIED_HOSTS");
        std::env::remove_var("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY");
        std::env::remove_var("AA_PROXY_CREDENTIAL_ACTION");
        std::env::remove_var("AA_PROXY_GATEWAY_ENDPOINT");
        std::env::remove_var("AA_PROXY_MCP_FAIL_OPEN");
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
        // AAASM-3357: MCP enforcement defaults to fail-closed.
        assert!(!cfg.mcp_fail_open);
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
    fn from_env_reads_mitm_hosts_csv() {
        // AAASM-4126: operators extend the MitM + DLP surface beyond the built-in
        // LLM providers via a comma-separated AA_PROXY_MITM_HOSTS list.
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_MITM_HOSTS", "generativelanguage.googleapis.com, *.groq.com");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.mitm_hosts, vec!["generativelanguage.googleapis.com", "*.groq.com"]);
    }

    #[test]
    fn from_env_mitm_hosts_defaults_empty() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.mitm_hosts.is_empty());
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
    fn from_env_skip_upstream_tls_verify_honoured_in_debug_only() {
        // AAASM-3131: the request is honoured only in debug builds. In a
        // release build the env var is ignored and the flag stays `false`,
        // so a deployed production binary cannot disable upstream TLS
        // verification via a stray env var.
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY", "1");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.skip_upstream_tls_verify, cfg!(debug_assertions));
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

    #[test]
    fn from_env_gateway_endpoint_defaults_to_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.gateway_endpoint, None);
    }

    #[test]
    fn from_env_reads_gateway_endpoint() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_GATEWAY_ENDPOINT", "http://127.0.0.1:50051");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.gateway_endpoint.as_deref(), Some("http://127.0.0.1:50051"));
    }

    #[test]
    fn from_env_gateway_endpoint_empty_string_is_none() {
        // Empty AA_PROXY_GATEWAY_ENDPOINT must be treated as "unset" so
        // operators can disable MCP forwarding by clearing the variable
        // without unsetting it (matches the AA_PROXY_DENIED_HOSTS pattern).
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_GATEWAY_ENDPOINT", "");

        let cfg = ProxyConfig::from_env().unwrap();
        assert_eq!(cfg.gateway_endpoint, None);
    }

    #[test]
    fn from_env_mcp_fail_open_defaults_to_false() {
        // AAASM-3357: an unreachable gateway must fail CLOSED unless the
        // operator explicitly opts into fail-open.
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(!cfg.mcp_fail_open);
    }

    #[test]
    fn from_env_mcp_fail_open_reads_one() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_MCP_FAIL_OPEN", "1");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.mcp_fail_open);
    }

    #[test]
    fn from_env_mcp_fail_open_reads_true_case_insensitive() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_MCP_FAIL_OPEN", "TRUE");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.mcp_fail_open);
    }

    #[test]
    fn from_env_mcp_fail_open_other_value_is_false() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AA_PROXY_MCP_FAIL_OPEN", "no");

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(!cfg.mcp_fail_open);
    }
}
