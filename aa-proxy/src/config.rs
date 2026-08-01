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
    /// Comma-separated list from env var `AA_PROXY_MITM_HOSTS`, **unioned** with
    /// the host lists installed developer integrations wrote under
    /// `${AASM_STATE_DIR:-~/.aasm}/integrations/mitm-hosts.d/` — see
    /// [`integration_mitm_hosts`].
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
            mitm_hosts: union_mitm_hosts(env_csv("AA_PROXY_MITM_HOSTS"), integration_mitm_hosts()),
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

/// A protection a proxy listener must have before it may face anything other
/// than loopback, and whether `aa-proxy` can supply it today.
///
/// `available` is a compile-time constant rather than a config knob because it
/// describes what this crate *implements*, not what an operator asked for — an
/// operator cannot switch on a handshake that does not exist. Whoever
/// implements one flips its constant and [`check_bind_addr`] relaxes on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteProtection {
    /// Named verbatim in the refusal, so the operator is told which specific
    /// protection is absent rather than that "something" is.
    pub name: &'static str,
    /// Whether `aa-proxy` implements it. See [`REMOTE_PROTECTIONS`].
    pub available: bool,
}

/// What a network-reachable `aa-proxy` would need, and what it has.
///
/// Both are `false`, and that is a statement about the current code rather than
/// a placeholder:
///
/// * **Listener TLS** — [`crate::proxy::ProxyServer::run`] binds a bare
///   [`tokio::net::TcpListener`] and speaks plain HTTP `CONNECT` on it. The
///   `rustls` server configs in that module are the per-host MitM certificates
///   presented *inside* an established tunnel; none of them protects the
///   listener itself. Off-host traffic to it, including the `CONNECT` line and
///   any plain-HTTP body, crosses the network in the clear.
/// * **Client authentication** — nothing in the crate reads
///   `Proxy-Authorization` or answers `407`. Every connection that completes a
///   TCP handshake is served, so with a non-loopback bind the set of authorised
///   clients is exactly the set of hosts that can route to the port.
///
/// That second point is why reachability must never be read as trust here.
/// `aa-proxy` is a credential-disclosure surface on both sides of the tunnel:
/// it terminates client TLS with leaves issued from a CA whose root is
/// installed in this machine's trust store (`crate::tls::CaStore`), so it can
/// read every intercepted request; and it injects the operator's provider keys
/// into forwarded requests (`crate::credentials::CredentialStore`), so it will
/// spend those keys on behalf of whoever connects. An unauthenticated listener
/// on a routable address hands both of those to the network.
pub const REMOTE_PROTECTIONS: [RemoteProtection; 2] = [
    RemoteProtection {
        name: "TLS on the proxy listener",
        available: false,
    },
    RemoteProtection {
        name: "client authentication and authorization",
        available: false,
    },
];

/// The protections from [`REMOTE_PROTECTIONS`] that `aa-proxy` cannot supply.
///
/// Empty means a non-loopback listener could be protected; today it never is.
pub fn missing_remote_protections() -> Vec<&'static str> {
    REMOTE_PROTECTIONS
        .iter()
        .filter(|p| !p.available)
        .map(|p| p.name)
        .collect()
}

/// Why a requested proxy listen address was refused.
///
/// Both variants are refusals — they differ only in what the operator has to be
/// told, because "you did not ask for this" and "you asked, and it cannot be
/// done safely" are different problems with different next steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindRefusal {
    /// A non-loopback address, with no explicit opt-in.
    RemoteNotRequested(SocketAddr),
    /// The opt-in was given, but [`REMOTE_PROTECTIONS`] are missing.
    Unprotected {
        addr: SocketAddr,
        missing: Vec<&'static str>,
    },
}

impl std::fmt::Display for BindRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RemoteNotRequested(addr) => write!(
                f,
                "refusing to listen on {addr}: it is not a loopback address, so the proxy would \
                 accept connections from other hosts. aa-proxy reads intercepted traffic under a \
                 CA this machine trusts and injects the operator's provider credentials into \
                 forwarded requests, so anything that can reach the listener can do both. Listen \
                 on a loopback address (for example 127.0.0.1:{}), or pass --allow-remote-clients \
                 to state the intent explicitly.",
                addr.port(),
            ),
            Self::Unprotected { addr, missing } => write!(
                f,
                "refusing to listen on {addr}: --allow-remote-clients was given, but a proxy \
                 reachable from other hosts also requires protection aa-proxy does not implement: \
                 {}. Being reachable is not being trusted — without those, every host that can \
                 route to {addr} is an authorized client of an interception endpoint that holds \
                 CA material and provider credentials. Listen on a loopback address instead.",
                missing.join(", "),
            ),
        }
    }
}

/// Whether the proxy may listen on `addr`.
///
/// Loopback is always allowed and is the default. Anything else is refused
/// unless the operator opted in **and** every [`REMOTE_PROTECTIONS`] entry is
/// available — which is why the opt-in currently refuses too. A flag whose
/// preconditions cannot be met is honest; a flag that exposes an
/// unauthenticated interception endpoint is not.
///
/// The loopback test is the same one `aasm run` applies before it will route a
/// governed tool at a recorded proxy endpoint, so the two commands cannot
/// disagree about which endpoints are usable (AAASM-5348).
pub fn check_bind_addr(addr: SocketAddr, allow_remote_clients: bool) -> Result<(), BindRefusal> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if !allow_remote_clients {
        return Err(BindRefusal::RemoteNotRequested(addr));
    }
    let missing = missing_remote_protections();
    if missing.is_empty() {
        return Ok(());
    }
    Err(BindRefusal::Unprotected { addr, missing })
}

/// Directory, under the Agent Assembly state root, holding one MitM host list
/// per installed developer integration.
const MITM_HOSTS_DIR: &str = "mitm-hosts.d";

/// Hosts the installed developer integrations asked to have inspected.
///
/// AAASM-5276 condition C5: one headless `claude -p` run produced four upstream
/// requests, only two of which were `/v1/messages` — an MCP-registry GET and a
/// 130 KB `POST /api/event_logging/v2/batch` went out alongside them. Under the
/// `llm_only` default those side channels are transparent-tunnelled and never
/// scanned.
///
/// The fix has to be **per integration**, not global: setting `llm_only = false`
/// would bring every host on the machine under MitM, which is a far larger
/// change than "inspect the tool you just installed". Each integration's install
/// writes one file here and its removal deletes it, so the proxy's interception
/// set follows exactly what is installed. The proxy still MitMs nothing else.
///
/// A directory that does not exist, a file that cannot be read, and a blank or
/// `#`-commented line all contribute nothing — this widens the DLP surface, so
/// failing to read it can only ever narrow the result, never open a host up.
fn integration_mitm_hosts() -> Vec<String> {
    let Some(dir) = integration_state_dir().map(|d| d.join(MITM_HOSTS_DIR)) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for entry in entries.flatten() {
        let Ok(body) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            hosts.push(line.to_string());
        }
    }
    hosts
}

/// `${AASM_STATE_DIR:-~/.aasm}/integrations`, the same root the receipt store
/// uses, so an integration's artifacts and its receipt live and die together.
fn integration_state_dir() -> Option<PathBuf> {
    let base = match std::env::var_os("AASM_STATE_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::home_dir()?.join(".aasm"),
    };
    Some(base.join("integrations"))
}

/// Merge the operator's list with the integrations', preserving first-seen order
/// and dropping duplicates.
fn union_mitm_hosts(operator: Vec<String>, integrations: Vec<String>) -> Vec<String> {
    let mut merged = operator;
    for host in integrations {
        if !merged.iter().any(|existing| existing.eq_ignore_ascii_case(&host)) {
            merged.push(host);
        }
    }
    merged
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
        std::env::remove_var("AASM_STATE_DIR");
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address literal")
    }

    /// The default, and the address an operator types when they mean "this
    /// machine only". Both must keep working — the guard exists to stop an
    /// exposure, not to stop the proxy.
    #[test]
    fn a_loopback_listen_address_is_accepted() {
        for literal in ["127.0.0.1:8899", "127.0.0.1:0", "[::1]:8899", "127.9.9.9:8899"] {
            assert_eq!(
                check_bind_addr(addr(literal), false),
                Ok(()),
                "{literal} is loopback and must be accepted without any opt-in"
            );
        }
    }

    /// AAASM-5348. Anything reachable off-host is refused by default, and the
    /// operator is told which fact about the address disqualified it and what
    /// the alternatives are — a bare "invalid address" would leave them
    /// guessing.
    #[test]
    fn a_non_loopback_listen_address_is_refused_without_the_opt_in() {
        for literal in ["0.0.0.0:8899", "192.168.1.7:8899", "[::]:8899"] {
            let refusal = check_bind_addr(addr(literal), false).expect_err(&format!(
                "{literal} is reachable from other hosts and must not be accepted by default"
            ));
            assert_eq!(refusal, BindRefusal::RemoteNotRequested(addr(literal)));

            let msg = refusal.to_string();
            assert!(msg.contains(literal), "the refusal must name the address, got: {msg}");
            assert!(
                msg.contains("not a loopback address"),
                "the refusal must say what disqualified the address, got: {msg}"
            );
            assert!(
                msg.contains("--allow-remote-clients"),
                "the refusal must name the option that states the intent, got: {msg}"
            );
        }
    }

    /// The heart of AAASM-5348: asking is not enough. `aa-proxy` can neither
    /// encrypt its listener nor tell one client from another, so with the
    /// opt-in given the answer is still no — and the diagnostic names both
    /// absent protections rather than reporting a generic failure.
    #[test]
    fn the_opt_in_alone_does_not_make_a_remote_listen_address_acceptable() {
        let requested = addr("0.0.0.0:8899");
        let refusal = check_bind_addr(requested, true)
            .expect_err("--allow-remote-clients must not by itself authorize an unprotected listener");

        let BindRefusal::Unprotected { addr: refused, missing } = &refusal else {
            panic!("expected an Unprotected refusal naming what is absent, got: {refusal:?}");
        };
        assert_eq!(*refused, requested);
        assert_eq!(
            missing,
            &["TLS on the proxy listener", "client authentication and authorization"]
        );

        let msg = refusal.to_string();
        assert!(
            msg.contains("TLS on the proxy listener"),
            "the refusal must name the missing transport protection, got: {msg}"
        );
        assert!(
            msg.contains("client authentication and authorization"),
            "the refusal must name the missing client-identity protection, got: {msg}"
        );
        assert!(
            msg.contains("Being reachable is not being trusted"),
            "the refusal must say why reaching the port is not authorization, got: {msg}"
        );
    }

    /// The refusal above is derived from the crate's real capabilities, not
    /// hardcoded — so this records that today it supplies neither, and turns
    /// into a failure the moment someone implements one without revisiting
    /// [`check_bind_addr`].
    #[test]
    fn neither_remote_protection_is_implemented_today() {
        assert_eq!(
            missing_remote_protections(),
            vec!["TLS on the proxy listener", "client authentication and authorization"],
            "both protections are absent; a change here must be matched by one in the listener"
        );
    }

    /// AAASM-5276 condition C5. An installed integration extends the DLP
    /// surface to the hosts it named, and `llm_only` stays on — the alternative
    /// (turning it off) would MitM every host on the machine.
    #[test]
    fn an_installed_integration_extends_the_mitm_set_without_disabling_llm_only() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();

        let dir = tempfile::tempdir().unwrap();
        let hosts_dir = dir.path().join("integrations").join(MITM_HOSTS_DIR);
        std::fs::create_dir_all(&hosts_dir).unwrap();
        std::fs::write(
            hosts_dir.join("claude-code--user.hosts"),
            "# written by an install\napi.anthropic.com\n\n*.anthropic.com\n",
        )
        .unwrap();
        std::env::set_var("AASM_STATE_DIR", dir.path());

        let cfg = ProxyConfig::from_env().unwrap();
        assert!(cfg.llm_only, "extending the set must not disable llm_only");
        assert_eq!(cfg.mitm_hosts, vec!["api.anthropic.com", "*.anthropic.com"]);

        // Removing the integration removes its hosts from the proxy's set.
        std::fs::remove_file(hosts_dir.join("claude-code--user.hosts")).unwrap();
        assert!(ProxyConfig::from_env().unwrap().mitm_hosts.is_empty());
        std::env::remove_var("AASM_STATE_DIR");
    }

    #[test]
    fn an_absent_state_directory_contributes_no_hosts() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_env_vars();
        std::env::set_var("AASM_STATE_DIR", "/nonexistent/aasm-state-for-tests");
        assert!(ProxyConfig::from_env().unwrap().mitm_hosts.is_empty());
        std::env::remove_var("AASM_STATE_DIR");
    }

    #[test]
    fn the_operator_list_and_the_integration_list_merge_without_duplicates() {
        assert_eq!(
            union_mitm_hosts(
                vec!["api.groq.com".to_string(), "API.ANTHROPIC.COM".to_string()],
                vec!["api.anthropic.com".to_string(), "*.anthropic.com".to_string()],
            ),
            vec!["api.groq.com", "API.ANTHROPIC.COM", "*.anthropic.com"],
            "a host the operator already listed must not be added twice"
        );
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
