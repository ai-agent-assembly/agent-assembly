//! Trusted upstream proxy chaining for explicitly declared enterprise
//! destinations (ADR 0036).
//!
//! Two independent trust decisions live here, deliberately kept as two
//! separate types (D-A): [`TrustedUpstreamProxyEndpoint`] says *who* AASM may
//! hand traffic to as a second hop; [`DeclaredEnterpriseDestination`] says
//! *which* destination is authorized to use that hop. Neither fact alone
//! authorizes a chained route — see [`ChainedUpstreamConfig`] and the
//! `ChainedRoute` construction in `crate::proxy::mod` for the one place both
//! are combined.
//!
//! Both types, and the declared-enterprise-LLM-endpoint list that feeds
//! D2b/F3/N4's MITM-eligibility precondition, are constructed **only** by
//! [`load_and_validate`] from an explicit, operator-authored configuration
//! artifact (D-C) — never from ambient environment, agent/request content, or
//! a pre-resolved address crossing the `aa-cli`→`aa-proxy` boundary. See that
//! function's doc for the full provenance chain and the D5/D7/F3/N4/M4
//! validation this module enforces before a chained route can exist at all.

use std::net::SocketAddr;
use std::path::Path;

use crate::credentials::Secret;
use crate::error::ProxyError;
use crate::intercept::detect::{detect_api, LlmApiPattern};

/// Transport scheme of a [`TrustedUpstreamProxyEndpoint`]'s second hop.
///
/// `Https` is mandatory whenever [`ProxyAuth`] is configured (D5) — never
/// send `Proxy-Authorization` over a plaintext transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProxyScheme {
    Http,
    Https,
}

/// Basic credential for authenticating to a [`TrustedUpstreamProxyEndpoint`]
/// (D3/D5).
///
/// The password is held in a [`Secret`] — the same zeroizing, mlocked,
/// non-`Display` container `crate::credentials::CredentialStore` uses for
/// provider API keys — so this narrow, new credential class gets the same
/// hardening without a parallel mechanism. `Debug` is derived rather than
/// hand-written: [`Secret`]'s own `Debug` impl already redacts, so deriving
/// here cannot leak the password through this struct.
#[derive(Debug)]
pub struct ProxyAuth {
    pub username: String,
    pub password: Secret,
}

/// WHO AASM may hand traffic to as a second hop (D-A).
///
/// Trusting this endpoint does **not** by itself authorize any destination —
/// see [`DeclaredEnterpriseDestination`] and D-D's exact-match gate.
/// Constructed only by [`load_and_validate`]; `pinned_addr` is resolved by
/// `aa-proxy` itself, once, at startup (D-C) and is never re-resolved per
/// connection (forbidden design 3) or accepted pre-computed from the config
/// artifact or ambient environment (forbidden design 2).
#[derive(Debug)]
pub struct TrustedUpstreamProxyEndpoint {
    pub scheme: UpstreamProxyScheme,
    /// Exact hostname or literal IP, no wildcards (D-A).
    pub host: String,
    pub port: u16,
    /// Resolved by [`load_and_validate`] via this process's own DNS
    /// resolution — never a value that crossed the `aa-cli`→`aa-proxy`
    /// boundary pre-resolved (D-C).
    pub pinned_addr: SocketAddr,
    pub auth: Option<ProxyAuth>,
}

/// WHICH destination is authorized to use a [`TrustedUpstreamProxyEndpoint`]
/// as a second hop (D-A).
///
/// Exact host identity in v1 (D-B) — no wildcard/suffix grammar, unlike
/// `ProxyConfig::mitm_hosts`, because this is an SSRF-adjacent routing
/// decision, not merely a MITM-eligibility one. Declaring a proxy endpoint
/// does not imply a destination, and vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredEnterpriseDestination {
    pub host: String,
    pub port: u16,
}

/// The validated, DNS-pinned chaining configuration this process holds for
/// its whole lifetime, once [`load_and_validate`] succeeds.
///
/// `llm_endpoints` is D2b's distinct, narrower declaration — a host may be a
/// [`DeclaredEnterpriseDestination`] without being in this list (a chained,
/// non-LLM-tier destination is not possible in v1: F3/N4 requires every
/// declared destination's host to appear here or match `detect_api`, so in
/// practice this list is not optional for any non-built-in destination — see
/// [`load_and_validate`]'s eligibility check). It exists as its own field,
/// not folded into `destinations`, because it answers a different question
/// (MITM-branch tier) than `destinations` does (chained-route eligibility),
/// and a host can matter for one without being declared for chaining at all.
#[derive(Debug)]
pub struct ChainedUpstreamConfig {
    pub endpoint: TrustedUpstreamProxyEndpoint,
    pub destinations: Vec<DeclaredEnterpriseDestination>,
    pub llm_endpoints: Vec<String>,
}

/// One CONNECT target's authorization to use the chained path — the
/// combination of D-A's two facts, both required (D-D).
///
/// Borrows from the [`ChainedUpstreamConfig`] a `ProxyServer` holds for its
/// whole lifetime, so no clone of [`ProxyAuth`]'s [`Secret`] is ever needed to
/// thread this through a request's handler call chain.
pub struct ChainedRoute<'a> {
    pub dest: &'a DeclaredEnterpriseDestination,
    pub endpoint: &'a TrustedUpstreamProxyEndpoint,
}

/// Raw, not-yet-validated shape of the trusted configuration artifact
/// (D-C) — JSON so this module adds no new dependency (`serde_json` is
/// already a direct `aa-proxy` dependency).
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawScheme {
    Http,
    Https,
}

#[derive(serde::Deserialize)]
struct RawProxyAuth {
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct RawEndpoint {
    scheme: RawScheme,
    host: String,
    port: u16,
    #[serde(default)]
    auth: Option<RawProxyAuth>,
}

#[derive(serde::Deserialize)]
struct RawDestination {
    host: String,
    port: u16,
}

#[derive(serde::Deserialize, Default)]
struct RawTrustedConfig {
    #[serde(default)]
    trusted_upstream_proxy: Option<RawEndpoint>,
    #[serde(default)]
    declared_enterprise_destinations: Vec<RawDestination>,
    #[serde(default)]
    declared_enterprise_llm_endpoints: Vec<String>,
}

/// D-B: reject a wildcard metacharacter in a declared host, with a clear
/// error naming the offending value.
///
/// Applied to both `declared_enterprise_destinations` and
/// `declared_enterprise_llm_endpoints` hosts. `DeclaredEnterpriseDestination`
/// is documented exact-host-only (D-A/D-B) regardless of how eligibility is
/// implemented internally, so this check is unconditional — not merely a
/// workaround for one specific matcher's grammar (M4's original finding was
/// against a design that unioned into the wildcard-interpreting
/// `config.mitm_hosts`; this module's own eligibility check
/// (`chained_dest_is_mitm_eligible` in `crate::proxy`) does exact-string
/// comparison and would not itself be fooled by `*`, but D-B's policy is
/// "no wildcards, ever" independent of that implementation detail).
///
/// `pub` (AAASM-5923): `aasm integrations install`'s trusted-upstream-proxy
/// install flags call this directly to refuse a wildcarded entry before ever
/// writing the artifact, rather than duplicating the check — `aa-proxy`
/// itself can't be reused wholesale for this (`load_and_validate` needs a
/// live `bound_addr` for D7's loop check, which doesn't exist at install
/// time), but this one exact-string check has no such dependency.
pub fn reject_wildcard_host(host: &str) -> Result<(), ProxyError> {
    if host.contains('*') {
        return Err(ProxyError::Config(format!(
            "declared host {host:?} contains a wildcard metacharacter ('*'); \
             DeclaredEnterpriseDestination and declared_enterprise_llm_endpoints \
             entries must be an exact host, no wildcards (D-B)"
        )));
    }
    Ok(())
}

/// D7: whether `pinned_addr` would route back to this very `aa-proxy`
/// process's own listener, forming a chaining loop.
///
/// Two addresses are treated as the same listener when their ports match and
/// either side is loopback-class (`127.0.0.1`/`127.x.x.x`/`::1` are all
/// equivalent to each other for this purpose — a proxy bound to one loopback
/// form is reachable via every other loopback form on the same host), the
/// bound address is unspecified (`0.0.0.0`/`::`, which binds to every local
/// address including any loopback or LAN address `pinned_addr` might be), or
/// the two addresses are identical outright. This is deliberately scoped to
/// the single-hop case D7 names (a trusted endpoint that resolves straight
/// back to this process) — a multi-hop loop through an intermediate host is
/// out of reach of a purely local check and is instead bounded by the dial
/// timeout ([`crate::proxy`]'s `establish_trusted_proxy_tunnel`), not this
/// function.
fn points_back_at_self(pinned_addr: SocketAddr, bound_addr: SocketAddr) -> bool {
    if pinned_addr.port() != bound_addr.port() {
        return false;
    }
    pinned_addr.ip() == bound_addr.ip()
        || bound_addr.ip().is_unspecified()
        || (pinned_addr.ip().is_loopback() && bound_addr.ip().is_loopback())
}

/// Parse, validate, and DNS-pin the trusted configuration artifact at `path`
/// (D-C), enforcing every ADR 0036 startup precondition before a chained
/// route can exist:
///
/// * D-B — a declared host containing `*` is refused ([`reject_wildcard_host`]).
/// * F3/N4 — every [`DeclaredEnterpriseDestination`] must be MITM-eligible via
///   `detect_api` **or** an entry in `declared_enterprise_llm_endpoints` in
///   this *same* artifact — never via the ambient
///   `AA_PROXY_MITM_HOSTS`/`AASM_STATE_DIR`-derived `mitm_hosts` set, which is
///   a different, untrusted-for-this-purpose source.
/// * D5 — `auth` on the endpoint requires `scheme: https`; refused otherwise.
/// * D-C — the endpoint's `pinned_addr` is resolved by this process's own DNS
///   lookup, once, here; no pre-resolved address is ever accepted from the
///   artifact.
/// * D7 — a `pinned_addr` that is loopback-equivalent to `bound_addr` (this
///   `aa-proxy`'s own, real, post-bind listen address) is refused as a
///   self-referential loop. Callers must pass the address `TcpListener::bind`
///   actually returned, not the configured (possibly ephemeral `:0`)
///   `bind_addr` — see [`crate::proxy::ProxyServer::run`].
///
/// Returns `Ok(None)` when no `trusted_upstream_proxy` is configured — D-A's
/// "neither fact alone is sufficient" means declared destinations with no
/// endpoint can never produce a chained route, so the feature is simply
/// inert, not an error. Any validation failure is `Err` (fail-closed): an
/// operator who believes they configured working chaining and instead has a
/// misconfigured artifact must be told at startup, not silently left
/// unchained or, worse, left with a route the validation was supposed to have
/// caught.
pub async fn load_and_validate(
    path: &Path,
    bound_addr: SocketAddr,
) -> Result<Option<ChainedUpstreamConfig>, ProxyError> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        ProxyError::Config(format!(
            "cannot read AA_PROXY_TRUSTED_CONFIG_PATH artifact {}: {e}",
            path.display()
        ))
    })?;
    let raw: RawTrustedConfig = serde_json::from_str(&contents)
        .map_err(|e| ProxyError::Config(format!("malformed trusted config artifact {}: {e}", path.display())))?;

    for dest in &raw.declared_enterprise_destinations {
        reject_wildcard_host(&dest.host)?;
    }
    for host in &raw.declared_enterprise_llm_endpoints {
        reject_wildcard_host(host)?;
    }

    for dest in &raw.declared_enterprise_destinations {
        let eligible = detect_api(&dest.host) != LlmApiPattern::Unknown
            || raw
                .declared_enterprise_llm_endpoints
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&dest.host));
        if !eligible {
            return Err(ProxyError::Config(format!(
                "declared enterprise destination {:?}:{} is not MITM-eligible: it is not a \
                 built-in LLM host and is not listed in declared_enterprise_llm_endpoints in \
                 this same trusted config artifact (F3/D2b/N4) — declaring an enterprise \
                 destination and making it MITM-eligible are two operator actions, and this \
                 precondition can only be satisfied via the trusted artifact, never via the \
                 ambient AA_PROXY_MITM_HOSTS/AASM_STATE_DIR-derived mitm_hosts set",
                dest.host, dest.port
            )));
        }
    }

    let Some(raw_endpoint) = raw.trusted_upstream_proxy else {
        return Ok(None);
    };

    let scheme = match raw_endpoint.scheme {
        RawScheme::Http => UpstreamProxyScheme::Http,
        RawScheme::Https => UpstreamProxyScheme::Https,
    };
    let auth = match raw_endpoint.auth {
        Some(a) => {
            if scheme != UpstreamProxyScheme::Https {
                return Err(ProxyError::Config(
                    "trusted_upstream_proxy has auth configured but scheme is \"http\" — \
                     Proxy-Authorization must never be sent over a plaintext transport (D5); \
                     set scheme to \"https\""
                        .into(),
                ));
            }
            Some(ProxyAuth {
                username: a.username,
                password: Secret::new(a.password.into_bytes()),
            })
        }
        None => None,
    };

    let resolve_target = format!("{}:{}", raw_endpoint.host, raw_endpoint.port);
    let mut addrs = tokio::net::lookup_host(&resolve_target).await.map_err(|e| {
        ProxyError::Config(format!(
            "cannot resolve trusted_upstream_proxy host {:?}: {e}",
            raw_endpoint.host
        ))
    })?;
    let pinned_addr = addrs.next().ok_or_else(|| {
        ProxyError::Config(format!(
            "no addresses resolved for trusted_upstream_proxy host {:?}",
            raw_endpoint.host
        ))
    })?;

    if points_back_at_self(pinned_addr, bound_addr) {
        return Err(ProxyError::Config(format!(
            "trusted_upstream_proxy {:?} resolves to {pinned_addr}, which is this aa-proxy's \
             own bound listen address ({bound_addr}) — refusing a self-referential chained \
             route (D7 loop prevention)",
            raw_endpoint.host
        )));
    }

    let endpoint = TrustedUpstreamProxyEndpoint {
        scheme,
        host: raw_endpoint.host,
        port: raw_endpoint.port,
        pinned_addr,
        auth,
    };
    let destinations = raw
        .declared_enterprise_destinations
        .into_iter()
        .map(|d| DeclaredEnterpriseDestination {
            host: d.host,
            port: d.port,
        })
        .collect();

    Ok(Some(ChainedUpstreamConfig {
        endpoint,
        destinations,
        llm_endpoints: raw.declared_enterprise_llm_endpoints,
    }))
}

/// Minimal standard-alphabet Base64 encoder (RFC 4648, with `=` padding).
///
/// Written locally rather than adding a `base64` crate dependency: the
/// algorithm is small and fixed, and the only caller is the
/// `Proxy-Authorization: Basic` header this module's dial path builds (D5) —
/// one call site does not warrant a new dependency.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_artifact(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f
    }

    fn any_bound_addr() -> SocketAddr {
        "127.0.0.1:8899".parse().unwrap()
    }

    #[test]
    fn base64_encode_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[tokio::test]
    async fn absent_trusted_upstream_proxy_yields_none() {
        let f = write_artifact(r#"{"declared_enterprise_destinations":[]}"#);
        let result = load_and_validate(f.path(), any_bound_addr()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn unreadable_path_is_a_config_error() {
        let err = load_and_validate(Path::new("/nonexistent/aasm-trusted.json"), any_bound_addr())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("AA_PROXY_TRUSTED_CONFIG_PATH"));
    }

    #[tokio::test]
    async fn malformed_json_is_a_config_error() {
        let f = write_artifact("not json");
        let err = load_and_validate(f.path(), any_bound_addr()).await.unwrap_err();
        assert!(err.to_string().contains("malformed"));
    }

    /// D-B: a wildcard destination host is refused with a clear error naming
    /// the offending value.
    #[tokio::test]
    async fn wildcard_destination_host_is_refused() {
        let f = write_artifact(
            r#"{
                "declared_enterprise_destinations": [{"host": "*", "port": 443}]
            }"#,
        );
        let err = load_and_validate(f.path(), any_bound_addr()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("wildcard"), "error must name the problem: {msg}");
        assert!(msg.contains('*'), "error must name the offending value: {msg}");
    }

    /// D-B, suffix form: `*.corp.example` is exactly the wildcard grammar
    /// `mitm_hosts` accepts and `DeclaredEnterpriseDestination` must not.
    #[tokio::test]
    async fn suffix_wildcard_destination_host_is_refused() {
        let f = write_artifact(
            r#"{
                "declared_enterprise_destinations": [{"host": "*.corp.example", "port": 443}]
            }"#,
        );
        assert!(load_and_validate(f.path(), any_bound_addr()).await.is_err());
    }

    /// F3/N4: a declared destination that is neither a built-in LLM host nor
    /// listed in `declared_enterprise_llm_endpoints` must be refused — it
    /// would otherwise pass validation and then fall to `transparent_tunnel`
    /// with zero inspection at runtime.
    #[tokio::test]
    async fn non_mitm_eligible_destination_is_refused() {
        let f = write_artifact(
            r#"{
                "declared_enterprise_destinations": [{"host": "llm.corp.example", "port": 443}]
            }"#,
        );
        let err = load_and_validate(f.path(), any_bound_addr()).await.unwrap_err();
        assert!(err.to_string().contains("not MITM-eligible"));
    }

    /// N4: the ambient ordinary `mitm_hosts` mechanism does not exist inside
    /// this artifact at all — there is no field name here that could be
    /// confused with it, and the eligibility check above only ever consults
    /// `declared_enterprise_llm_endpoints` and `detect_api`. This test pins
    /// that a destination declared alongside an *unrelated* llm_endpoints
    /// entry still fails — the match must be exact, not "any llm_endpoints
    /// entry present at all".
    #[tokio::test]
    async fn an_unrelated_llm_endpoint_entry_does_not_satisfy_eligibility() {
        let f = write_artifact(
            r#"{
                "declared_enterprise_destinations": [{"host": "llm.corp.example", "port": 443}],
                "declared_enterprise_llm_endpoints": ["other.corp.example"]
            }"#,
        );
        assert!(load_and_validate(f.path(), any_bound_addr()).await.is_err());
    }

    /// A built-in `detect_api` host needs no `declared_enterprise_llm_endpoints`
    /// entry at all to satisfy F3.
    #[tokio::test]
    async fn a_built_in_llm_host_destination_needs_no_llm_endpoint_entry() {
        let f = write_artifact(
            r#"{
                "trusted_upstream_proxy": {"scheme": "https", "host": "127.0.0.1", "port": 3128},
                "declared_enterprise_destinations": [{"host": "api.anthropic.com", "port": 443}]
            }"#,
        );
        // The endpoint above resolves; only the eligibility precondition is
        // under test, so a passing result here just needs to not be the
        // "not MITM-eligible" error.
        let result = load_and_validate(f.path(), any_bound_addr()).await;
        if let Err(e) = &result {
            assert!(!e.to_string().contains("not MITM-eligible"), "{e}");
        }
    }

    /// D2b: a declared LLM-endpoint entry satisfies F3 for its own matching
    /// destination.
    #[tokio::test]
    async fn a_declared_llm_endpoint_satisfies_eligibility_for_its_own_destination() {
        let f = write_artifact(
            r#"{
                "declared_enterprise_destinations": [{"host": "llm.corp.example", "port": 443}],
                "declared_enterprise_llm_endpoints": ["llm.corp.example"]
            }"#,
        );
        let result = load_and_validate(f.path(), any_bound_addr()).await;
        if let Err(e) = &result {
            assert!(!e.to_string().contains("not MITM-eligible"), "{e}");
        }
    }

    /// D5: `scheme: http` with `auth` configured must be refused at
    /// validation, never silently sent cleartext.
    #[tokio::test]
    async fn http_scheme_with_auth_is_refused() {
        let f = write_artifact(
            r#"{
                "trusted_upstream_proxy": {
                    "scheme": "http",
                    "host": "127.0.0.1",
                    "port": 3128,
                    "auth": {"username": "svc", "password": "hunter2"}
                },
                "declared_enterprise_destinations": []
            }"#,
        );
        let err = load_and_validate(f.path(), any_bound_addr()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("plaintext"), "{msg}");
        // The password must never appear in the error text.
        assert!(!msg.contains("hunter2"), "credential leaked into error: {msg}");
    }

    /// D5, negative control: the same auth configured under `https` must NOT
    /// be refused for this reason (proves the check is scheme-specific, not
    /// "any auth is refused").
    #[tokio::test]
    async fn https_scheme_with_auth_is_not_refused_for_scheme_reasons() {
        let f = write_artifact(
            r#"{
                "trusted_upstream_proxy": {
                    "scheme": "https",
                    "host": "127.0.0.1",
                    "port": 3128,
                    "auth": {"username": "svc", "password": "hunter2"}
                },
                "declared_enterprise_destinations": []
            }"#,
        );
        let result = load_and_validate(f.path(), any_bound_addr()).await;
        if let Err(e) = &result {
            assert!(!e.to_string().contains("plaintext"), "{e}");
        }
    }

    /// D7: a trusted endpoint whose resolved address is this very proxy's own
    /// bound listen address must be refused as a loop.
    #[tokio::test]
    async fn self_pointing_endpoint_is_refused_as_a_loop() {
        let bound = "127.0.0.1:8899".parse().unwrap();
        let f = write_artifact(
            r#"{
                "trusted_upstream_proxy": {"scheme": "http", "host": "127.0.0.1", "port": 8899},
                "declared_enterprise_destinations": []
            }"#,
        );
        let err = load_and_validate(f.path(), bound).await.unwrap_err();
        assert!(err.to_string().contains("loop"), "{err}");
    }

    /// D7, negative control: a different port on the same loopback address is
    /// a genuinely different endpoint, not a loop.
    #[tokio::test]
    async fn a_different_port_on_loopback_is_not_a_loop() {
        let bound = "127.0.0.1:8899".parse().unwrap();
        let f = write_artifact(
            r#"{
                "trusted_upstream_proxy": {"scheme": "http", "host": "127.0.0.1", "port": 3128},
                "declared_enterprise_destinations": []
            }"#,
        );
        let result = load_and_validate(f.path(), bound).await;
        if let Err(e) = &result {
            assert!(!e.to_string().contains("loop"), "{e}");
        }
    }

    /// `points_back_at_self` directly: the equivalence classes D7 names.
    #[test]
    fn points_back_at_self_covers_loopback_equivalence_classes() {
        let bound: SocketAddr = "127.0.0.1:8899".parse().unwrap();
        assert!(points_back_at_self("127.9.9.9:8899".parse().unwrap(), bound));
        assert!(points_back_at_self("[::1]:8899".parse().unwrap(), bound));
        assert!(!points_back_at_self("127.0.0.1:9000".parse().unwrap(), bound));
        assert!(!points_back_at_self("203.0.113.1:8899".parse().unwrap(), bound));

        let unspecified: SocketAddr = "0.0.0.0:8899".parse().unwrap();
        assert!(points_back_at_self("203.0.113.1:8899".parse().unwrap(), unspecified));
    }
}
