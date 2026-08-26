//! `aasm integrations install ... --trusted-upstream-proxy ... --enterprise-destination ...`
//! — writes the ADR 0036 trusted-config artifact `aa-proxy` reads via
//! `AA_PROXY_TRUSTED_CONFIG_PATH` (AAASM-5923).
//!
//! # Why this bypasses the plan/apply engine
//!
//! Every other `aasm integrations install` mutation (`WriteManagedSettings`,
//! `ConfigureProxy`, the `mitm-hosts.d` `ManageArtifact` step, …) is
//! *per-tool integration state*: it is planned, presented, confirmed, applied
//! through `session.client.apply`, and tracked with a receipt so drift and
//! removal can be reasoned about per tool. The trusted-upstream-proxy
//! artifact is not that — it is a single, tool-independent, operator-owned
//! piece of `aa-proxy` process configuration (D-C), the same conceptual
//! category as `${AASM_STATE_DIR:-~/.aasm}/identity` or
//! `${AASM_STATE_DIR:-~/.aasm}/aasm-uninstall`, both of which this crate
//! already writes directly rather than through the plan engine. Routing it
//! through `StepAction`/the DI-API session would require a new step variant
//! *and* a server-side executor for it — a change to the shared
//! multi-tool-integration engine for a single-artifact, single-consumer
//! (`aa-proxy`) config write, which is disproportionate to what this Story
//! asks for. Written directly, with the same ownership discipline
//! (`${AASM_STATE_DIR:-~/.aasm}/integrations/...`, matching every other
//! machine-global artifact this crate resolves) as the pattern it mirrors.
//!
//! `--scope` on the outer `install` command still applies to the tool
//! integration itself; this artifact does not vary by scope, because
//! `aa-proxy` is one process serving every tool on the machine, not one per
//! scope.

use std::path::PathBuf;

use aa_proxy::trusted_upstream::reject_wildcard_host;
use clap::Args;
use serde::Serialize;

/// Flags accepted alongside `aasm integrations install <tool>` for
/// configuring ADR 0036 enterprise proxy chaining. All optional — a plain
/// `install` with none of these touches nothing here.
#[derive(Args, Clone, Default)]
pub struct TrustedUpstreamArgs {
    /// The corporate/enterprise upstream proxy this aa-proxy instance may
    /// chain through, as `scheme://host:port` (e.g. `https://corp-proxy.example:3128`).
    /// Declaring this alone authorizes nothing — see `--enterprise-destination`.
    #[arg(long, value_name = "SCHEME://HOST:PORT")]
    pub trusted_upstream_proxy: Option<String>,

    /// A destination host:port authorized to use the trusted upstream proxy
    /// (D-A/D-B: exact match only, no wildcards). Repeatable.
    #[arg(long = "enterprise-destination", value_name = "HOST:PORT")]
    pub enterprise_destinations: Vec<String>,

    /// A declared destination host that should also be treated as an
    /// enterprise LLM endpoint (D2b), reaching the full MITM/redaction tier
    /// rather than the weaker non-LLM tier. Repeatable.
    #[arg(long = "llm-endpoint", value_name = "HOST")]
    pub llm_endpoints: Vec<String>,
}

impl TrustedUpstreamArgs {
    /// Whether any trusted-upstream-proxy flag was actually passed.
    pub fn is_empty(&self) -> bool {
        self.trusted_upstream_proxy.is_none()
            && self.enterprise_destinations.is_empty()
            && self.llm_endpoints.is_empty()
    }
}

/// Mirrors `aa-proxy::config`'s `RawEndpoint`/`RawTrustedConfig` JSON shape
/// exactly — this is the artifact `AA_PROXY_TRUSTED_CONFIG_PATH` names, so
/// the two must never drift independently. Kept as a small local mirror
/// rather than a shared type because `aa-proxy::trusted_upstream`'s raw
/// structs are private `serde::Deserialize`-only (parsing is aa-proxy's
/// concern); this side only ever serializes.
#[derive(Serialize)]
struct RawEndpoint {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct RawDestination {
    host: String,
    port: u16,
}

#[derive(Serialize, Default)]
struct RawTrustedConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    trusted_upstream_proxy: Option<RawEndpoint>,
    declared_enterprise_destinations: Vec<RawDestination>,
    declared_enterprise_llm_endpoints: Vec<String>,
}

/// Error writing the trusted-config artifact — every variant names the
/// offending value, since this is the operator's one chance to catch a typo
/// before `aa-proxy` fails closed on it at its own startup.
#[derive(Debug)]
pub enum TrustedUpstreamWriteError {
    MalformedEndpoint(String),
    UnsupportedScheme(String),
    MalformedDestination(String),
    Wildcard(String),
    Io(std::io::Error),
    NoStateDir,
}

impl std::fmt::Display for TrustedUpstreamWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedEndpoint(v) => write!(
                f,
                "--trusted-upstream-proxy {v:?} is not SCHEME://HOST:PORT (expected e.g. https://corp-proxy.example:3128)"
            ),
            Self::UnsupportedScheme(v) => write!(f, "--trusted-upstream-proxy scheme {v:?} must be \"http\" or \"https\""),
            Self::MalformedDestination(v) => write!(f, "{v:?} is not HOST:PORT"),
            Self::Wildcard(msg) => write!(f, "{msg}"),
            Self::Io(e) => write!(f, "cannot write trusted-config artifact: {e}"),
            Self::NoStateDir => write!(f, "cannot resolve AASM_STATE_DIR and no home directory is available"),
        }
    }
}

impl std::error::Error for TrustedUpstreamWriteError {}

/// `${AASM_STATE_DIR:-~/.aasm}/integrations/trusted-upstream-proxy.json` —
/// mirrors `aa-proxy::config`'s own `integration_state_dir()` resolution
/// exactly (same env var, same default, same `integrations` subdirectory)
/// so both sides of this artifact agree on where it lives without either
/// hardcoding the other's path.
pub fn trusted_upstream_config_path() -> Option<PathBuf> {
    let base = match std::env::var_os("AASM_STATE_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::home_dir()?.join(".aasm"),
    };
    Some(base.join("integrations").join("trusted-upstream-proxy.json"))
}

fn parse_endpoint(raw: &str) -> Result<RawEndpoint, TrustedUpstreamWriteError> {
    let (scheme, rest) = raw
        .split_once("://")
        .ok_or_else(|| TrustedUpstreamWriteError::MalformedEndpoint(raw.to_string()))?;
    if scheme != "http" && scheme != "https" {
        return Err(TrustedUpstreamWriteError::UnsupportedScheme(scheme.to_string()));
    }
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| TrustedUpstreamWriteError::MalformedEndpoint(raw.to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TrustedUpstreamWriteError::MalformedEndpoint(raw.to_string()))?;
    if host.is_empty() {
        return Err(TrustedUpstreamWriteError::MalformedEndpoint(raw.to_string()));
    }
    reject_wildcard_host(host).map_err(|e| TrustedUpstreamWriteError::Wildcard(e.to_string()))?;
    Ok(RawEndpoint {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port,
    })
}

fn parse_host_port(raw: &str) -> Result<RawDestination, TrustedUpstreamWriteError> {
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| TrustedUpstreamWriteError::MalformedDestination(raw.to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TrustedUpstreamWriteError::MalformedDestination(raw.to_string()))?;
    if host.is_empty() {
        return Err(TrustedUpstreamWriteError::MalformedDestination(raw.to_string()));
    }
    reject_wildcard_host(host).map_err(|e| TrustedUpstreamWriteError::Wildcard(e.to_string()))?;
    Ok(RawDestination {
        host: host.to_string(),
        port,
    })
}

/// Validate `args` and write (creating parent directories as needed) the
/// trusted-config artifact. Overwrites any existing artifact wholesale — this
/// command is the sole owner of this file, unlike `mitm-hosts.d`'s
/// many-small-files-per-integration union model, since v1 supports exactly
/// one trusted upstream proxy (D-A).
///
/// Every host is refused before any bytes are written (`reject_wildcard_host`,
/// D-B) — a positive control for this is `wildcard_entry_is_refused_before_any_write`.
pub fn write_trusted_upstream_config(args: &TrustedUpstreamArgs) -> Result<PathBuf, TrustedUpstreamWriteError> {
    let mut config = RawTrustedConfig::default();

    if let Some(raw) = &args.trusted_upstream_proxy {
        config.trusted_upstream_proxy = Some(parse_endpoint(raw)?);
    }
    for raw in &args.enterprise_destinations {
        config.declared_enterprise_destinations.push(parse_host_port(raw)?);
    }
    for host in &args.llm_endpoints {
        reject_wildcard_host(host).map_err(|e| TrustedUpstreamWriteError::Wildcard(e.to_string()))?;
        config.declared_enterprise_llm_endpoints.push(host.clone());
    }

    let path = trusted_upstream_config_path().ok_or(TrustedUpstreamWriteError::NoStateDir)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(TrustedUpstreamWriteError::Io)?;
    }
    let body =
        serde_json::to_string_pretty(&config).map_err(|e| TrustedUpstreamWriteError::Io(std::io::Error::other(e)))?;
    std::fs::write(&path, body).map_err(TrustedUpstreamWriteError::Io)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // AASM_STATE_DIR is a process-global env var; serialize the tests that
    // touch it so they cannot observe each other's value (the ambient-env
    // test-isolation pitfall this codebase's own ADR 0036 work already names
    // for `aa-proxy`'s equivalent tests).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_state_dir<T>(f: impl FnOnce(&std::path::Path) -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AASM_STATE_DIR", dir.path());
        let result = f(dir.path());
        std::env::remove_var("AASM_STATE_DIR");
        result
    }

    #[test]
    fn absent_flags_write_an_empty_but_valid_artifact() {
        with_state_dir(|state_dir| {
            let args = TrustedUpstreamArgs::default();
            assert!(args.is_empty());
            let path = write_trusted_upstream_config(&args).unwrap();
            assert_eq!(path, state_dir.join("integrations").join("trusted-upstream-proxy.json"));
            let body = std::fs::read_to_string(&path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["declared_enterprise_destinations"], serde_json::json!([]));
        });
    }

    #[test]
    fn a_full_declaration_round_trips_through_the_written_json() {
        with_state_dir(|_| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: Some("https://corp-proxy.example:3128".to_string()),
                enterprise_destinations: vec!["llm.corp.example:443".to_string()],
                llm_endpoints: vec!["llm.corp.example".to_string()],
            };
            let path = write_trusted_upstream_config(&args).unwrap();
            let body = std::fs::read_to_string(&path).unwrap();
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(parsed["trusted_upstream_proxy"]["host"], "corp-proxy.example");
            assert_eq!(parsed["trusted_upstream_proxy"]["port"], 3128);
            assert_eq!(parsed["trusted_upstream_proxy"]["scheme"], "https");
            assert_eq!(
                parsed["declared_enterprise_destinations"][0]["host"],
                "llm.corp.example"
            );
            assert_eq!(parsed["declared_enterprise_llm_endpoints"][0], "llm.corp.example");
        });
    }

    /// D-B positive control: a wildcarded destination is refused, and nothing
    /// is written — proves the refusal happens before any I/O, not merely
    /// that the resulting file would later be rejected by `aa-proxy` itself.
    #[test]
    fn wildcard_entry_is_refused_before_any_write() {
        with_state_dir(|state_dir| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: None,
                enterprise_destinations: vec!["*.corp.example:443".to_string()],
                llm_endpoints: vec![],
            };
            let err = write_trusted_upstream_config(&args).unwrap_err();
            assert!(matches!(err, TrustedUpstreamWriteError::Wildcard(_)), "{err}");
            assert!(
                !state_dir
                    .join("integrations")
                    .join("trusted-upstream-proxy.json")
                    .exists(),
                "a refused entry must not leave a partial artifact on disk"
            );
        });
    }

    #[test]
    fn a_wildcard_llm_endpoint_is_also_refused() {
        with_state_dir(|_| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: None,
                enterprise_destinations: vec![],
                llm_endpoints: vec!["*".to_string()],
            };
            assert!(write_trusted_upstream_config(&args).is_err());
        });
    }

    #[test]
    fn malformed_endpoint_missing_scheme_is_refused() {
        with_state_dir(|_| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: Some("corp-proxy.example:3128".to_string()),
                enterprise_destinations: vec![],
                llm_endpoints: vec![],
            };
            let err = write_trusted_upstream_config(&args).unwrap_err();
            assert!(matches!(err, TrustedUpstreamWriteError::MalformedEndpoint(_)), "{err}");
        });
    }

    #[test]
    fn unsupported_scheme_is_refused() {
        with_state_dir(|_| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: Some("ftp://corp-proxy.example:21".to_string()),
                enterprise_destinations: vec![],
                llm_endpoints: vec![],
            };
            let err = write_trusted_upstream_config(&args).unwrap_err();
            assert!(matches!(err, TrustedUpstreamWriteError::UnsupportedScheme(_)), "{err}");
        });
    }

    #[test]
    fn malformed_destination_missing_port_is_refused() {
        with_state_dir(|_| {
            let args = TrustedUpstreamArgs {
                trusted_upstream_proxy: None,
                enterprise_destinations: vec!["llm.corp.example".to_string()],
                llm_endpoints: vec![],
            };
            let err = write_trusted_upstream_config(&args).unwrap_err();
            assert!(
                matches!(err, TrustedUpstreamWriteError::MalformedDestination(_)),
                "{err}"
            );
        });
    }
}
