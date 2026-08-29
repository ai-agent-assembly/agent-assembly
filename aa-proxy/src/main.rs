//! Binary entry point for the `aa-proxy` sidecar.
//!
//! This is intentionally minimal. All logic lives in the library crate.
//! `aa-runtime` spawns this binary via `tokio::process::Command::new("aa-proxy")`.

use clap::Parser;

/// Agent Assembly sidecar traffic-interception proxy.
///
/// `aa-proxy` is a MitM HTTPS proxy implementing E3, Protocol / Transport
/// Mediation (ADR 0033 §1): it refuses or redacts a request before it leaves
/// the machine (credential scanning, network egress allowlists, and MCP
/// `tools/call` adjudication against `aa-gateway`). It is normally spawned by
/// `aa-runtime`, but can be run standalone for testing and debugging.
///
/// All runtime configuration is read from environment variables. The most
/// common knobs are listed below; see the project documentation for the full
/// surface.
///
/// ENVIRONMENT VARIABLES:
///
///   AA_PROXY_ADDR                  TCP listen address (default 127.0.0.1:8899)
///   AA_CA_DIR                      CA cert/key directory (default ~/.aa/ca)
///   AA_PROXY_CERT_CACHE_CAPACITY   Max cached per-host certs (default 1000)
///   AA_PROXY_LLM_ONLY              Intercept LLM traffic only (default true)
///   AA_PROXY_DENIED_HOSTS          Comma-separated CONNECT block-list
///   AA_PROXY_NETWORK_ALLOWLIST     Comma-separated egress allowlist patterns
///   AA_PROXY_CREDENTIAL_ACTION     block | redact_only | alert_only
///   AA_PROXY_GATEWAY_ENDPOINT      aa-gateway PolicyService URL for MCP enforcement
///   AA_PROXY_MCP_FAIL_OPEN         1/true to fail OPEN when the gateway is
///                                  unreachable (default: fail CLOSED — deny)
///
/// RUST_LOG controls log verbosity via the standard `EnvFilter` syntax.
///
/// `long_version` names the commit this binary was compiled from, not only
/// its semver (AAASM-5984) — `aa-proxy` performs pre-egress credential
/// redaction (ADR 0030 row 7), so a redaction-evidence claim is a claim about
/// a specific build's interception logic, and a plain version string cannot
/// distinguish two `aa-proxy` binaries built from different commits at the
/// same version. Read from `aa_runtime::devint::provenance` rather than
/// derived here, so this binary and `aa-runtime`/`aa-cli` cannot disagree
/// about their own commit by construction — they're compiled in the same
/// `cargo build` invocation and share the constant.
#[derive(Parser, Debug)]
#[command(
    name = "aa-proxy",
    version,
    long_version = aa_runtime::devint::provenance::LONG_VERSION,
    verbatim_doc_comment
)]
struct Cli {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse CLI args. With no flags defined this still wires up `--help` and
    // `--version`, making the binary's existence and version discoverable.
    let _cli = Cli::parse();

    // rustls 0.23+ requires an explicit crypto provider at startup.
    // The `ring` feature is enabled in Cargo.toml; install it before any TLS operation.
    rustls::crypto::ring::default_provider().install_default().ok();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // AAASM-5984: state which build is about to perform interception/redaction
    // before anything else happens — the earliest point the log carries it.
    let identity = aa_runtime::devint::provenance::BuildIdentity::of_this_build();
    tracing::info!(
        build_sha = %identity.build_sha,
        build_identity_source = %identity.sha_source.as_str(),
        version = %identity.core_version,
        "aa-proxy starting",
    );

    let config = aa_proxy::ProxyConfig::from_env()?;

    // AAASM-5449: this used to drop the receiver on the spot. Every
    // `emit_policy_decision` / `emit_mcp_decision` / `intercept` call publishes
    // here and discards the send error, so in the standalone binary the whole
    // governance event stream went nowhere while reading, at every call site,
    // exactly like a working one. The channel itself is not removable — it is
    // how an embedder receives these events — so what was missing is a
    // subscriber for the case where there is no embedder.
    let (event_tx, event_rx) = tokio::sync::broadcast::channel(256);
    tokio::spawn(aa_proxy::pipeline_log::drain_pipeline_events(event_rx));

    aa_proxy::run(config, event_tx).await
}
