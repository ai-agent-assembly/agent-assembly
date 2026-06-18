//! Binary entry point for the `aa-proxy` sidecar.
//!
//! This is intentionally minimal. All logic lives in the library crate.
//! `aa-runtime` spawns this binary via `tokio::process::Command::new("aa-proxy")`.

use clap::Parser;

/// Agent Assembly sidecar traffic-interception proxy.
///
/// `aa-proxy` is a MitM HTTPS proxy that enforces Layer 2 governance policy
/// (credential scanning, network egress allowlists, and MCP `tools/call`
/// enforcement against `aa-gateway`). It is normally spawned by `aa-runtime`,
/// but can be run standalone for testing and debugging.
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
#[derive(Parser, Debug)]
#[command(name = "aa-proxy", version, verbatim_doc_comment)]
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

    let config = aa_proxy::ProxyConfig::from_env()?;
    let (event_tx, _rx) = tokio::sync::broadcast::channel(256);
    aa_proxy::run(config, event_tx).await
}
