//! AAASM-1112 — an out-of-process `aa-proxy` whose upstream dial is redirected
//! to a loopback mock provider.
//!
//! # Why this exists
//!
//! `cli_run_claude_governed_launch::run_claude_launches_the_real_binary_and_the_secret_is_redacted`
//! has to measure a governed launch end to end: the real `claude` binary,
//! launched by the real `aasm run`, its traffic intercepted, and the synthetic
//! secret redacted before it reaches the provider. That needs two things at
//! once, and no shipped artefact provides both:
//!
//! 1. **A proxy `aasm run` will vouch for.** Since AAASM-5323 the launcher
//!    refuses unless it can resolve a state record written by `aasm proxy
//!    start` naming a *live process* whose executable is `aa-proxy`
//!    (`aa-cli/src/commands/proxy/trust.rs`). An in-process
//!    [`aa_proxy::proxy::ProxyServer`] — what
//!    `conformance_support::RestartableProxy` runs — can never satisfy that: it
//!    is not a process.
//! 2. **An upstream the test can read.** The shipped `aa-proxy` binary dials the
//!    real `api.anthropic.com`. [`aa_proxy::ProxyConfig::from_env`] leaves
//!    `upstream_override` at `None` and there is deliberately no environment
//!    variable for it, and the SSRF guard
//!    (`allow_private_connect_targets`, also unreachable from the environment)
//!    refuses every loopback dial. Both are correct production decisions and
//!    neither is being argued with here.
//!
//! So this example is the shipped proxy *server* — the same
//! [`aa_proxy::proxy::ProxyServer`], built from the same
//! [`aa_proxy::ProxyConfig::from_env`] — in a process the trust check can
//! identify, with exactly one field overridden: where the upstream dial lands.
//! That is the identical knob `conformance_support::RestartableProxy` and
//! `spike_support::proxy_harness::ProxyHarness` already turn in-process, and it
//! is documented on the field itself as the integration-test path.
//!
//! # What is *not* faked
//!
//! MitM certificate issuance, TLS termination, host classification, the
//! credential scanner and the redaction rewrite are all the production code
//! path, reached through the production config loader. The only test-shaped
//! facts are the upstream address (here) and the two environment variables the
//! caller sets on top of it (`AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY`, because the
//! mock's leaf is signed by the throwaway CA rather than a public one, and
//! `AA_PROXY_LLM_ONLY=false`, mirroring the conformance harness so a secret
//! leaking down a side channel is in the capture set too).
//!
//! # What the caller must understand about the name
//!
//! The test copies the built artefact to a file literally named `aa-proxy` so
//! `aasm proxy start` resolves it and the trust check's identity constraint
//! holds. That constraint is therefore **not** under test in that scenario — it
//! is measured against the genuine binary by `cli_run_trusted_proxy.rs`, and
//! nothing here weakens it. The scenario using this binary is measuring a
//! different join: whether the launch environment `aasm run` produces actually
//! reaches the tool.
//!
//! # Safety
//!
//! [`aa_proxy::run`] is deliberately **not** called. It installs the CA into the
//! macOS System Keychain, which every fixture in this crate is forbidden from
//! doing. The server is constructed directly instead, so the certificate
//! authority never leaves the caller's temp directory.

use std::net::SocketAddr;

/// Environment variable naming the loopback address every upstream dial is
/// redirected to. Required: a run without it would silently dial the real
/// provider, which is the outcome this binary exists to prevent.
const UPSTREAM_ENV: &str = "AA_TEST_PROXY_UPSTREAM";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // AAASM-5902: without this the binary emitted no logs at all, which blocks
    // any test that needs to correlate this process's behaviour (e.g. redaction
    // decisions) against captured stdout/stderr, and blocks a `LogLine`
    // readiness condition on this binary entirely.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls 0.23 refuses to pick a provider implicitly when more than one
    // resolves, as it does in this workspace.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let raw = std::env::var(UPSTREAM_ENV)
        .map_err(|_| anyhow::anyhow!("{UPSTREAM_ENV} is not set; refusing to start with a real upstream"))?;
    let upstream: SocketAddr = raw
        .parse()
        .map_err(|e| anyhow::anyhow!("{UPSTREAM_ENV}={raw:?} is not a socket address: {e}"))?;

    let mut config = aa_proxy::ProxyConfig::from_env()?;
    config.upstream_override = Some(upstream);

    let ca = aa_proxy::tls::CaStore::load_or_create(&config.ca_dir).await?;
    // Held for the process lifetime: the pipeline's broadcast sends fail when
    // no receiver exists, and a proxy whose event sends fail is not the proxy
    // production runs.
    let (event_tx, _event_rx) = tokio::sync::broadcast::channel(256);
    let server = aa_proxy::proxy::ProxyServer::new(config, ca, event_tx);
    server.run().await?;
    Ok(())
}
