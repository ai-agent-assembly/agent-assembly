//! Sidecar traffic interception proxy for Agent Assembly.
//!
//! This crate implements E3, Protocol / Transport Mediation (ADR 0033 §1): a
//! sidecar proxy that sits alongside an AI agent process, intercepting outbound
//! HTTPS traffic and refusing or redacting a request before it leaves the
//! machine. The agent's own code does not change, but the proxy must be
//! installed, started, routed to via `HTTPS_PROXY` and have its CA trusted, and
//! `llm_only` defaults to `true`, so only the built-in LLM hosts are decrypted.
//!
//! ## Architecture
//!
//! ```text
//! TCP accept loop → CONNECT tunnel → TLS termination → intercept → forward
//! ```
//!
//! ## Entry points
//!
//! - **Binary** (`aa-proxy`): standalone sidecar spawned by `aa-runtime` via
//!   `tokio::process::Command::new("aa-proxy")`.
//! - **Library** (`aa_proxy::run()`): embeddable in-process for integration tests
//!   or constrained environments where subprocess spawning is unavailable.

pub mod audit_jsonl;
pub mod config;
pub mod credentials;
pub mod error;
pub mod hardening;
pub mod intercept;
pub mod mcp_enforce;
pub mod pipeline_log;
pub mod probe_adjudication;
pub mod proxy;
pub mod ssrf;
pub mod tls;
pub mod transmission_evidence;

pub use config::ProxyConfig;
pub use error::ProxyError;

/// Start the proxy with the given configuration.
///
/// Loads or creates the CA from `config.ca_dir`, installs it into the macOS
/// System Keychain if not already trusted, constructs a [`proxy::ProxyServer`],
/// and enters the TCP accept loop. Returns only on unrecoverable error.
pub async fn run(
    config: ProxyConfig,
    event_tx: tokio::sync::broadcast::Sender<aa_runtime::pipeline::PipelineEvent>,
) -> anyhow::Result<()> {
    // AAASM-3584: harden the process before any credential is loaded — mark it
    // non-dumpable so a forced crash cannot leave a core dump containing
    // plaintext provider keys, and so same-uid processes cannot ptrace it.
    // Best-effort: a failure is logged, not fatal.
    let _ = hardening::harden_process();

    // AAASM-3131: shout if upstream TLS verification is disabled. This is a
    // debug-only test affordance (the env var is ignored in release builds);
    // the banner makes an accidentally-enabled run impossible to miss in logs.
    if config.skip_upstream_tls_verify {
        tracing::warn!(
            "⚠️  AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY is ACTIVE — upstream TLS certificate \
             verification is DISABLED. This is for integration tests only and must NEVER \
             be used against real upstreams."
        );
    }

    let ca = tls::CaStore::load_or_create(&config.ca_dir).await?;

    #[cfg(target_os = "macos")]
    if !ca.is_installed()? {
        tracing::info!("CA not yet trusted — installing into macOS System Keychain");
        ca.install()?;
        tracing::info!("CA installed successfully");
    }

    // AAASM-5358: until now nothing in production ever constructed the JSONL
    // writer — this call site passed `None` unconditionally, so every finding,
    // every block and every redaction the proxy recorded was discarded when the
    // process exited. Persistence stays **opt-in** (an unset
    // `AA_PROXY_AUDIT_JSONL_PATH` reproduces exactly that behaviour), but it is
    // now reachable at all, which is what makes the execution evidence recorded
    // on each entry worth recording. A configured-but-unopenable path is an
    // error rather than a silent `None`: an operator who believes an audit trail
    // exists and has none is the failure mode this work stream is about.
    //
    // AAASM-5660: the retention bounds and the export target come from the same
    // place. A misconfigured retention period is an error rather than a silent
    // fallback to the default, for the same reason the path is: an operator who
    // believes they configured a ninety-day policy and quietly did not is in the
    // state this surface exists to prevent.
    let audit_rotation = config::audit_rotation_policy_from_env()?;
    let audit_export = config::audit_export_target_from_env();
    let audit_jsonl_tx = audit_jsonl::build_audit_sink(
        config::audit_jsonl_path_from_env().as_deref(),
        audit_rotation,
        audit_export.clone(),
    )
    .await?;
    if audit_jsonl_tx.is_some() {
        tracing::info!(
            max_segment_bytes = audit_rotation.max_segment_bytes,
            retained_segments = audit_rotation.retained_segments,
            retention_days = audit_rotation.max_age.map(|d| d.as_secs() / 86_400),
            export = ?audit_export.status(),
            "proxy audit JSONL persistence enabled via AA_PROXY_AUDIT_JSONL_PATH",
        );
        if matches!(audit_export, audit_jsonl::ExportTarget::LocalRingOnly) {
            // Said out loud at startup rather than left to be discovered when
            // the evidence is asked for: this ring is bounded, rotation deletes
            // earlier refusals permanently, and nothing replicates it off this
            // host. Durable retention that outlives the host is a SaaS
            // capability, not an unset flag.
            tracing::warn!(
                "proxy audit evidence is LOCAL-RING-ONLY: rotation permanently deletes earlier                  prevention records and nothing survives loss of this host — set                  AA_PROXY_AUDIT_EXPORT_DIR to hand sealed segments to a collector",
            );
        }
    }

    let server = proxy::ProxyServer::new_with_audit_sink(config, ca, event_tx, audit_jsonl_tx);
    server.run().await?;
    Ok(())
}
