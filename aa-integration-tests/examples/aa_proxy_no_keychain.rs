//! AAASM-5868 — a per-launch `aa-proxy` that never touches the macOS System
//! Keychain.
//!
//! # Why this exists
//!
//! `aa_proxy::run()` (the real binary's entry point) unconditionally installs
//! the CA into the macOS System Keychain on first use of a not-yet-trusted
//! `ca_dir` (`aa-proxy/src/lib.rs`, `#[cfg(target_os = "macos")]` block).
//! That call blocks on a GUI authentication dialog this benchmark cannot
//! click through, and every fixture in this crate is already forbidden from
//! doing it (see `proxy_with_mock_upstream.rs`'s own module doc, the
//! precedent this file follows). So this is the identical minus-keychain
//! trick applied to the *dedicated per-launch* path instead of the
//! standalone-proxy path that example covers: `ProxyConfig::from_env()` is
//! still the production loader (so `ready_file`/`parent_pid`/`gateway_endpoint`
//! wiring — everything `ProxyGuard` (`aa-cli/src/commands/proxy/guard.rs`)
//! configures via env vars — is exercised exactly as production sets it), and
//! `proxy::ProxyServer` is still the real MitM engine. Only the two-line
//! keychain-install block from `aa_proxy::run()` is omitted.
//!
//! No upstream override: unlike `proxy_with_mock_upstream.rs`, this binary
//! does not need one. `ProxyGuard::spawn` sets `AA_PROXY_LLM_ONLY=false` for
//! every per-launch proxy it spawns (`aa-cli/src/commands/proxy/guard.rs`),
//! so `llm_only`'s `true` default never applies here — the benchmark's
//! active-forwarding CONNECT is genuinely MitM'd (a leaf cert is issued from
//! the launch's own throwaway CA, decrypted, forwarded, re-encrypted), not
//! tunnelled byte-for-byte. That MitM issuance is exactly why the keychain
//! step matters in the first place: a real client would need to trust this
//! CA to complete that handshake without a certificate error, but nothing
//! in this benchmark's own `curl --cacert` call depends on OS-level Keychain
//! trust, so omitting the keychain-install step here changes nothing this
//! benchmark measures.
//!
//! Copied to a file literally named `aa-proxy` and put first on `PATH` by the
//! harness, the same way `TrustedProxy::start_intercepting` does — see that
//! function's doc for why the name match matters and what it does not prove.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // rustls 0.23+ requires an explicit crypto provider before any TLS
    // operation; the real binary's `main.rs` does the same.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = aa_proxy::ProxyConfig::from_env()?;

    let (event_tx, event_rx) = tokio::sync::broadcast::channel(256);
    tokio::spawn(aa_proxy::pipeline_log::drain_pipeline_events(event_rx));

    // From here down: `aa_proxy::run()`'s own body, minus the
    // `#[cfg(target_os = "macos")] ca.install()` block — see the module doc.
    let _ = aa_proxy::hardening::harden_process();

    let ca = aa_proxy::tls::CaStore::load_or_create(&config.ca_dir).await?;

    let audit_rotation = aa_proxy::config::audit_rotation_policy_from_env()?;
    let audit_export = aa_proxy::config::audit_export_target_from_env();
    let audit_jsonl_tx = aa_proxy::audit_jsonl::build_audit_sink(
        aa_proxy::config::audit_jsonl_path_from_env().as_deref(),
        audit_rotation,
        audit_export,
    )
    .await?;

    let server = aa_proxy::proxy::ProxyServer::new_with_audit_sink(config, ca, event_tx, audit_jsonl_tx);
    server.run().await?;
    Ok(())
}
