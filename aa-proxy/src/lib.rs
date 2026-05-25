//! Sidecar traffic interception proxy for Agent Assembly.
//!
//! This crate implements the Layer 2 interception model: a sidecar proxy that
//! sits alongside each AI agent process, intercepting outbound HTTPS traffic
//! and enforcing governance policies before forwarding requests.
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
pub mod error;
pub mod intercept;
pub mod mcp_enforce;
pub mod proxy;
pub mod tls;
pub mod wasm_dispatch;

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
    let ca = tls::CaStore::load_or_create(&config.ca_dir).await?;

    #[cfg(target_os = "macos")]
    if !ca.is_installed()? {
        tracing::info!("CA not yet trusted — installing into macOS System Keychain");
        ca.install()?;
        tracing::info!("CA installed successfully");
    }

    let server = proxy::ProxyServer::new(config, ca, event_tx);
    server.run().await?;
    Ok(())
}
