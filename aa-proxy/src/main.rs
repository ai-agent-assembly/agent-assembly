//! Binary entry point for the `aa-proxy` sidecar.
//!
//! This is intentionally minimal. All logic lives in the library crate.
//! `aa-runtime` spawns this binary via `tokio::process::Command::new("aa-proxy")`.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
