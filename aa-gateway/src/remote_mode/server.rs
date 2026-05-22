//! Remote Control-Plane Mode listener bootstrap.
//!
//! Owns `start_remote` and the `router` builder. See AAASM-1709 for the
//! design rationale; the deeper architectural context lives in
//! AAASM-1577 / E17 S-C.

use std::sync::Arc;
use std::time::Duration;

use aa_core::config::RemoteModeConfig;
use axum::{routing::get, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;

use super::error::GatewayError;
use super::tls::{self, TlsValidation};
use crate::routes::healthz::{healthz, HealthzState};
use crate::storage::{open_postgres_backend, PostgresConfig, StorageBackend};

/// Build the remote-mode Axum router.
///
/// Mounts only `/healthz` today via [`crate::routes::healthz::healthz`].
/// Later sub-tasks (cross-mode API routes wired by AAASM-1731, dashboard
/// SPA opt-in in AAASM-1580) merge into this same router.
///
/// The injected `HealthzState::new("remote", "memory")` layer supplies
/// the labels the shared `/healthz` handler reads, so the response body
/// carries `mode: "remote"` and `storage: "memory"`. The `"memory"`
/// label is a stub until E18 S-C (AAASM-1719 PostgreSQL backend) wires
/// the real storage label through `RemoteModeConfig`.
pub fn router() -> Router {
    let state = HealthzState::new("remote", "memory");
    Router::new().route("/healthz", get(healthz)).layer(Extension(state))
}

/// Print the operator-facing startup banner via `tracing::info!`.
///
/// Five lines — mode, listen addr, scheme (http / https), storage label,
/// version — sized to fit a typical 80-column terminal so the boot log
/// is scannable.
fn log_startup_banner(cfg: &RemoteModeConfig) {
    let scheme = if cfg.tls.is_some() { "https" } else { "http" };
    tracing::info!(
        scheme,
        addr = %cfg.listen_addr,
        storage = "memory",
        version = env!("CARGO_PKG_VERSION"),
        "Agent Assembly [remote mode] starting on {scheme}://{}",
        cfg.listen_addr
    );
}

/// How long graceful shutdown waits for in-flight requests to drain
/// before forcefully closing the listener. Matches the 30-second
/// budget the Story AC documents.
const GRACEFUL_SHUTDOWN_BUDGET: Duration = Duration::from_secs(30);

/// Bind the remote-mode listener and serve until SIGTERM / SIGINT.
///
/// Top-level entrypoint for `aasm-gateway --mode remote`. Creates an
/// internal [`Handle`], spawns a signal listener that drives graceful
/// shutdown on SIGTERM (Unix) or Ctrl+C, then defers to
/// [`start_remote_with_handle`] for the actual bind + serve loop.
///
/// Returns `Ok(())` after the server has drained, or `Err(GatewayError)`
/// for any pre-flight / bind / serve / signal-installation failure.
pub async fn start_remote(cfg: &RemoteModeConfig) -> Result<(), GatewayError> {
    let handle = Handle::new();
    let signal_handle = handle.clone();

    tokio::spawn(async move {
        if let Err(err) = wait_for_shutdown_signal().await {
            tracing::error!(error = %err, "shutdown signal listener failed");
            signal_handle.shutdown();
            return;
        }
        tracing::info!(
            secs = GRACEFUL_SHUTDOWN_BUDGET.as_secs(),
            "shutdown signal received — draining in-flight requests"
        );
        signal_handle.graceful_shutdown(Some(GRACEFUL_SHUTDOWN_BUDGET));
    });

    start_remote_with_handle(cfg, handle).await
}

/// Wait for SIGTERM (Unix) or SIGINT (Ctrl+C, all platforms), whichever
/// arrives first. Returns `Err(GatewayError::Signal)` only when the
/// underlying signal handler could not be installed.
async fn wait_for_shutdown_signal() -> Result<(), GatewayError> {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(GatewayError::Signal)?;
        tokio::select! {
            res = ctrl_c => res.map_err(GatewayError::Signal),
            _ = sigterm.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.map_err(GatewayError::Signal)
    }
}

/// Bind the remote-mode listener and serve until `handle` triggers
/// shutdown. Plain-HTTP path — TLS is added in a follow-up commit.
///
/// Returns `Ok(())` after the server has drained on graceful shutdown,
/// or `Err(GatewayError)` if bind / serve failed.
///
/// `handle` is the caller's lever for shutdown: tests build their own
/// and call `handle.graceful_shutdown(Some(_))` to exit cleanly; the
/// production [`start_remote`] entrypoint wires the handle to a
/// SIGTERM / SIGINT listener.
pub async fn start_remote_with_handle(cfg: &RemoteModeConfig, handle: Handle) -> Result<(), GatewayError> {
    log_startup_banner(cfg);

    // Epic 18 Story S-I.1 (AAASM-1859): when a database URL is
    // configured, open the PostgreSQL backend and apply pending
    // migrations before binding the listener. The handle stays in
    // scope for the lifetime of the serve loop so the connection
    // pool is not dropped mid-request; future Sub-tasks of the same
    // Story pass it through AppState to handlers.
    //
    // When `database_url` is `None`, remote mode keeps its pre-S-I.1
    // behaviour: no backend is opened, healthz reports `storage: memory`.
    let _storage: Option<Arc<dyn StorageBackend>> = if let Some(url) = cfg.database_url.as_ref() {
        let pg = PostgresConfig {
            database_url: Some(url.clone()),
            ..PostgresConfig::default()
        };
        Some(open_postgres_backend(&pg).await.map_err(GatewayError::Storage)?)
    } else {
        None
    };

    let app = router().into_make_service();

    if let Some(tls_cfg) = &cfg.tls {
        // Pre-flight cert + key (existence, readability, PEM parse, expiry).
        match tls::validate(tls_cfg)? {
            TlsValidation::Ok => {}
            TlsValidation::ExpiringSoon { days_until_expiry } => {
                tracing::warn!(
                    days_until_expiry,
                    "⚠ TLS cert expires within 30 days — rotate before notAfter"
                );
            }
            TlsValidation::Expired { expired_days_ago } => {
                tracing::error!(
                    expired_days_ago,
                    "TLS cert has already expired — new TLS clients will reject the chain"
                );
            }
        }

        let rustls_cfg = RustlsConfig::from_pem_file(&tls_cfg.cert_file, &tls_cfg.key_file)
            .await
            .map_err(GatewayError::TlsLoad)?;

        axum_server::bind_rustls(cfg.listen_addr, rustls_cfg)
            .handle(handle)
            .serve(app)
            .await
            .map_err(GatewayError::Serve)
    } else {
        tracing::warn!("⚠ TLS not configured — running over plain HTTP");

        axum_server::bind(cfg.listen_addr)
            .handle(handle)
            .serve(app)
            .await
            .map_err(GatewayError::Serve)
    }
}
