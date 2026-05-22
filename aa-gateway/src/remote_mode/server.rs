//! Remote Control-Plane Mode listener bootstrap.
//!
//! Owns `start_remote` and the `router` builder. See AAASM-1709 for the
//! design rationale; the deeper architectural context lives in
//! AAASM-1577 / E17 S-C.

use aa_core::config::RemoteModeConfig;
use axum::{routing::get, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;

use super::error::GatewayError;
use super::tls::{self, TlsValidation};
use crate::routes::healthz::{healthz, HealthzState};

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
