//! Remote Control-Plane Mode listener bootstrap.
//!
//! Owns `start_remote` and the `router` builder. See AAASM-1709 for the
//! design rationale; the deeper architectural context lives in
//! AAASM-1577 / E17 S-C.

use aa_core::config::RemoteModeConfig;
use axum::{routing::get, Extension, Router};
use axum_server::Handle;

use super::error::GatewayError;
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
    if cfg.tls.is_none() {
        tracing::warn!("⚠ TLS not configured — running over plain HTTP");
    }

    let app = router().into_make_service();

    axum_server::bind(cfg.listen_addr)
        .handle(handle)
        .serve(app)
        .await
        .map_err(GatewayError::Serve)
}
