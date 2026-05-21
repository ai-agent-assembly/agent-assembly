//! Local Dev Mode bootstrap (Epic 17 S-B, AAASM-1576).
//!
//! Hosts the lightweight in-process control plane the gateway runs in
//! [`DeploymentMode::Local`]. The module is built up across the eight
//! sub-tasks of AAASM-1576; this file currently provides only the type
//! surface that the remaining sub-tasks layer behaviour onto.
//!
//! [`DeploymentMode::Local`]: aa_core::config::DeploymentMode::Local

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{routing::get, Extension, Router};
use tokio::sync::oneshot;

use crate::routes::healthz::{healthz, HealthzState};

/// Handle returned by `start_local()` once the local control plane is up.
///
/// Holds the bound socket address (useful in tests that bind to port `0`
/// to pick a free port) and the one-shot sender that drives the graceful
/// shutdown path installed in AAASM-1728.
///
/// The handle is intentionally **not** `Clone` — only one caller can
/// own the shutdown trigger at a time.
#[allow(dead_code)] // consumed by start_local() / run_until_shutdown — AAASM-1725, AAASM-1728
pub struct LocalGatewayHandle {
    /// Address the local gateway is actually bound to. In normal
    /// operation this is `127.0.0.1:{config.port}`; in tests that pass
    /// port `0`, the resolved ephemeral port lives here.
    pub local_addr: SocketAddr,
    /// One-shot channel that signals the Axum server task to begin
    /// graceful shutdown. Hooked up by AAASM-1728's signal handler.
    pub(crate) shutdown_tx: oneshot::Sender<()>,
}

/// Errors that can occur while booting the local-mode control plane.
///
/// Each variant maps to a discrete failure mode an operator running
/// `aasm start --mode local` (or a test calling `start_local()`
/// directly) might hit. The `#[source]` fields preserve the original
/// I/O / sqlx / signal error so `{:?}` and `tracing` capture the full
/// chain.
#[derive(Debug, thiserror::Error)]
pub enum LocalModeError {
    /// `TcpListener::bind` failed — port already in use by a foreign
    /// process, permission denied, or address invalid.
    #[error("failed to bind local gateway to {addr}: {source}")]
    Bind {
        /// The socket address `start_local()` tried to bind.
        addr: String,
        /// Underlying `std::io::Error` from `TcpListener::bind`.
        #[source]
        source: std::io::Error,
    },
    /// Opening or migrating the SQLite database at `path` failed.
    #[error("failed to open SQLite at {path}: {source}", path = path.display())]
    Storage {
        /// The resolved on-disk path the gateway tried to open.
        path: PathBuf,
        /// Underlying `sqlx::Error` from `SqlitePool::connect_with`.
        #[source]
        source: sqlx::Error,
    },
    /// Writing the PID file to `~/.aasm/gateway.pid` failed.
    #[error("failed to write PID file at {path}: {source}", path = path.display())]
    PidFile {
        /// The PID-file path the gateway tried to write.
        path: PathBuf,
        /// Underlying `std::io::Error` from `std::fs::write`.
        #[source]
        source: std::io::Error,
    },
    /// Installing the SIGTERM / SIGINT handler failed (Unix only).
    #[error("shutdown signal handler installation failed: {0}")]
    Signal(#[source] std::io::Error),
}

/// Build the local-mode Axum router skeleton.
///
/// Mounts only `/healthz` for now via [`crate::routes::healthz::healthz`];
/// later sub-tasks (dashboard SPA in AAASM-1580, API routes wired by
/// AAASM-1731) merge into this same router.
///
/// The `Extension(HealthzState::new("local", "sqlite"))` layer supplies
/// the labels the shared `/healthz` handler reads, so the response body
/// carries `mode: "local"` and `storage: "sqlite"` per AAASM-1576 AC #4.
#[allow(dead_code)] // consumed by start_local() — AAASM-1725
pub(crate) fn router() -> Router {
    let state = HealthzState::new("local", "sqlite");
    Router::new().route("/healthz", get(healthz)).layer(Extension(state))
}
