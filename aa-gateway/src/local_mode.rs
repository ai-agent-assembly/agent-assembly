//! Local Dev Mode bootstrap (Epic 17 S-B, AAASM-1576).
//!
//! Hosts the lightweight in-process control plane the gateway runs in
//! [`DeploymentMode::Local`]. The module is built up across the eight
//! sub-tasks of AAASM-1576; this file currently provides only the type
//! surface that the remaining sub-tasks layer behaviour onto.
//!
//! [`DeploymentMode::Local`]: aa_core::config::DeploymentMode::Local

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

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

/// JSON payload returned by `GET /healthz` in local mode.
///
/// Documented response shape from AAASM-1576 AC #4:
///
/// ```json
/// {"mode":"local","storage":"sqlite","version":"0.0.1"}
/// ```
///
/// `Deserialize` is derived so the pre-flight probe in AAASM-1715 can
/// re-parse the response and reject other servers that happen to be
/// listening on the same port but speak a different protocol.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthzResponse {
    /// Always `"local"` when produced by this module.
    pub mode: String,
    /// Storage backend label — `"sqlite"` for local mode.
    pub storage: String,
    /// Gateway binary version (set from `CARGO_PKG_VERSION` at compile time).
    pub version: String,
}
