//! Remote Control-Plane Mode listener bootstrap.
//!
//! Owns `start_remote` and the `router` builder. See AAASM-1709 for the
//! design rationale; the deeper architectural context lives in
//! AAASM-1577 / E17 S-C.

use axum::{routing::get, Extension, Router};

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
