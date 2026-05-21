//! `GET /healthz` — gateway process-liveness probe.
//!
//! Returns `200 OK` whenever the gateway process is responsive. The
//! response is intentionally cheap to compute — no DB queries, no
//! downstream subsystem checks — so the endpoint can be hit by
//! load-balancer health probes at high frequency without affecting
//! request-path latency.

use std::time::Instant;

/// Process-wide state required by [`healthz`] to compute its response.
///
/// Constructed once at gateway startup and threaded into Axum as an
/// `Extension`. Cloning is cheap — `mode`, `version`, and `storage`
/// are `'static` string slices and `started_at` is a `Copy` `Instant`.
#[derive(Clone, Debug)]
pub struct HealthzState {
    /// Deployment mode label: `"local"` or `"remote"`.
    pub mode: &'static str,
    /// Storage backend label: `"sqlite"`, `"postgres"`, or `"memory"`.
    pub storage: &'static str,
    /// Gateway crate version (from `CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Wall-clock instant the gateway became ready to serve traffic.
    pub started_at: Instant,
}

impl HealthzState {
    /// Build state for a freshly-started gateway. `mode` and `storage`
    /// are the labels reported in the response body; `started_at` is
    /// captured at construction time and drives the `uptime_secs`
    /// field of [`super::healthz`]'s response.
    pub fn new(mode: &'static str, storage: &'static str) -> Self {
        Self {
            mode,
            storage,
            version: env!("CARGO_PKG_VERSION"),
            started_at: Instant::now(),
        }
    }
}
