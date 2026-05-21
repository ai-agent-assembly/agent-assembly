//! `GET /healthz` — gateway process-liveness probe.
//!
//! Returns `200 OK` whenever the gateway process is responsive. The
//! response is intentionally cheap to compute — no DB queries, no
//! downstream subsystem checks — so the endpoint can be hit by
//! load-balancer health probes at high frequency without affecting
//! request-path latency.

use std::time::Instant;

use axum::{Extension, Json};
use serde::Serialize;

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

/// JSON body returned by `GET /healthz`.
///
/// Field names are stable wire contract — load balancers, the `aasm
/// status` CLI, and the dashboard parse this shape. Do not rename
/// without a coordinated client update.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct HealthzBody {
    /// Deployment mode label: `"local"` or `"remote"`.
    pub mode: String,
    /// Gateway crate version.
    pub version: String,
    /// Storage backend label.
    pub storage: String,
    /// Seconds elapsed since the gateway became ready to serve traffic.
    pub uptime_secs: u64,
}

/// `GET /healthz` — process-liveness probe.
///
/// Always returns `200 OK` with [`HealthzBody`] as long as the gateway
/// process is responding to HTTP. A 200 here does **not** imply the
/// database or any downstream subsystem is healthy — `/api/v1/admin/status`
/// reports the deeper readiness signal (delivered by AAASM-1474).
pub async fn healthz(Extension(state): Extension<HealthzState>) -> Json<HealthzBody> {
    Json(HealthzBody {
        mode: state.mode.to_string(),
        version: state.version.to_string(),
        storage: state.storage.to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_serialises_to_documented_shape() {
        let body = HealthzBody {
            mode: "remote".into(),
            version: "0.0.1".into(),
            storage: "memory".into(),
            uptime_secs: 7,
        };
        let json = serde_json::to_value(&body).expect("HealthzBody must serialise");
        assert_eq!(json["mode"], "remote");
        assert_eq!(json["version"], "0.0.1");
        assert_eq!(json["storage"], "memory");
        assert_eq!(json["uptime_secs"], 7);
    }

    #[tokio::test]
    async fn handler_returns_documented_body() {
        let state = HealthzState::new("remote", "memory");
        let Json(body) = healthz(Extension(state)).await;
        assert_eq!(body.mode, "remote");
        assert_eq!(body.storage, "memory");
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    }
}
