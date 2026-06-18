//! `GET /api/v1/health` — REST-surface liveness probe served by local mode.
//!
//! The full REST surface lives in the sibling `aa-api` crate, whose router
//! is library-only: no shipped binary mounts it, and `aa-gateway` cannot
//! depend on `aa-api` because `aa-api` already depends on `aa-gateway`
//! (`pub use aa_gateway::ops`) — nesting the real router would be a
//! circular crate dependency, and it additionally requires the heavyweight
//! `aa_api::AppState` (≈30 wired subsystems) that local mode does not
//! construct.
//!
//! To keep `/api/v1/*` from returning a blanket 404 in local mode
//! (AAASM-3354), this module owns a minimal, self-contained
//! `/api/v1/health` handler whose JSON body is wire-compatible with
//! `aa_api::routes::health::HealthResponse`. It is the smallest viable
//! version of "serve the REST API in local mode"; the remaining
//! `/api/v1/*` data routes still require the `aa-api` router and are
//! tracked as a follow-up (see the AAASM-3354 PR body).

use std::time::Instant;

use axum::{Extension, Json};
use serde::Serialize;

/// Process-wide state required by [`api_health`] to compute uptime.
///
/// Mirrors [`super::healthz::HealthzState`] but is its own type so the
/// `/api/v1/health` surface can evolve independently of the bare
/// `/healthz` liveness probe.
#[derive(Clone, Debug)]
pub struct ApiHealthState {
    /// Gateway crate version (from `CARGO_PKG_VERSION`).
    pub version: &'static str,
    /// Wall-clock instant the gateway became ready to serve traffic.
    pub started_at: Instant,
}

impl ApiHealthState {
    /// Build state for a freshly-started gateway. `started_at` is captured
    /// at construction time and drives the `uptime_secs` response field.
    pub fn new() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            started_at: Instant::now(),
        }
    }
}

impl Default for ApiHealthState {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON body returned by `GET /api/v1/health`.
///
/// Field names match the subset of `aa_api::routes::health::HealthResponse`
/// that local mode can populate without the full `aa_api::AppState`: the
/// per-subsystem `checks` map is reported empty because local mode does not
/// wire the policy engine / registry / alert subsystems the `aa-api`
/// handler probes.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ApiHealthBody {
    /// Liveness status string: always `"ok"` here — a 200 means the
    /// process is responding to HTTP.
    pub status: String,
    /// Gateway version (semver from Cargo.toml).
    pub version: String,
    /// API version prefix.
    pub api_version: String,
    /// Server uptime in seconds since startup.
    pub uptime_secs: u64,
}

/// `GET /api/v1/health` — REST-surface liveness probe.
///
/// Always returns `200 OK` with [`ApiHealthBody`] as long as the gateway
/// process is responding to HTTP, so `curl http://127.0.0.1:7391/api/v1/health`
/// returns JSON rather than a 404 in local mode (AAASM-3354).
pub async fn api_health(Extension(state): Extension<ApiHealthState>) -> Json<ApiHealthBody> {
    Json(ApiHealthBody {
        status: "ok".to_string(),
        version: state.version.to_string(),
        api_version: "v1".to_string(),
        uptime_secs: state.started_at.elapsed().as_secs(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_serialises_to_documented_shape() {
        let body = ApiHealthBody {
            status: "ok".into(),
            version: "0.0.1".into(),
            api_version: "v1".into(),
            uptime_secs: 7,
        };
        let json = serde_json::to_value(&body).expect("ApiHealthBody must serialise");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["version"], "0.0.1");
        assert_eq!(json["api_version"], "v1");
        assert_eq!(json["uptime_secs"], 7);
    }

    #[tokio::test]
    async fn handler_returns_ok_body() {
        let Json(body) = api_health(Extension(ApiHealthState::new())).await;
        assert_eq!(body.status, "ok");
        assert_eq!(body.api_version, "v1");
        assert_eq!(body.version, env!("CARGO_PKG_VERSION"));
    }
}
