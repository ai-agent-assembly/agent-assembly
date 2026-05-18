//! Health check endpoint.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Serialize;

use crate::error::ProblemDetail;
use crate::state::AppState;

/// Response body for the health endpoint.
#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    /// Liveness status string: `"ok"` when all subsystems healthy, `"degraded"` otherwise.
    pub status: String,
    /// Gateway version (semver from Cargo.toml).
    pub version: String,
    /// API version prefix (e.g. `"v1"`).
    pub api_version: String,
    /// Server uptime in seconds since startup.
    pub uptime_secs: u64,
    /// Number of currently active WebSocket/SSE connections.
    pub active_connections: i64,
    /// Pipeline processing lag in milliseconds (placeholder, always 0 for now).
    pub pipeline_lag_ms: u64,
    /// Per-subsystem health status. Each value is `"ok"` or `"degraded"`.
    pub checks: BTreeMap<String, String>,
}

/// Probe each downstream subsystem and return its health status string.
async fn subsystem_checks(state: &AppState) -> BTreeMap<String, String> {
    let mut checks = BTreeMap::new();

    // policy_engine: active_policy_info() is a sync infallible read of the loaded policy.
    let _ = state.policy_engine.active_policy_info();
    checks.insert("policy_engine".to_string(), "ok".to_string());

    // registry: list() is a sync infallible read of the in-memory agent store.
    let _ = state.agent_registry.list();
    checks.insert("registry".to_string(), "ok".to_string());

    // audit: list() reads the audit log directory; errors (e.g. permissions) → degraded.
    let audit_status = match state.audit_reader.list(1, 0, None, None).await {
        Ok(_) => "ok",
        Err(_) => "degraded",
    };
    checks.insert("audit".to_string(), audit_status.to_string());

    // alerts: list() is a sync infallible read of the in-memory alert ring buffer.
    let _ = state.alert_store.list(0, 0);
    checks.insert("alerts".to_string(), "ok".to_string());

    checks
}

/// `GET /api/v1/health` — liveness and readiness probe.
///
/// Returns `200` when all subsystems report healthy; `503` when any subsystem
/// is degraded. The `checks` map in the response body carries per-subsystem
/// status strings (`"ok"` or `"degraded"`).
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "One or more subsystems are degraded", body = HealthResponse),
        (status = 404, description = "Not found", body = ProblemDetail)
    )
)]
pub async fn health(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let uptime_secs = state.startup_time.elapsed().as_secs();
    let active_connections = state.active_connections.load(Ordering::Relaxed);
    let checks = subsystem_checks(&state).await;

    let all_ok = checks.values().all(|v| v == "ok");
    let status_code = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status_str = if all_ok { "ok" } else { "degraded" };

    (
        status_code,
        Json(HealthResponse {
            status: status_str.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            api_version: "v1".to_string(),
            uptime_secs,
            active_connections,
            pipeline_lag_ms: 0,
            checks,
        }),
    )
}
