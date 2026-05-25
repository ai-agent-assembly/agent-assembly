//! Audit log query endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// JSON representation of an audit log entry.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LogEntry {
    /// Monotonic sequence number within the session.
    pub seq: u64,
    /// ISO 8601 timestamp of the event.
    pub timestamp: String,
    /// Hex-encoded agent ID that produced this log entry.
    pub agent_id: String,
    /// Hex-encoded session ID for the agent run.
    pub session_id: String,
    /// Type of audit event.
    pub event_type: String,
    /// Pre-serialized JSON payload.
    pub payload: String,
}

/// Optional filter parameters for the audit log query.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct LogFilterParams {
    /// Filter by hex-encoded agent ID.
    pub agent_id: Option<String>,
    /// Filter by event type name (e.g. `PolicyViolation`).
    pub event_type: Option<String>,
    /// AAASM-2008 — filter by organisation identifier. When supplied, only
    /// audit entries whose `lineage.org_id` matches are returned. Entries
    /// emitted before the agent was registered with an `org_id` (where the
    /// field is `None` on the entry) never match an explicit `org_id`
    /// filter — multi-tenancy isolation requires explicit Org tagging on
    /// the entry at write time.
    pub org_id: Option<String>,
}

/// `GET /api/v1/logs` — paginated audit log query.
///
/// Query the paginated audit log of governance events.
/// Supports optional filtering by agent ID and event type.
#[utoipa::path(
    get,
    path = "/api/v1/logs",
    params(PaginationParams, LogFilterParams),
    responses(
        (status = 200, description = "Paginated audit log entries", body = Vec<LogEntry>)
    ),
    tag = "logs"
)]
pub async fn list_logs(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
    axum::extract::Query(filters): axum::extract::Query<LogFilterParams>,
) -> impl IntoResponse {
    let limit = params.per_page() as usize;
    let offset = params.offset();

    let (entries, total) = state
        .audit_reader
        .list(
            limit,
            offset,
            filters.agent_id.as_deref(),
            filters.event_type.as_deref(),
            filters.org_id.as_deref(),
        )
        .await
        .unwrap_or_default();

    let items: Vec<LogEntry> = entries
        .into_iter()
        .map(|e| {
            let ts_secs = e.timestamp_ns() / 1_000_000_000;
            let ts_nanos = (e.timestamp_ns() % 1_000_000_000) as u32;
            let timestamp = chrono::DateTime::from_timestamp(ts_secs as i64, ts_nanos)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_default();

            LogEntry {
                seq: e.seq(),
                timestamp,
                agent_id: hex::encode(e.agent_id().as_bytes()),
                session_id: hex::encode(e.session_id().as_bytes()),
                event_type: e.event_type().as_str().to_string(),
                payload: e.payload().to_string(),
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedResponse {
            items,
            page: params.page(),
            per_page: params.per_page(),
            total,
        }),
    )
}
