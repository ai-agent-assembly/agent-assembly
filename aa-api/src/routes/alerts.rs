//! Governance alert endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;

use crate::alerts::StoredAlert;
use crate::error::ProblemDetail;
use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// Convert a `StoredAlert` into the public-facing `AlertResponse` shape.
fn alert_response_from_stored(a: StoredAlert) -> AlertResponse {
    AlertResponse {
        id: a.id.to_string(),
        severity: a.severity.to_string(),
        category: "budget".to_string(),
        message: a.message,
        timestamp: a.timestamp,
        agent_id: Some(a.agent_id),
        status: a.status,
        updated_at: a.updated_at,
    }
}

/// JSON representation of a governance alert.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AlertResponse {
    /// Unique alert identifier.
    pub id: String,
    /// Alert severity level (e.g. "warning", "critical").
    pub severity: String,
    /// Alert category (e.g. "budget", "policy_violation", "anomaly").
    pub category: String,
    /// Human-readable alert message.
    pub message: String,
    /// ISO 8601 timestamp when the alert was raised.
    pub timestamp: String,
    /// Agent ID that triggered the alert (if applicable).
    pub agent_id: Option<String>,
    /// Lifecycle status — `"unresolved"` on capture, `"resolved"` once
    /// the alert has been acknowledged via `POST /alerts/:id/resolve`.
    pub status: String,
    /// ISO 8601 timestamp of the last mutation (e.g. resolve). `None`
    /// while the alert is still in its initial captured state.
    pub updated_at: Option<String>,
}

/// `GET /api/v1/alerts` — list recent governance alerts.
///
/// List recent governance alerts such as budget warnings and policy violations.
#[utoipa::path(
    get,
    path = "/api/v1/alerts",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of recent alerts", body = Vec<AlertResponse>)
    ),
    tag = "alerts"
)]
pub async fn list_alerts(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = params.per_page() as usize;
    let offset = params.offset();

    let (stored, total) = state.alert_store.list(limit, offset);

    let items: Vec<AlertResponse> = stored.into_iter().map(alert_response_from_stored).collect();

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

/// `GET /api/v1/alerts/:id` — fetch one governance alert by ID.
///
/// Returns 404 with an RFC 7807 problem detail if the alert is unknown
/// or has been evicted from the in-memory ring buffer.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/{id}",
    params(("id" = String, Path, description = "Numeric alert identifier")),
    responses(
        (status = 200, description = "Alert detail", body = AlertResponse),
        (status = 404, description = "Alert not found")
    ),
    tag = "alerts"
)]
pub async fn get_alert(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<AlertResponse>), ProblemDetail> {
    let numeric_id = id
        .parse::<u64>()
        .map_err(|_| ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Alert not found: {id}")))?;

    let stored = state.alert_store.get(numeric_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Alert not found: {id}"))
    })?;

    Ok((StatusCode::OK, Json(alert_response_from_stored(stored))))
}
