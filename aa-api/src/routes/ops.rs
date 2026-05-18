//! Per-operation lifecycle endpoints (AAASM-1525).
//!
//! Backed by [`crate::ops::OpsRegistry`] on [`crate::state::AppState`].
//! Each operation is registered via `POST /api/v1/ops` and then driven
//! through its lifecycle with the `pause`, `resume`, and `terminate` actions.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ProblemDetail;
use crate::ops::{OpRecord, OpsError};
use crate::state::AppState;

/// Acknowledgement returned by the per-op lifecycle endpoints.
///
/// The fields are deliberately minimal — they document what the
/// gateway received, not the resulting state (which the dashboard
/// observes via the WebSocket event stream).
#[derive(Debug, Serialize, ToSchema)]
pub struct OpActionAck {
    /// Operation id from the URL path.
    pub op_id: String,
    /// Action that was requested — one of `"pause"`, `"resume"`, `"terminate"`.
    pub action: String,
    /// Server-side timestamp when the request was accepted (RFC 3339).
    pub accepted_at: String,
}

fn lifecycle_ok(record: OpRecord, action: &'static str) -> impl IntoResponse {
    tracing::info!(target: "aa_api::ops", op_id = %record.op_id, action, state = ?record.state, "op lifecycle transition");
    (
        StatusCode::OK,
        Json(OpActionAck {
            op_id: record.op_id,
            action: action.to_string(),
            accepted_at: record.updated_at,
        }),
    )
}

fn ops_error_to_problem(err: OpsError) -> ProblemDetail {
    match err {
        OpsError::NotFound => {
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail("Operation not found in registry".to_string())
        }
        OpsError::InvalidTransition => ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail("Operation state does not permit this transition".to_string()),
    }
}

fn validate_op_id(raw: &str) -> Result<String, ProblemDetail> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("Operation id must not be empty".to_string()));
    }
    Ok(trimmed.to_string())
}

/// `POST /api/v1/ops/{id}/pause` — transition a running operation to paused.
///
/// * `200 OK` — op transitioned `running → paused`.
/// * `400 Bad Request` — whitespace-only op id.
/// * `404 Not Found` — no op with this id is registered.
/// * `409 Conflict` — op is already paused or terminated.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/pause",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 200, description = "Op paused", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail),
        (status = 404, description = "Op not found", body = ProblemDetail),
        (status = 409, description = "Invalid state transition", body = ProblemDetail)
    )
)]
pub async fn pause_op(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    state
        .ops_registry
        .pause(&op_id)
        .map(|record| lifecycle_ok(record, "pause"))
        .map_err(ops_error_to_problem)
}

/// `POST /api/v1/ops/{id}/resume` — transition a paused operation back to running.
///
/// * `200 OK` — op transitioned `paused → running`.
/// * `400 Bad Request` — whitespace-only op id.
/// * `404 Not Found` — no op with this id is registered.
/// * `409 Conflict` — op is running or terminated.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/resume",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 200, description = "Op resumed", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail),
        (status = 404, description = "Op not found", body = ProblemDetail),
        (status = 409, description = "Invalid state transition", body = ProblemDetail)
    )
)]
pub async fn resume_op(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    state
        .ops_registry
        .resume(&op_id)
        .map(|record| lifecycle_ok(record, "resume"))
        .map_err(ops_error_to_problem)
}

/// `POST /api/v1/ops/{id}/terminate` — terminate a running or paused operation.
///
/// Idempotent: a second call on an already-terminated op also returns `200 OK`.
///
/// * `200 OK` — op transitioned to `terminated` (or was already terminated).
/// * `400 Bad Request` — whitespace-only op id.
/// * `404 Not Found` — no op with this id is registered.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/terminate",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 200, description = "Op terminated", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail),
        (status = 404, description = "Op not found", body = ProblemDetail)
    )
)]
pub async fn terminate_op(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    state
        .ops_registry
        .terminate(&op_id)
        .map(|record| lifecycle_ok(record, "terminate"))
        .map_err(ops_error_to_problem)
}

/// `GET /api/v1/ops` — list all registered in-flight operations.
///
/// Returns a snapshot of every op currently tracked in the registry,
/// regardless of lifecycle state (running, paused, or terminated).
#[utoipa::path(
    get,
    path = "/api/v1/ops",
    tag = "ops",
    responses(
        (status = 200, description = "List of all registered ops", body = Vec<OpRecord>)
    )
)]
pub async fn list_ops(Extension(state): Extension<AppState>) -> impl IntoResponse {
    Json(state.ops_registry.list())
}

/// Request body for `POST /api/v1/ops` — register a new in-flight operation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterOpRequest {
    /// Stable identifier for the operation, typically a `GovernanceEvent.id`.
    pub op_id: String,
}

/// `POST /api/v1/ops` — register a new in-flight operation in the `running` state.
///
/// Returns `201 Created` with the initial [`OpRecord`]. Callers may then drive
/// lifecycle transitions via the `pause`, `resume`, and `terminate` endpoints.
#[utoipa::path(
    post,
    path = "/api/v1/ops",
    tag = "ops",
    request_body = RegisterOpRequest,
    responses(
        (status = 201, description = "Op registered in running state", body = OpRecord),
        (status = 400, description = "Empty or missing op_id", body = ProblemDetail)
    )
)]
pub async fn register_op(
    Extension(state): Extension<AppState>,
    Json(req): Json<RegisterOpRequest>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = req.op_id.trim().to_string();
    if op_id.is_empty() {
        return Err(
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail("op_id must not be empty".to_string())
        );
    }
    let record = state.ops_registry.register(op_id);
    tracing::info!(target: "aa_api::ops", op_id = %record.op_id, "op registered");
    Ok((StatusCode::CREATED, Json(record)))
}
