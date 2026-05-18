//! Per-operation lifecycle endpoints — pause / resume / terminate.
//!
//! These endpoints accept a request to change an in-flight operation's
//! lifecycle state and return `202 Accepted`. They are intentionally
//! **stubs** today:
//!
//! * No in-flight-ops registry exists in the gateway yet, so there is no
//!   state machine to update.
//! * No SDK-side enforcement channel exists, so the agent is not actually
//!   paused / resumed / terminated.
//!
//! The handlers exist so the Live Ops dashboard can call the conventional
//! `POST /api/v1/ops/{id}/{action}` paths without 404-ing, which exercises
//! its optimistic UI's success path instead of its rollback path. Real
//! enforcement is tracked under a separate architecture follow-up Task.

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

fn ack(op_id: String, action: &'static str) -> impl IntoResponse {
    tracing::info!(target: "aa_api::ops", op_id = %op_id, action, "op lifecycle action accepted");
    (
        StatusCode::ACCEPTED,
        Json(OpActionAck {
            op_id,
            action: action.to_string(),
            accepted_at: chrono::Utc::now().to_rfc3339(),
        }),
    )
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

/// `POST /api/v1/ops/{id}/resume` — request that a paused operation resume.
///
/// Stub today: returns 202 Accepted and logs the request without updating
/// any state. Real enforcement awaits the in-flight-ops registry architecture.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/resume",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 202, description = "Resume request accepted", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail)
    )
)]
pub async fn resume_op(Path(id): Path<String>) -> Result<impl IntoResponse, ProblemDetail> {
    Ok(ack(validate_op_id(&id)?, "resume"))
}

/// `POST /api/v1/ops/{id}/terminate` — request that an in-flight operation be terminated.
///
/// Stub today: returns 202 Accepted and logs the request without updating
/// any state. Real enforcement awaits the in-flight-ops registry architecture.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/terminate",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 202, description = "Terminate request accepted", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail)
    )
)]
pub async fn terminate_op(Path(id): Path<String>) -> Result<impl IntoResponse, ProblemDetail> {
    Ok(ack(validate_op_id(&id)?, "terminate"))
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
