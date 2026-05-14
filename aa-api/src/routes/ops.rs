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
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::error::ProblemDetail;

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

/// `POST /api/v1/ops/{id}/pause` — request that an in-flight operation be paused.
///
/// Stub today: returns 202 Accepted and logs the request without updating
/// any state. Real enforcement awaits the in-flight-ops registry architecture.
#[utoipa::path(
    post,
    path = "/api/v1/ops/{id}/pause",
    tag = "ops",
    params(
        ("id" = String, Path, description = "Operation id (string form of `GovernanceEvent.id`).")
    ),
    responses(
        (status = 202, description = "Pause request accepted", body = OpActionAck),
        (status = 400, description = "Empty or malformed operation id", body = ProblemDetail)
    )
)]
pub async fn pause_op(Path(id): Path<String>) -> Result<impl IntoResponse, ProblemDetail> {
    Ok(ack(validate_op_id(&id)?, "pause"))
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
