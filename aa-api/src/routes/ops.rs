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

use crate::auth::scope::{RequireRead, RequireWrite, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::events::OpsChangeBroadcast;
use crate::models::ws_payloads::OpsChangePayload;
use crate::ops::{OpRecord, OpsError};
use crate::state::AppState;

/// Parse a hex-encoded 16-byte agent id, or `None` if it is not 32 hex chars.
fn parse_hex_agent_id(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(id.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Owning team of an operation, resolved op → agent → registry lineage.
///
/// Returns `None` for ops with no recorded agent, an agent id that does not
/// resolve to a registered agent, or an agent with no team — all of which are
/// then treated as admin-only by [`authorize_op_access`], so an unresolvable id
/// can never widen access.
fn op_team_id(state: &AppState, op_id: &str) -> Option<String> {
    let agent = state.ops_registry.agent_for(op_id)?;
    let bytes = parse_hex_agent_id(&agent.agent_id)?;
    state.agent_registry.lineage(&bytes).and_then(|l| l.team_id)
}

/// Enforce tenant ownership of an operation for a caller that already cleared
/// the scope gate (AAASM-3790).
///
/// Mirrors `agents::authorize_agent_access`: an admin may act on any op; a
/// tenant-scoped caller may act only on ops whose owning agent is in its team;
/// a caller with neither admin scope nor a team scope is denied up front so it
/// cannot enumerate ops via a 403-vs-404 oracle. Returns 403 for an unauthorized
/// caller, 404 when the op is unknown to an authorized caller.
fn authorize_op_access(caller: &AuthenticatedCaller, state: &AppState, op_id: &str) -> Result<(), ProblemDetail> {
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or a team scope".to_string()));
    }

    if state.ops_registry.get(op_id).is_none() {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail("Operation not found in registry".to_string()));
    }

    let authorized = match op_team_id(state, op_id) {
        Some(team) => caller.can_access_team(&team),
        // The op has no resolvable team — only an admin may act on it.
        None => is_admin,
    };
    if !authorized {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or membership in the op's team".to_string()));
    }
    Ok(())
}

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

/// AAASM-1657 PR-H: emit an `ops_change` WS event so the dashboard's
/// `useLiveOpsStream` hook can clear the optimistic override and update
/// the row in place. Looks up the owning `agent_id` from the registry
/// (recorded by `OpsRegistry::ingest_with_agent` in the policy-service
/// path); falls back to an empty string for ops registered without one
/// (e.g. the legacy `POST /api/v1/ops` register path).
fn emit_ops_change(state: &AppState, record: &OpRecord) {
    let agent_id = state
        .ops_registry
        .agent_for(&record.op_id)
        .map(|a| a.agent_id)
        .unwrap_or_default();
    let payload = OpsChangePayload {
        op_id: record.op_id.clone(),
        state: record.state,
        updated_at: record.updated_at.clone(),
    };
    let _ = state
        .events
        .ops_change_sender()
        .send(OpsChangeBroadcast { agent_id, payload });
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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    // AAASM-3790: write-scope + tenant ownership before the state change.
    authorize_op_access(&caller, &state, &op_id)?;
    let record = state.ops_registry.pause(&op_id).map_err(ops_error_to_problem)?;
    emit_ops_change(&state, &record);
    Ok(lifecycle_ok(record, "pause"))
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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    // AAASM-3790: write-scope + tenant ownership before the state change.
    authorize_op_access(&caller, &state, &op_id)?;
    let record = state.ops_registry.resume(&op_id).map_err(ops_error_to_problem)?;
    emit_ops_change(&state, &record);
    Ok(lifecycle_ok(record, "resume"))
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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ProblemDetail> {
    let op_id = validate_op_id(&id)?;
    // AAASM-3790: write-scope + tenant ownership before the state change.
    authorize_op_access(&caller, &state, &op_id)?;
    let record = state.ops_registry.terminate(&op_id).map_err(ops_error_to_problem)?;
    emit_ops_change(&state, &record);
    Ok(lifecycle_ok(record, "terminate"))
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
pub async fn list_ops(RequireRead(caller): RequireRead, Extension(state): Extension<AppState>) -> impl IntoResponse {
    // AAASM-3790: confine the listing to ops the caller's tenant owns. An admin
    // sees every op; a team-scoped caller sees only its team's ops; a caller
    // with no team scope (and no admin) sees none. Ops with no resolvable team
    // are visible only to an admin.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let ops: Vec<OpRecord> = state
        .ops_registry
        .list()
        .into_iter()
        .filter(|r| match op_team_id(&state, &r.op_id) {
            Some(team) => caller.can_access_team(&team),
            None => is_admin,
        })
        .collect();
    Json(ops)
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
