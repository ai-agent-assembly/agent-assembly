//! Human-in-the-loop approval endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use aa_runtime::approval::ApprovalDecision;

use crate::error::ProblemDetail;
use crate::pagination::{PaginatedResponse, PaginationParams};
use crate::state::AppState;

/// One step in the routing history of an approval request.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RoutingHistoryEntry {
    /// Unix epoch timestamp (seconds) when this step occurred.
    pub at: u64,
    /// Whether this step was an initial routing or an escalation: `"routed"` or `"escalated"`.
    pub action: String,
    /// Role that previously held the request, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_role: Option<String>,
    /// Role the request was routed or escalated to.
    pub to_role: String,
}

/// Structured routing metadata set by the approval router.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RoutingStatusInfo {
    /// Routing status string: `"routed_to_team_admin"`, `"routed_to_org_admin"`, or `"escalated_to_<role>"`.
    pub status: String,
    /// Team the request was routed to, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_team_id: Option<String>,
    /// Role the request is currently assigned to (e.g. `"TeamAdmin"`, `"OrgAdmin"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_role: Option<String>,
    /// Unix timestamp (seconds) at which escalation is scheduled to fire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalate_at: Option<u64>,
    /// Unix timestamp (seconds) when the initial routing decision was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routed_at: Option<u64>,
    /// Full routing and escalation history for this request.
    pub history: Vec<RoutingHistoryEntry>,
}

/// JSON representation of a pending approval request.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApprovalResponse {
    /// Unique approval request identifier.
    pub id: String,
    /// Agent that triggered the approval.
    pub agent_id: String,
    /// The governance action requiring approval.
    pub action: String,
    /// Human-readable reason for the approval request.
    pub reason: String,
    /// Current status: "pending", "approved", or "rejected".
    pub status: String,
    /// ISO 8601 timestamp when the request was created.
    pub created_at: String,
    /// Structured routing metadata. Absent until the router has processed the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_status: Option<RoutingStatusInfo>,
    /// Team the approval was routed to, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
}

/// `GET /api/v1/approvals` — list pending approval requests.
///
/// List pending human-in-the-loop approval requests with pagination.
#[utoipa::path(
    get,
    path = "/api/v1/approvals",
    params(PaginationParams),
    responses(
        (status = 200, description = "Paginated list of pending approvals", body = Vec<ApprovalResponse>)
    ),
    tag = "approvals"
)]
pub async fn list_approvals(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> impl IntoResponse {
    let pending = state.approval_queue.list();
    let total = pending.len();

    let items: Vec<ApprovalResponse> = pending
        .into_iter()
        .skip(params.offset())
        .take(params.per_page() as usize)
        .map(|p| {
            let routing_status = p.routing_status.map(|status| RoutingStatusInfo {
                status,
                target_team_id: p.team_id.clone(),
                target_role: p.target_role,
                escalate_at: p.escalate_at,
                routed_at: p.routed_at,
                history: p
                    .routing_history
                    .into_iter()
                    .map(|e| RoutingHistoryEntry {
                        at: e.at,
                        action: e.action,
                        from_role: e.from_role,
                        to_role: e.to_role,
                    })
                    .collect(),
            });
            ApprovalResponse {
                id: p.request_id.to_string(),
                agent_id: p.agent_id,
                action: p.action,
                reason: p.condition_triggered,
                status: "pending".to_string(),
                created_at: chrono::DateTime::from_timestamp(p.submitted_at as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                routing_status,
                team_id: p.team_id,
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedResponse {
            items,
            page: params.page(),
            per_page: params.per_page(),
            total: total as u64,
        }),
    )
}

/// `POST /api/v1/approvals/:id/approve` — approve a pending action.
///
/// Approve a pending governance action, unblocking the agent.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}/approve",
    params(("id" = String, Path, description = "Approval request identifier")),
    responses(
        (status = 200, description = "Action approved", body = ApprovalResponse),
        (status = 404, description = "Approval request not found")
    ),
    tag = "approvals"
)]
pub async fn approve_action(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<DecideRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid UUID: {id}")))?;

    let decision = ApprovalDecision::Approved {
        by: body.by.unwrap_or_else(|| "api".to_string()),
        reason: body.reason,
    };

    state.approval_queue.decide(uuid, decision).map_err(|_| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Approval request not found: {id}"))
    })?;

    Ok((
        StatusCode::OK,
        Json(ApprovalResponse {
            id,
            agent_id: String::new(),
            action: String::new(),
            reason: String::new(),
            status: "approved".to_string(),
            created_at: String::new(),
            routing_status: None,
            team_id: None,
        }),
    ))
}

/// `POST /api/v1/approvals/:id/reject` — reject a pending action.
///
/// Reject a pending governance action, denying the agent request.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}/reject",
    params(("id" = String, Path, description = "Approval request identifier")),
    responses(
        (status = 200, description = "Action rejected", body = ApprovalResponse),
        (status = 404, description = "Approval request not found")
    ),
    tag = "approvals"
)]
pub async fn reject_action(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<DecideRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid UUID: {id}")))?;

    let decision = ApprovalDecision::Rejected {
        by: body.by.unwrap_or_else(|| "api".to_string()),
        reason: body.reason.unwrap_or_else(|| "rejected via API".to_string()),
    };

    state.approval_queue.decide(uuid, decision).map_err(|_| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Approval request not found: {id}"))
    })?;

    Ok((
        StatusCode::OK,
        Json(ApprovalResponse {
            id,
            agent_id: String::new(),
            action: String::new(),
            reason: String::new(),
            status: "rejected".to_string(),
            created_at: String::new(),
            routing_status: None,
            team_id: None,
        }),
    ))
}

/// Request body for approval decide actions.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DecideRequest {
    /// Identity of the operator making the decision.
    pub by: Option<String>,
    /// Optional reason for the decision.
    pub reason: Option<String>,
}
