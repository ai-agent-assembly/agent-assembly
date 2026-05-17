//! Human-in-the-loop approval endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use aa_runtime::approval::{ApprovalDecision, ApprovalError, ApprovalLookup, PendingApprovalRequest, ResolvedRecord};
use utoipa::IntoParams;

use crate::error::ProblemDetail;
use crate::pagination::PaginatedResponse;
use crate::state::AppState;

/// Query parameters for `GET /api/v1/approvals` (AAASM-1477).
///
/// Adds `status` and `agent` filters on top of [`PaginationParams`].
///
/// * `status` is case-insensitive; accepted values are `pending`,
///   `approved`, `rejected`. Omitted ⇒ pending-only (backwards-compatible).
/// * `agent` matches `agent_id` exactly across both pending and resolved.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListApprovalsParams {
    /// Page number (1-indexed). Same semantics as [`PaginationParams::page`].
    pub page: Option<u32>,
    /// Items per page. Same semantics as [`PaginationParams::per_page`].
    pub per_page: Option<u32>,
    /// Filter by approval status: `pending` | `approved` | `rejected`
    /// (case-insensitive). When absent, returns pending requests only —
    /// matches the pre-AAASM-1477 contract.
    pub status: Option<String>,
    /// Filter by `agent_id` exact match.
    pub agent: Option<String>,
}

impl ListApprovalsParams {
    /// 1-indexed page number, defaulting to 1.
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }
    /// Items per page, clamped to [1, 100].
    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(20).clamp(1, 100)
    }
    /// Offset = (page-1) * per_page.
    pub fn offset(&self) -> usize {
        ((self.page() - 1) * self.per_page()) as usize
    }
    /// Normalize the optional status string to one of the canonical
    /// lower-case values used internally (`"pending"`, `"approved"`,
    /// `"rejected"`). Returns `None` for absent/empty inputs and `Some(_)`
    /// for any other value (so unknown statuses just return empty rather
    /// than erroring — matches the established CLI tolerance pattern).
    pub fn normalized_status(&self) -> Option<String> {
        self.status
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
    }
}

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
    /// ISO 8601 timestamp at which the pending request expires
    /// (`created_at` + the governing `approval_timeout_secs`). The
    /// dashboard renders a countdown from this value. Empty string on
    /// post-decision (`approved` / `rejected`) responses where
    /// expiration is no longer meaningful.
    pub expires_at: String,
    /// Structured routing metadata. Absent until the router has processed the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_status: Option<RoutingStatusInfo>,
    /// Team the approval was routed to, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
}

/// Render a `PendingApprovalRequest` (returned by `ApprovalQueue::list`)
/// as the wire-format `ApprovalResponse` consumed by the dashboard and CLI.
/// Factored out so `list_approvals`, `get_approval`, and any future handler
/// share one mapping path.
fn pending_to_response(p: PendingApprovalRequest) -> ApprovalResponse {
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
        expires_at: chrono::DateTime::from_timestamp(p.submitted_at.saturating_add(p.timeout_secs) as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        routing_status,
        team_id: p.team_id,
    }
}

/// Render a `ResolvedRecord` (returned by `ApprovalQueue::get_by_id` or
/// `list_resolved`) as the wire-format `ApprovalResponse`. `expires_at`
/// is intentionally left empty for resolved entries — the field semantically
/// only applies to pending requests; see [`ApprovalResponse::expires_at`].
fn resolved_to_response(r: ResolvedRecord) -> ApprovalResponse {
    ApprovalResponse {
        id: r.request_id.to_string(),
        agent_id: r.agent_id,
        action: r.action,
        reason: r.condition_triggered,
        status: r.status,
        created_at: chrono::DateTime::from_timestamp(r.submitted_at as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
        expires_at: String::new(),
        routing_status: None,
        team_id: r.team_id,
    }
}

/// `GET /api/v1/approvals` — list approval requests with optional filters.
///
/// Without `status` returns pending requests only (backwards-compatible).
/// With `status=PENDING|APPROVED|REJECTED` (case-insensitive) returns the
/// matching slice. The `agent` filter narrows by `agent_id` exact match
/// across both states.
#[utoipa::path(
    get,
    path = "/api/v1/approvals",
    params(ListApprovalsParams),
    responses(
        (status = 200, description = "Paginated list of approvals", body = Vec<ApprovalResponse>)
    ),
    tag = "approvals"
)]
pub async fn list_approvals(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<ListApprovalsParams>,
) -> impl IntoResponse {
    let agent_filter = params.agent.as_deref();
    let all: Vec<ApprovalResponse> = match params.normalized_status().as_deref() {
        // No status filter — preserve the pre-AAASM-1477 contract:
        // pending only, optionally narrowed by `agent`.
        None | Some("pending") => state
            .approval_queue
            .list()
            .into_iter()
            .filter(|p| match agent_filter {
                None => true,
                Some(a) => p.agent_id == a,
            })
            .map(pending_to_response)
            .collect(),
        Some(status @ ("approved" | "rejected" | "timed_out")) => state
            .approval_queue
            .list_resolved(Some(status), agent_filter)
            .into_iter()
            .map(resolved_to_response)
            .collect(),
        // Unknown status value — empty page, not an error. Matches the
        // established CLI tolerance for typos in filter values.
        Some(_) => Vec::new(),
    };

    let total = all.len();
    let items: Vec<ApprovalResponse> = all
        .into_iter()
        .skip(params.offset())
        .take(params.per_page() as usize)
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

/// `GET /api/v1/approvals/:id` — look up a single approval by ID.
///
/// Returns the request whether it is currently pending or has been
/// resolved (approved / rejected / timed-out). Resolved entries come
/// from a bounded in-memory history (default cap 1000) — older entries
/// may have been evicted under load.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/{id}",
    params(("id" = String, Path, description = "Approval request identifier")),
    responses(
        (status = 200, description = "Approval found", body = ApprovalResponse),
        (status = 404, description = "Approval request not found or evicted from history")
    ),
    tag = "approvals"
)]
pub async fn get_approval(
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid UUID: {id}")))?;

    let resp = match state.approval_queue.get_by_id(uuid) {
        Some(ApprovalLookup::Pending(p)) => pending_to_response(p),
        Some(ApprovalLookup::Resolved(r)) => resolved_to_response(r),
        None => {
            return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("Approval request not found: {id}")));
        }
    };

    Ok((StatusCode::OK, Json(resp)))
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

    state.approval_queue.decide(uuid, decision).map_err(|e| match e {
        ApprovalError::AlreadyDecided => ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail(format!("Approval request has already been decided: {id}")),
        ApprovalError::NotFound => {
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Approval request not found: {id}"))
        }
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
            expires_at: String::new(),
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

    let reason = body.reason.filter(|r| !r.trim().is_empty()).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail("Rejection requires a non-empty reason")
    })?;

    let decision = ApprovalDecision::Rejected {
        by: body.by.unwrap_or_else(|| "api".to_string()),
        reason,
    };

    state.approval_queue.decide(uuid, decision).map_err(|e| match e {
        ApprovalError::AlreadyDecided => ProblemDetail::from_status(StatusCode::CONFLICT)
            .with_detail(format!("Approval request has already been decided: {id}")),
        ApprovalError::NotFound => {
            ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Approval request not found: {id}"))
        }
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
            expires_at: String::new(),
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
