//! Human-in-the-loop approval endpoints.

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use aa_runtime::approval::{ApprovalDecision, ApprovalError, ApprovalLookup, PendingApprovalRequest, ResolvedRecord};
use utoipa::IntoParams;

use crate::auth::scope::{RequireRead, RequireWrite, Scope};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::state::AppState;

/// Owning team of an approval lookup result, if any.
fn approval_team_id(lookup: &ApprovalLookup) -> Option<&str> {
    match lookup {
        ApprovalLookup::Pending(p) => p.team_id.as_deref(),
        ApprovalLookup::Resolved(r) => r.team_id.as_deref(),
    }
}

/// Enforce tenant ownership of a single approval for a caller that already
/// cleared the scope gate (AAASM-3790).
///
/// Mirrors `agents::authorize_agent_access`: an admin may act on any approval; a
/// tenant-scoped caller may act only on approvals in its own team; a caller with
/// neither admin scope nor any team scope is denied up front so it cannot
/// enumerate approvals via a 403-vs-404 oracle. On success returns the looked-up
/// record so callers need not look it up twice. Returns 403 for an unauthorized
/// caller, 404 when the approval is unknown to an authorized caller.
fn authorize_approval_access(
    caller: &AuthenticatedCaller,
    state: &AppState,
    uuid: Uuid,
    id: &str,
) -> Result<ApprovalLookup, ProblemDetail> {
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or a team scope"));
    }

    let lookup = state.approval_queue.get_by_id(uuid).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND).with_detail(format!("Approval request not found: {id}"))
    })?;

    let authorized = match approval_team_id(&lookup) {
        Some(team) => caller.can_access_team(team),
        // The approval has no team — only an admin may act on it.
        None => is_admin,
    };
    if !authorized {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or membership in the approval's team"));
    }
    Ok(lookup)
}

/// Parse the path `id` as a UUID and run the write-scope + tenant-ownership
/// guard in one step, returning the parsed id alongside the resolved approval.
/// The get / approve / reject / forward handlers share this exact preamble
/// (AAASM-5095), so it lives here once rather than repeated per handler.
fn parse_and_authorize(
    caller: &AuthenticatedCaller,
    state: &AppState,
    id: &str,
) -> Result<(Uuid, ApprovalLookup), ProblemDetail> {
    let uuid = Uuid::parse_str(id)
        .map_err(|_| ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Invalid UUID: {id}")))?;
    let lookup = authorize_approval_access(caller, state, uuid, id)?;
    Ok((uuid, lookup))
}

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

/// Response state of a single approver in a multi-approver quorum (AAASM-5095).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuorumApproverStatus {
    /// Approver identifier (user id or role) participating in the quorum.
    pub approver: String,
    /// This approver's response so far: `"pending"`, `"approved"`, or
    /// `"rejected"`. Never fabricated — reflects the approver's real recorded
    /// response.
    pub status: String,
}

/// Multi-approver quorum status for an approval request (AAASM-5095).
///
/// Present **only** when the approval is a quorum approval (more than one
/// approver is required). It carries a truthful "`responded` of `required`
/// responded" tally plus the per-approver breakdown — the counts always
/// reflect real approver responses and are never fabricated. Absent
/// (serialized as omitted) for single-target approvals.
///
/// NOTE: full N-approver quorum *enforcement* (gateway-side routing that
/// blocks resolution until the quorum is met) is scoped as a follow-up. This
/// type is the wire contract; until the gateway can supply real per-approver
/// responses the field is emitted as absent rather than with a fabricated
/// count.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct QuorumStatus {
    /// Number of approver responses required to satisfy the quorum (N).
    pub required: u32,
    /// Number of approvers that have responded so far — a real count of the
    /// entries in `approvers` whose status is not `"pending"`. Never a
    /// fabricated value.
    pub responded: u32,
    /// Per-approver response breakdown. Length is the quorum size.
    pub approvers: Vec<QuorumApproverStatus>,
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
    /// Multi-approver quorum status (AAASM-5095). Present only when the
    /// approval is a quorum approval; absent for single-target approvals. When
    /// present the tally reflects real approver responses and is never
    /// fabricated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum: Option<QuorumStatus>,
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
        // Quorum enforcement/routing is a documented AAASM-5095 follow-up; the
        // queue does not yet track per-approver quorum responses, so emit the
        // field as absent rather than fabricate a tally.
        quorum: None,
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
        quorum: None,
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
        (status = 200, description = "Paginated list of approvals", body = PaginatedApprovalResponse)
    ),
    tag = "approvals"
)]
pub async fn list_approvals(
    RequireRead(caller): RequireRead,
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

    // AAASM-3790: confine the listing to approvals the caller's tenant owns.
    // An admin sees every team; a team-scoped caller sees only its own team's
    // approvals; a caller with no team scope (and no admin) sees none. Untagged
    // approvals (no team) are visible only to an admin.
    let all: Vec<ApprovalResponse> = all
        .into_iter()
        .filter(|a| match a.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => caller.scopes.contains(&Scope::Admin),
        })
        .collect();

    let total = all.len();
    let items: Vec<ApprovalResponse> = all
        .into_iter()
        .skip(params.offset())
        .take(params.per_page() as usize)
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedApprovalResponse {
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
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    // AAASM-3790: read-scope + tenant ownership before exposing the approval.
    let resp = match parse_and_authorize(&caller, &state, &id)?.1 {
        ApprovalLookup::Pending(p) => pending_to_response(p),
        ApprovalLookup::Resolved(r) => resolved_to_response(r),
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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<DecideRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    // AAASM-3790: write-scope + tenant ownership before resolving the approval.
    let (uuid, _) = parse_and_authorize(&caller, &state, &id)?;

    // Normalize conditions: drop empty/whitespace-only slugs so an empty or
    // blank list is recorded as an unconditional approval (AAASM-5095).
    let conditions: Vec<String> = body
        .conditions
        .unwrap_or_default()
        .into_iter()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();

    let decision = ApprovalDecision::Approved {
        by: body.by.unwrap_or_else(|| "api".to_string()),
        reason: body.reason,
        conditions,
    };

    // AAASM-5657: `_persisted` so this decision is visible to any other
    // process (e.g. aa-gateway) sharing the durable approval store.
    state
        .approval_queue
        .decide_persisted(uuid, decision)
        .await
        .map_err(|e| match e {
            ApprovalError::AlreadyDecided => ProblemDetail::from_status(StatusCode::CONFLICT)
                .with_detail(format!("Approval request has already been decided: {id}")),
            ApprovalError::NotFound => ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("Approval request not found: {id}")),
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
            quorum: None,
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
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<DecideRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    // AAASM-3790: write-scope + tenant ownership before resolving the approval.
    let (uuid, _) = parse_and_authorize(&caller, &state, &id)?;

    let reason = body.reason.filter(|r| !r.trim().is_empty()).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail("Rejection requires a non-empty reason")
    })?;

    let decision = ApprovalDecision::Rejected {
        by: body.by.unwrap_or_else(|| "api".to_string()),
        reason,
    };

    // AAASM-5657: `_persisted` so this decision is visible to any other
    // process (e.g. aa-gateway) sharing the durable approval store.
    state
        .approval_queue
        .decide_persisted(uuid, decision)
        .await
        .map_err(|e| match e {
            ApprovalError::AlreadyDecided => ProblemDetail::from_status(StatusCode::CONFLICT)
                .with_detail(format!("Approval request has already been decided: {id}")),
            ApprovalError::NotFound => ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("Approval request not found: {id}")),
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
            quorum: None,
        }),
    ))
}

/// `POST /api/v1/approvals/:id/forward` — reassign a pending approval to a
/// different approver (AAASM-5095).
///
/// Forwarding does **not** decide the request: it stays pending so the new
/// target must still approve or reject it. This is a governance action and
/// carries the *same* write-scope + tenant-ownership guard as approve/reject
/// (an operator may only forward approvals in a team it can access, or any
/// approval when it holds admin scope). Returns the still-pending approval on
/// success, 404 when the id is unknown or already resolved (no pending request
/// to forward), and 400 for a missing target or invalid UUID.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}/forward",
    params(("id" = String, Path, description = "Approval request identifier")),
    responses(
        (status = 200, description = "Approval reassigned; still pending", body = ApprovalResponse),
        (status = 400, description = "Missing forward target or invalid UUID"),
        (status = 404, description = "Approval request not found or already resolved")
    ),
    tag = "approvals"
)]
pub async fn forward_action(
    RequireWrite(caller): RequireWrite,
    Extension(state): Extension<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<ForwardRequest>,
) -> Result<(StatusCode, Json<ApprovalResponse>), ProblemDetail> {
    // Same guard as approve/reject: write scope + tenant ownership. Forwarding
    // must not let a caller act on an approval outside its authority.
    let (uuid, _) = parse_and_authorize(&caller, &state, &id)?;

    let to = body.to.trim();
    if to.is_empty() {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("Forwarding requires a non-empty `to` approver target"));
    }

    // `forward` returns false when the request is unknown or already resolved
    // (no pending request to reassign) — surface that as 404.
    if !state.approval_queue.forward(uuid, to) {
        return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("No pending approval request to forward: {id}")));
    }

    // The request is still pending; return its current snapshot so the caller
    // observes the updated routing target.
    let resp = match state.approval_queue.get_by_id(uuid) {
        Some(ApprovalLookup::Pending(p)) => pending_to_response(p),
        // Raced to resolution between forward and lookup — report not found
        // rather than a stale/misleading body.
        _ => {
            return Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("No pending approval request to forward: {id}")))
        }
    };

    Ok((StatusCode::OK, Json(resp)))
}

/// Request body for the forward/reassign action (AAASM-5095).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ForwardRequest {
    /// Approver identifier (user id or role) to reassign the request to.
    pub to: String,
    /// Identity of the operator performing the forward. Optional; recorded for
    /// audit context.
    #[serde(default)]
    pub by: Option<String>,
    /// Optional reason for the reassignment.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Request body for approval decide actions.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DecideRequest {
    /// Identity of the operator making the decision.
    pub by: Option<String>,
    /// Optional reason for the decision.
    pub reason: Option<String>,
    /// Structured approval conditions attached to an approve decision
    /// (AAASM-5095). Each entry is a condition slug such as `"this-once"`,
    /// `"policy-exception"`, or `"time-boxed"`. Ignored on reject. Absent or
    /// empty ⇒ an unconditional approval.
    #[serde(default)]
    pub conditions: Option<Vec<String>>,
}

/// Paginated wire-format envelope for `GET /api/v1/approvals`.
///
/// Mirrors the JSON shape produced by [`PaginatedResponse<ApprovalResponse>`]
/// — `{items, page, per_page, total}` — but is declared as a concrete,
/// non-generic type so utoipa can register it as a named component schema
/// and downstream codegen (the dashboard `openapi-typescript` step) sees
/// a typed envelope rather than a bare array. Introduced to close the
/// drift between the handler's runtime body and the OpenAPI contract
/// flagged by AAASM-1922; the other paginated list endpoints
/// (`list_agents`, `list_alerts`, `list_policies`, `list_logs`) carry the
/// same drift and will be addressed independently.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedApprovalResponse {
    /// Items in the current page.
    pub items: Vec<ApprovalResponse>,
    /// 1-indexed page number echoed from the request.
    pub page: u32,
    /// Items per page echoed from the request.
    pub per_page: u32,
    /// Total number of items across all pages (after filters).
    pub total: u64,
}
