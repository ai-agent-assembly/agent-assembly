//! Audit log query endpoints.

use aa_core::AuditEventType;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::auth::scope::{RequireRead, Scope};
use crate::pagination::PaginationParams;
use crate::state::AppState;

/// Category of an audit log entry, mirroring [`aa_core::AuditEventType`].
///
/// AAASM-5221 — constrains the [`LogEntry::event_type`] wire vocabulary to the
/// closed set of labels [`AuditEventType::as_str`] emits, so the generated
/// OpenAPI spec advertises an enum rather than a free-form `string`. Variants
/// serialize verbatim (PascalCase), matching the strings the audit log has
/// always written, so the wire shape is unchanged.
///
/// Kept in lock-step with `AuditEventType`: the [`From`] impl is exhaustive, so
/// adding an audit variant without extending this enum is a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum LogEventType {
    ToolCallIntercepted,
    PolicyViolation,
    CredentialLeakBlocked,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalDenied,
    BudgetLimitApproached,
    BudgetLimitExceeded,
    ApprovalTimedOut,
    ApprovalRouted,
    ApprovalEscalated,
    AgentForceDeregistered,
    MessageBlocked,
    ToolDispatched,
    A2ACallIntercepted,
    A2AImpersonationAttempted,
    SandboxStarted,
    SandboxFilesystemBlocked,
    SandboxCpuTimeout,
    SandboxOomKilled,
    SandboxTerminated,
    SandboxHostFnRateLimited,
    GovernanceMutation,
}

impl From<AuditEventType> for LogEventType {
    fn from(t: AuditEventType) -> Self {
        match t {
            AuditEventType::ToolCallIntercepted => LogEventType::ToolCallIntercepted,
            AuditEventType::PolicyViolation => LogEventType::PolicyViolation,
            AuditEventType::CredentialLeakBlocked => LogEventType::CredentialLeakBlocked,
            AuditEventType::ApprovalRequested => LogEventType::ApprovalRequested,
            AuditEventType::ApprovalGranted => LogEventType::ApprovalGranted,
            AuditEventType::ApprovalDenied => LogEventType::ApprovalDenied,
            AuditEventType::BudgetLimitApproached => LogEventType::BudgetLimitApproached,
            AuditEventType::BudgetLimitExceeded => LogEventType::BudgetLimitExceeded,
            AuditEventType::ApprovalTimedOut => LogEventType::ApprovalTimedOut,
            AuditEventType::ApprovalRouted => LogEventType::ApprovalRouted,
            AuditEventType::ApprovalEscalated => LogEventType::ApprovalEscalated,
            AuditEventType::AgentForceDeregistered => LogEventType::AgentForceDeregistered,
            AuditEventType::MessageBlocked => LogEventType::MessageBlocked,
            AuditEventType::ToolDispatched => LogEventType::ToolDispatched,
            AuditEventType::A2ACallIntercepted => LogEventType::A2ACallIntercepted,
            AuditEventType::A2AImpersonationAttempted => LogEventType::A2AImpersonationAttempted,
            AuditEventType::SandboxStarted => LogEventType::SandboxStarted,
            AuditEventType::SandboxFilesystemBlocked => LogEventType::SandboxFilesystemBlocked,
            AuditEventType::SandboxCpuTimeout => LogEventType::SandboxCpuTimeout,
            AuditEventType::SandboxOomKilled => LogEventType::SandboxOomKilled,
            AuditEventType::SandboxTerminated => LogEventType::SandboxTerminated,
            AuditEventType::SandboxHostFnRateLimited => LogEventType::SandboxHostFnRateLimited,
            AuditEventType::GovernanceMutation => LogEventType::GovernanceMutation,
        }
    }
}

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
    pub event_type: LogEventType,
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

/// Paginated `GET /api/v1/logs` body (AAASM-4892) — a named wrapper so the
/// OpenAPI schema `$ref`s `LogEntry` and matches the `{ items, total }` object
/// the handler serializes, not a bare array.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedLogResponse {
    /// Audit log entries in the current page.
    pub items: Vec<LogEntry>,
    /// 1-indexed page number echoed from the request.
    pub page: u32,
    /// Items per page echoed from the request.
    pub per_page: u32,
    /// Total entries matching the filter across all pages.
    pub total: u64,
}

/// `GET /api/v1/logs` — paginated audit log query.
///
/// Query the paginated audit log of governance events.
/// Supports optional filtering by agent ID and event type.
///
/// Per-tenant scoping (AAASM-3483): the audit log is per-tenant data. An admin
/// caller may read any org's audit (honouring an explicit `?org_id`); a
/// tenant-scoped caller has the `org_id` filter forced to its own org, so it
/// can neither read another org's audit nor omit the filter to enumerate every
/// org. A non-admin caller with no org scope receives an empty page rather than
/// a cross-tenant dump.
#[utoipa::path(
    get,
    path = "/api/v1/logs",
    params(PaginationParams, LogFilterParams),
    responses(
        (status = 200, description = "Paginated audit log entries", body = PaginatedLogResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "logs"
)]
pub async fn list_logs(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
    axum::extract::Query(filters): axum::extract::Query<LogFilterParams>,
) -> impl IntoResponse {
    let limit = params.per_page() as usize;
    let offset = params.offset();

    // AAASM-3483 — bind the `org_id` filter to the caller's tenant. An admin
    // honours the caller-supplied `?org_id`; a tenant-scoped caller is forced to
    // its own org; a non-admin with no org scope is given a sentinel that the
    // `AuditReader` org filter never matches (entries with `org_id = None` never
    // match an explicit filter), yielding an empty page instead of every org's
    // audit.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let effective_org: Option<&str> = if is_admin {
        filters.org_id.as_deref()
    } else {
        Some(caller.tenant.org_id.as_deref().unwrap_or("\0__no_tenant_scope__"))
    };

    let (entries, total) = state
        .audit_reader
        .list(
            limit,
            offset,
            filters.agent_id.as_deref(),
            filters.event_type.as_deref(),
            effective_org,
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
                event_type: LogEventType::from(e.event_type()),
                payload: e.payload().to_string(),
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(PaginatedLogResponse {
            items,
            page: params.page(),
            per_page: params.per_page(),
            total,
        }),
    )
}
