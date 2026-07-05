//! Dashboard analytics aggregation endpoints (AAASM-4141).
//!
//! Seven read-only `GET /api/v1/analytics/*` endpoints that aggregate the
//! gateway's existing in-process data sources (audit log, budget tracker,
//! agent registry, approval queue) into the shapes the dashboard analytics
//! hooks expect (`dashboard/src/features/analytics/*.ts`). No new data source
//! is introduced: every metric is derived from state the API already holds.
//!
//! Each handler carries the same read-scope + tenant guard as the other read
//! routes: authentication is enforced by the `require_authentication` gate on
//! the protected router, and the [`RequireRead`] extractor enforces the read
//! scope. Audit-derived aggregations are additionally confined to the caller's
//! tenant (admin sees all; a tenant-scoped caller sees only its own org),
//! mirroring [`crate::routes::audit`].
//!
//! Several dashboard metrics have no historical time-series source in the
//! current in-process state (the budget tracker and agent registry are
//! point-in-time). Where that is the case the handler returns a well-typed,
//! honestly-shaped response (a single current-value bucket, or a zero value)
//! and documents the v1 definition on the handler rather than fabricating a
//! synthetic series. Those decisions are called out in each handler's doc
//! comment.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/v1/analytics/kpis`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct KpiParams {
    /// KPI to compute: `agents` | `invocations` | `p99` | `cost` | `anomalies`.
    pub metric: Option<String>,
    /// Time range preset (`24h`, `7d`, `30d`, `90d`) or custom
    /// `YYYY-MM-DD..YYYY-MM-DD`. Defaults to `7d`.
    pub range: Option<String>,
    /// Comma-separated agent filter (reserved; not yet applied to KPIs).
    pub agents: Option<String>,
    /// Comma-separated team filter (reserved; not yet applied to KPIs).
    pub teams: Option<String>,
}

/// Query parameters for `GET /api/v1/analytics/cost-breakdown`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct CostBreakdownParams {
    /// Grouping dimension: `agent` | `team` | `model`.
    #[serde(rename = "groupBy")]
    pub group_by: Option<String>,
    /// Time range preset or custom range. See [`KpiParams::range`].
    pub range: Option<String>,
    /// Comma-separated agent filter (reserved).
    pub agents: Option<String>,
    /// Comma-separated team filter (reserved).
    pub teams: Option<String>,
}

/// Query parameters shared by the filter-only analytics endpoints
/// (action-volume, tool-usage, approvals, policy-effectiveness, fleet-health).
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AnalyticsParams {
    /// Time range preset or custom range. See [`KpiParams::range`].
    pub range: Option<String>,
    /// Comma-separated agent filter (reserved).
    pub agents: Option<String>,
    /// Comma-separated team filter (reserved).
    pub teams: Option<String>,
}

// ---------------------------------------------------------------------------
// Response types — kpis
// ---------------------------------------------------------------------------

/// Response for `GET /api/v1/analytics/kpis` — a single scalar KPI plus the
/// fractional change versus the previous equivalent window.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct KpiResponse {
    /// Echo of the requested metric key.
    pub metric: String,
    /// Current value of the metric over the requested window.
    pub value: f64,
    /// Fractional change vs the previous equivalent window
    /// (`0.12` = +12%). `0.0` when no prior window is available.
    pub delta: f64,
    /// Unit hint for the value (e.g. `USD`, `ms`), when meaningful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

// ---------------------------------------------------------------------------
// Response types — cost-breakdown
// ---------------------------------------------------------------------------

/// One stacked segment within a cost bucket (a single agent / team / model).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostSegment {
    /// Stable segment key (agent id hex, team id, or model name).
    pub key: String,
    /// Human-readable segment label.
    pub name: String,
    /// Spend for this segment in USD.
    pub value: f64,
}

/// A single bucket (x-axis position) of the cost-breakdown chart.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostBucket {
    /// Bucket label (the current calendar date for the v1 point-in-time view).
    pub label: String,
    /// Per-dimension spend segments within this bucket.
    pub segments: Vec<CostSegment>,
}

/// Response for `GET /api/v1/analytics/cost-breakdown`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostBreakdownResponse {
    /// Ordered cost buckets. The v1 view emits a single current-day bucket
    /// (the budget tracker exposes point-in-time spend, not a time series).
    pub buckets: Vec<CostBucket>,
}

// ---------------------------------------------------------------------------
// Response types — action-volume
// ---------------------------------------------------------------------------

/// A single time-series point: `t` is epoch milliseconds, `value` the count.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SeriesPoint {
    /// Epoch-millisecond timestamp of the bucket (bucket start).
    pub t: i64,
    /// Aggregated value for the bucket.
    pub value: f64,
}

/// One named series in the action-volume chart (an action category).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActionVolumeSeries {
    /// Stable series key.
    pub key: String,
    /// Human-readable series name.
    pub name: String,
    /// Time-bucketed points for the series.
    pub points: Vec<SeriesPoint>,
}

/// Response for `GET /api/v1/analytics/action-volume`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActionVolumeResponse {
    /// One series per action category (empty when no audit events matched).
    pub series: Vec<ActionVolumeSeries>,
}

// ---------------------------------------------------------------------------
// Response types — tool-usage
// ---------------------------------------------------------------------------

/// Per-tool call statistics.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolStat {
    /// Tool name as recorded in the audit payload.
    pub name: String,
    /// Number of intercepted / dispatched calls in the window.
    pub calls: u64,
    /// Fraction (0.0–1.0) of this tool's calls that were blocked/denied.
    pub error_rate: f64,
}

/// Response for `GET /api/v1/analytics/tool-usage`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ToolUsageResponse {
    /// Per-tool statistics (empty when no tool events carried a tool name).
    pub tools: Vec<ToolStat>,
}

// ---------------------------------------------------------------------------
// Response types — approvals
// ---------------------------------------------------------------------------

/// Resolved-outcome counts for the approvals analytics panel.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApprovalOutcome {
    /// Approvals granted.
    pub approved: u64,
    /// Approvals rejected.
    pub rejected: u64,
    /// Approvals that expired without a decision (`timed_out`).
    pub expired: u64,
}

/// Response for `GET /api/v1/analytics/approvals`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalAnalyticsResponse {
    /// Total resolved approvals in the window (approved + rejected + expired).
    pub volume: u64,
    /// Median time-to-answer in seconds across resolved (non-expired) approvals.
    pub median_tta: f64,
    /// Approval rate = approved / (approved + rejected + expired), `0.0` when none.
    pub approval_rate: f64,
    /// Breakdown by final outcome.
    pub by_outcome: ApprovalOutcome,
}

// ---------------------------------------------------------------------------
// Response types — policy-effectiveness
// ---------------------------------------------------------------------------

/// Per-rule, per-day policy outcome counts.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyDay {
    /// UTC calendar date (`YYYY-MM-DD`).
    pub date: String,
    /// Blocked evaluations (policy violations / denies) for the rule that day.
    pub blocks: u64,
    /// Warned (shadow / dry-run) evaluations for the rule that day.
    pub warns: u64,
    /// Passed (allowed) evaluations for the rule that day.
    pub passes: u64,
}

/// One policy rule's daily effectiveness series.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyRuleStat {
    /// Rule identifier (from the audit payload `policy_rule`).
    pub id: String,
    /// Human-readable rule name (equals the id in v1).
    pub name: String,
    /// Per-day outcome counts, ordered by date ascending.
    pub days: Vec<PolicyDay>,
}

/// Response for `GET /api/v1/analytics/policy-effectiveness`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyEffectivenessResponse {
    /// One entry per policy rule that recorded at least one evaluation.
    pub rules: Vec<PolicyRuleStat>,
}

// ---------------------------------------------------------------------------
// Response types — fleet-health
// ---------------------------------------------------------------------------

/// A single fleet-health sample: `t` epoch milliseconds, `score` 0–100.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HealthPoint {
    /// Epoch-millisecond timestamp of the sample.
    pub t: i64,
    /// Health score in `[0, 100]`.
    pub score: i64,
}

/// One agent's health sparkline.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AgentHealth {
    /// Hex-encoded agent id.
    pub id: String,
    /// Display name (metadata `name`, falling back to the id).
    pub name: String,
    /// Health samples. The v1 view emits a single current sample per agent
    /// (the registry exposes point-in-time status, not a health time series).
    pub points: Vec<HealthPoint>,
}

/// Response for `GET /api/v1/analytics/fleet-health`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct FleetHealthResponse {
    /// One entry per agent the caller may see.
    pub agents: Vec<AgentHealth>,
}

// Shared helpers and the seven handlers follow in subsequent commits.
