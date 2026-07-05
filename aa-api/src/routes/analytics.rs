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

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::audit::AuditEventType;
use aa_core::AuditEntry;
use aa_gateway::AgentRecord;

use crate::auth::scope::{RequireRead, Scope};
use crate::auth::AuthenticatedCaller;
use crate::state::AppState;

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

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Resolve a dashboard range filter to a window length in seconds.
///
/// Accepts the presets `24h` / `7d` / `30d` / `90d` and custom
/// `YYYY-MM-DD..YYYY-MM-DD` ranges (inclusive of both endpoints). Any
/// unrecognised or absent value falls back to the `7d` default the dashboard
/// uses.
fn window_secs_from_range(range: Option<&str>) -> u64 {
    const DAY: u64 = 86_400;
    match range {
        Some("24h") => DAY,
        Some("7d") => 7 * DAY,
        Some("30d") => 30 * DAY,
        Some("90d") => 90 * DAY,
        Some(custom) if custom.contains("..") => parse_custom_range(custom).unwrap_or(7 * DAY),
        _ => 7 * DAY,
    }
}

/// Parse a `YYYY-MM-DD..YYYY-MM-DD` custom range into an inclusive window in
/// seconds. Returns `None` for malformed input or an inverted range.
fn parse_custom_range(s: &str) -> Option<u64> {
    let (start, end) = s.split_once("..")?;
    let start = chrono::NaiveDate::parse_from_str(start.trim(), "%Y-%m-%d").ok()?;
    let end = chrono::NaiveDate::parse_from_str(end.trim(), "%Y-%m-%d").ok()?;
    let days = (end - start).num_days();
    if days < 0 {
        return None;
    }
    Some((days as u64 + 1) * 86_400)
}

/// Current wall-clock time in epoch nanoseconds.
fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Map an audit event type to the action-volume series it contributes to, or
/// `None` for event types the chart does not track.
fn action_category(ev: AuditEventType) -> Option<(&'static str, &'static str)> {
    match ev {
        AuditEventType::ToolCallIntercepted => Some(("intercepted", "Intercepted")),
        AuditEventType::ToolDispatched => Some(("dispatched", "Dispatched")),
        AuditEventType::PolicyViolation => Some(("violations", "Policy Violations")),
        AuditEventType::ApprovalRequested => Some(("approvals", "Approvals Requested")),
        _ => None,
    }
}

/// Confine a set of audit entries to the caller's tenant.
///
/// Mirrors [`crate::routes::audit`]: an admin sees every org's entries; a
/// tenant-scoped caller sees only its own org; a non-admin caller with no org
/// scope sees nothing (rather than a cross-tenant dump).
fn scope_entries(caller: &AuthenticatedCaller, entries: Vec<AuditEntry>) -> Vec<AuditEntry> {
    if caller.scopes.contains(&Scope::Admin) {
        return entries;
    }
    match caller.tenant.org_id.as_deref() {
        Some(org) => entries.into_iter().filter(|e| e.org_id() == Some(org)).collect(),
        None => Vec::new(),
    }
}

/// Fetch audit entries at or after `since_ns`, confined to the caller's tenant.
///
/// Reads the full JSONL log via [`AuditReader::list`] and filters by timestamp;
/// the in-process reader holds the same entries the other audit aggregations
/// read, so no new data source is introduced.
async fn fetch_window_entries(caller: &AuthenticatedCaller, state: &AppState, since_ns: u64) -> Vec<AuditEntry> {
    let (entries, _total) = state
        .audit_reader
        .list(usize::MAX, 0, None, None, None)
        .await
        .unwrap_or_default();
    let entries: Vec<AuditEntry> = entries.into_iter().filter(|e| e.timestamp_ns() >= since_ns).collect();
    scope_entries(caller, entries)
}

/// Agents the caller may see: admin sees all; a tenant-scoped caller sees only
/// its own team's agents; a caller with no team scope sees none. Matches the
/// tenant posture the cost and approval read routes apply.
fn visible_agents(caller: &AuthenticatedCaller, state: &AppState) -> Vec<AgentRecord> {
    let all = state.agent_registry.list();
    if caller.scopes.contains(&Scope::Admin) {
        return all;
    }
    all.into_iter()
        .filter(|r| match r.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => false,
        })
        .collect()
}

/// Fractional change of `cur` versus `prev`; `0.0` when there is no prior
/// window to compare against.
fn delta_ratio(cur: u64, prev: u64) -> f64 {
    if prev == 0 {
        0.0
    } else {
        (cur as f64 - prev as f64) / prev as f64
    }
}

/// Count audit entries in the half-open window `[lo, hi)` whose event type is a
/// tool invocation (`ToolCallIntercepted` or `ToolDispatched`).
fn count_invocations(entries: &[AuditEntry], lo: u64, hi: u64) -> u64 {
    entries
        .iter()
        .filter(|e| {
            let t = e.timestamp_ns();
            t >= lo
                && t < hi
                && matches!(
                    e.event_type(),
                    AuditEventType::ToolCallIntercepted | AuditEventType::ToolDispatched
                )
        })
        .count() as u64
}

/// Count `PolicyViolation` audit entries in the half-open window `[lo, hi)`.
fn count_violations(entries: &[AuditEntry], lo: u64, hi: u64) -> u64 {
    entries
        .iter()
        .filter(|e| {
            let t = e.timestamp_ns();
            t >= lo && t < hi && matches!(e.event_type(), AuditEventType::PolicyViolation)
        })
        .count() as u64
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/analytics/kpis` — a single scalar KPI plus its window-over-window delta.
///
/// v1 metric definitions (documented because several are not uniquely
/// determined by the available in-process state):
///
/// * `agents` — number of registered agents the caller may see (registry is
///   point-in-time, so `delta` is always `0.0`).
/// * `invocations` — count of `ToolCallIntercepted` + `ToolDispatched` audit
///   events in the window; `delta` compares against the immediately preceding
///   equal-length window.
/// * `cost` — current daily spend (USD) from the budget tracker snapshot
///   (point-in-time; `delta` is `0.0`, `unit` = `USD`).
/// * `anomalies` — count of `PolicyViolation` audit events in the window (the
///   closest available signal to an anomaly); `delta` is window-over-window.
/// * `p99` — request-tail latency. **No latency source exists** in the
///   in-process audit/budget state, so this honestly returns `0.0` (`unit` =
///   `ms`) rather than a fabricated value.
///
/// Audit-derived metrics are confined to the caller's tenant; registry/budget
/// metrics use the same visibility rules as the cost route.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/kpis",
    params(KpiParams),
    responses(
        (status = 200, description = "KPI value and window-over-window delta", body = KpiResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_kpis(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<KpiParams>,
) -> (StatusCode, Json<KpiResponse>) {
    let window = window_secs_from_range(params.range.as_deref());
    let metric = params.metric.unwrap_or_else(|| "invocations".to_string());

    let now = now_ns();
    let window_ns = window.saturating_mul(1_000_000_000);
    let since = now.saturating_sub(window_ns);
    let prev_since = since.saturating_sub(window_ns);

    let (value, delta, unit) = match metric.as_str() {
        "agents" => (visible_agents(&caller, &state).len() as f64, 0.0, None),
        "cost" => {
            let spent = state
                .budget_tracker
                .snapshot()
                .global
                .spent_usd
                .to_string()
                .parse::<f64>()
                .unwrap_or(0.0);
            (spent, 0.0, Some("USD".to_string()))
        }
        "invocations" => {
            let entries = fetch_window_entries(&caller, &state, prev_since).await;
            let cur = count_invocations(&entries, since, now);
            let prev = count_invocations(&entries, prev_since, since);
            (cur as f64, delta_ratio(cur, prev), None)
        }
        "anomalies" => {
            let entries = fetch_window_entries(&caller, &state, prev_since).await;
            let cur = count_violations(&entries, since, now);
            let prev = count_violations(&entries, prev_since, since);
            (cur as f64, delta_ratio(cur, prev), None)
        }
        // No request-latency source exists — report zero honestly.
        "p99" => (0.0, 0.0, Some("ms".to_string())),
        // Unknown metric: echo it back with a zero value rather than 400,
        // matching the tolerant filter behaviour of the other read routes.
        _ => (0.0, 0.0, None),
    };

    (
        StatusCode::OK,
        Json(KpiResponse {
            metric,
            value,
            delta,
            unit,
        }),
    )
}

/// `GET /api/v1/analytics/cost-breakdown` — stacked spend broken down by a dimension.
///
/// The budget tracker exposes **point-in-time** spend (today's totals per agent
/// and per team), not a time series, so the v1 response emits a single bucket
/// labelled with the current budget date. Grouping:
///
/// * `agent` (default) — one segment per agent, from the budget snapshot's
///   per-agent breakdown. Only an admin sees the per-agent rows (they are not
///   team-keyed, so exposing them to a tenant caller would leak other tenants'
///   agents — same rule the `/costs` route applies).
/// * `team` — one segment per team; an admin sees every team, a tenant-scoped
///   caller sees only its own team's row.
/// * `model` — **no per-model spend source exists** in the budget tracker, so
///   this returns an empty bucket list rather than fabricated segments.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/cost-breakdown",
    params(CostBreakdownParams),
    responses(
        (status = 200, description = "Cost broken down into stacked segments", body = CostBreakdownResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_cost_breakdown(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<CostBreakdownParams>,
) -> (StatusCode, Json<CostBreakdownResponse>) {
    let group_by = params.group_by.as_deref().unwrap_or("agent");
    let snapshot = state.budget_tracker.snapshot();
    let is_admin = caller.scopes.contains(&Scope::Admin);
    let caller_team = caller.tenant.team_id.as_deref();
    let label = snapshot.global.date.to_string();

    let segments: Vec<CostSegment> = match group_by {
        "team" => {
            let mut rows: Vec<CostSegment> = snapshot
                .team_budgets
                .iter()
                .filter(|(team, _)| is_admin || caller_team == Some(team.as_str()))
                .map(|(team, st)| CostSegment {
                    key: team.clone(),
                    name: team.clone(),
                    value: st.spent_usd.to_string().parse::<f64>().unwrap_or(0.0),
                })
                .collect();
            rows.sort_by(|a, b| a.key.cmp(&b.key));
            rows
        }
        // No per-model spend is tracked by the budget engine.
        "model" => Vec::new(),
        // Default: group by agent. Per-agent rows are admin-only (not team-keyed).
        _ => {
            if is_admin {
                snapshot
                    .per_agent
                    .iter()
                    .map(|e| CostSegment {
                        key: e.agent_id_hex.clone(),
                        name: e.agent_id_hex.clone(),
                        value: e.state.spent_usd.to_string().parse::<f64>().unwrap_or(0.0),
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
    };

    let buckets = if segments.is_empty() {
        Vec::new()
    } else {
        vec![CostBucket { label, segments }]
    };

    (StatusCode::OK, Json(CostBreakdownResponse { buckets }))
}

/// Number of time buckets the action-volume / series endpoints divide a window
/// into. Fixed count (not a fixed width) so every range renders a comparable
/// line density.
const SERIES_BUCKETS: usize = 24;

/// `GET /api/v1/analytics/action-volume` — action counts over time, per category.
///
/// Buckets the requested window into [`SERIES_BUCKETS`] equal slices and counts
/// audit events per slice, grouped into a small set of action categories
/// (`intercepted`, `dispatched`, `violations`, `approvals` — see
/// [`action_category`]). Each emitted series carries a point for every bucket
/// (including zeros) so the line chart is continuous; `t` is the bucket-start
/// epoch-millisecond timestamp. Only categories that recorded at least one
/// event in the window are emitted, so an idle window yields an empty series
/// list rather than fabricated activity. Confined to the caller's tenant.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/action-volume",
    params(AnalyticsParams),
    responses(
        (status = 200, description = "Per-category action-volume time series", body = ActionVolumeResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_action_volume(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<AnalyticsParams>,
) -> (StatusCode, Json<ActionVolumeResponse>) {
    let window = window_secs_from_range(params.range.as_deref());
    let now = now_ns();
    let window_ns = window.saturating_mul(1_000_000_000);
    let since = now.saturating_sub(window_ns);
    let bucket_ns = (window_ns / SERIES_BUCKETS as u64).max(1);

    let entries = fetch_window_entries(&caller, &state, since).await;

    // category key -> (display name, per-bucket counts)
    let mut by_category: BTreeMap<&'static str, (&'static str, Vec<u64>)> = BTreeMap::new();
    for e in &entries {
        if let Some((key, name)) = action_category(e.event_type()) {
            let idx = ((e.timestamp_ns().saturating_sub(since)) / bucket_ns) as usize;
            let idx = idx.min(SERIES_BUCKETS - 1);
            let slot = by_category
                .entry(key)
                .or_insert_with(|| (name, vec![0u64; SERIES_BUCKETS]));
            slot.1[idx] += 1;
        }
    }

    let series: Vec<ActionVolumeSeries> = by_category
        .into_iter()
        .map(|(key, (name, counts))| ActionVolumeSeries {
            key: key.to_string(),
            name: name.to_string(),
            points: counts
                .into_iter()
                .enumerate()
                .map(|(i, c)| SeriesPoint {
                    t: ((since + i as u64 * bucket_ns) / 1_000_000) as i64,
                    value: c as f64,
                })
                .collect(),
        })
        .collect();

    (StatusCode::OK, Json(ActionVolumeResponse { series }))
}

/// Extract a tool identifier from an audit payload, trying the explicit `tool`
/// / `tool_name` keys first and falling back to the policy `action_type` label
/// (the closest grouping key the gateway records for evaluated actions).
fn extract_tool_name(payload: &serde_json::Value) -> Option<String> {
    for key in ["tool", "tool_name", "action_type"] {
        if let Some(s) = payload.get(key).and_then(|v| v.as_str()) {
            if !s.is_empty() {
                return Some(s.to_string());
            }
        }
    }
    None
}

/// Whether an audit payload's policy `decision` represents a blocked/denied
/// outcome (anything other than an explicit allow). A missing decision is
/// treated as a success.
fn decision_is_error(payload: &serde_json::Value) -> bool {
    match payload.get("decision").and_then(|v| v.as_str()) {
        Some(d) => !d.eq_ignore_ascii_case("allow"),
        None => false,
    }
}

/// `GET /api/v1/analytics/tool-usage` — per-tool call counts and error rate.
///
/// Aggregates `ToolCallIntercepted` / `ToolDispatched` audit events in the
/// window by tool identifier (see [`extract_tool_name`]). `calls` is the event
/// count; `errorRate` is the fraction whose policy `decision` was not an allow
/// (see [`decision_is_error`]) — the v1 definition of a failed tool call.
/// Events whose payload carries no resolvable tool name are skipped, so a
/// window with no tool activity returns an empty list rather than a synthetic
/// tool. Confined to the caller's tenant.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/tool-usage",
    params(AnalyticsParams),
    responses(
        (status = 200, description = "Per-tool call statistics", body = ToolUsageResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_tool_usage(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<AnalyticsParams>,
) -> (StatusCode, Json<ToolUsageResponse>) {
    let window = window_secs_from_range(params.range.as_deref());
    let now = now_ns();
    let since = now.saturating_sub(window.saturating_mul(1_000_000_000));

    let entries = fetch_window_entries(&caller, &state, since).await;

    // tool name -> (call count, error count)
    let mut by_tool: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for e in &entries {
        if !matches!(
            e.event_type(),
            AuditEventType::ToolCallIntercepted | AuditEventType::ToolDispatched
        ) {
            continue;
        }
        let payload: serde_json::Value = match serde_json::from_str(e.payload()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(name) = extract_tool_name(&payload) else {
            continue;
        };
        let slot = by_tool.entry(name).or_insert((0, 0));
        slot.0 += 1;
        if decision_is_error(&payload) {
            slot.1 += 1;
        }
    }

    let tools: Vec<ToolStat> = by_tool
        .into_iter()
        .map(|(name, (calls, errors))| ToolStat {
            name,
            calls,
            error_rate: if calls == 0 { 0.0 } else { errors as f64 / calls as f64 },
        })
        .collect();

    (StatusCode::OK, Json(ToolUsageResponse { tools }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_presets_resolve_to_expected_windows() {
        assert_eq!(window_secs_from_range(Some("24h")), 86_400);
        assert_eq!(window_secs_from_range(Some("7d")), 604_800);
        assert_eq!(window_secs_from_range(Some("30d")), 2_592_000);
        assert_eq!(window_secs_from_range(Some("90d")), 7_776_000);
    }

    #[test]
    fn range_defaults_to_seven_days_when_absent_or_unknown() {
        assert_eq!(window_secs_from_range(None), 604_800);
        assert_eq!(window_secs_from_range(Some("bogus")), 604_800);
    }

    #[test]
    fn custom_range_is_inclusive_of_both_endpoints() {
        // 2026-01-01 .. 2026-01-07 spans 7 calendar days inclusive.
        assert_eq!(window_secs_from_range(Some("2026-01-01..2026-01-07")), 7 * 86_400);
    }

    #[test]
    fn custom_range_rejects_inverted_or_malformed() {
        assert_eq!(window_secs_from_range(Some("2026-01-07..2026-01-01")), 604_800);
        assert_eq!(parse_custom_range("not-a-range"), None);
        assert_eq!(parse_custom_range("2026-13-01..2026-13-02"), None);
    }

    #[test]
    fn delta_ratio_is_zero_without_a_prior_window() {
        assert_eq!(delta_ratio(5, 0), 0.0);
        assert_eq!(delta_ratio(0, 0), 0.0);
    }

    #[test]
    fn delta_ratio_computes_fractional_change() {
        assert_eq!(delta_ratio(12, 10), 0.2);
        assert_eq!(delta_ratio(8, 10), -0.2);
    }
}
