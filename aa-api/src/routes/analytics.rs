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

use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::Query;
use axum::http::StatusCode;
use axum::{Extension, Json};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::audit::AuditEventType;
use aa_core::{AgentId, AuditEntry};
use aa_gateway::{AgentRecord, AgentStatus};

use crate::models::topology::format_id;

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

/// Upper bound on the number of audit events a single analytics request pulls
/// from the audit log.
///
/// [`AuditReader::list_windowed`] returns entries newest-first, so this caps
/// each analytics aggregation to the most recent `MAX_ANALYTICS_AUDIT_EVENTS`
/// events within the query's time window — bounding per-request work instead of
/// the former unbounded `usize::MAX` full-log read (AAASM-4145). The ceiling is
/// high enough that realistic dashboard windows are never truncated, yet fixed
/// so a growing log can't turn one analytics call into an unbounded scan. A
/// window holding more than the cap counts only its most recent events.
const MAX_ANALYTICS_AUDIT_EVENTS: usize = 100_000;

/// Fetch audit entries at or after `since_ns`, confined to the caller's tenant.
///
/// Pushes the `since_ns` window into [`AuditReader::list_windowed`] so entries
/// older than the window are dropped during the directory scan and never
/// collected (AAASM-4147) — no client-side timestamp re-filter is needed. The
/// read stays bounded by [`MAX_ANALYTICS_AUDIT_EVENTS`] (AAASM-4145): a window
/// with more events than the cap aggregates only its most recent ones. The
/// in-process reader holds the same entries the other audit aggregations read,
/// so no new data source is introduced.
async fn fetch_window_entries(caller: &AuthenticatedCaller, state: &AppState, since_ns: u64) -> Vec<AuditEntry> {
    let (entries, _total) = state
        .audit_reader
        .list_windowed(since_ns, MAX_ANALYTICS_AUDIT_EVENTS, 0, None, None, None)
        .await
        .unwrap_or_default();
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
///
/// The gateway writes `decision` as the proto [`Decision`] enum's **integer**
/// discriminant (see `record_audit` in `aa-gateway` and `build_payload` in
/// `aa-runtime`), not a string — so this reads it as an integer and compares
/// against `Decision::Allow` rather than a case-insensitive `"allow"` string,
/// which never matched the emitted payload (AAASM-5035).
fn decision_is_error(payload: &serde_json::Value) -> bool {
    use aa_proto::assembly::common::v1::Decision;
    match payload.get("decision").and_then(|v| v.as_i64()) {
        Some(d) => d != Decision::Allow as i64,
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

/// Format an epoch-nanosecond timestamp as a `YYYY-MM-DD` UTC calendar date.
fn utc_date(ts_ns: u64) -> String {
    let secs = (ts_ns / 1_000_000_000) as i64;
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.date_naive().to_string())
        .unwrap_or_default()
}

/// `GET /api/v1/analytics/policy-effectiveness` — per-rule daily outcome counts.
///
/// Groups audit events that carry a non-empty `policy_rule` by rule and by UTC
/// day, classifying each into the v1 buckets:
///
/// * `warns` — the evaluation was a shadow / dry-run (`dry_run: true`).
/// * `blocks` — a `PolicyViolation` event, or a non-dry-run evaluation whose
///   `decision` was not an allow.
/// * `passes` — a non-dry-run evaluation whose `decision` was an allow (or that
///   recorded no explicit decision).
///
/// The rule `name` equals its id in v1 (the audit log records only the rule
/// identifier). Rules with no recorded evaluations produce no entry, so an idle
/// window returns an empty rule list. Confined to the caller's tenant.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/policy-effectiveness",
    params(AnalyticsParams),
    responses(
        (status = 200, description = "Per-rule daily policy effectiveness", body = PolicyEffectivenessResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_policy_effectiveness(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<AnalyticsParams>,
) -> (StatusCode, Json<PolicyEffectivenessResponse>) {
    let window = window_secs_from_range(params.range.as_deref());
    let now = now_ns();
    let since = now.saturating_sub(window.saturating_mul(1_000_000_000));

    let entries = fetch_window_entries(&caller, &state, since).await;

    // rule id -> (date -> (blocks, warns, passes)). BTreeMaps keep both the
    // rules and the per-rule days in stable ascending order.
    let mut by_rule: BTreeMap<String, BTreeMap<String, (u64, u64, u64)>> = BTreeMap::new();
    for e in &entries {
        let payload: serde_json::Value = match serde_json::from_str(e.payload()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let rule = match payload.get("policy_rule").and_then(|v| v.as_str()) {
            Some(r) if !r.is_empty() => r.to_string(),
            _ => continue,
        };
        let date = utc_date(e.timestamp_ns());
        let day = by_rule.entry(rule).or_default().entry(date).or_insert((0, 0, 0));

        let dry_run = payload.get("dry_run").and_then(|v| v.as_bool()).unwrap_or(false);
        if dry_run {
            day.1 += 1;
        } else if matches!(e.event_type(), AuditEventType::PolicyViolation) {
            day.0 += 1;
        } else {
            // The gateway writes `decision` as the proto `Decision` enum's
            // integer discriminant, not a string (AAASM-5035) — read it as an
            // integer and compare against `Decision::Allow`, so a non-allow
            // outcome is counted as a block instead of silently passing (the
            // old `as_str()` reader never matched the emitted payload).
            let allow = aa_proto::assembly::common::v1::Decision::Allow as i64;
            match payload.get("decision").and_then(|v| v.as_i64()) {
                Some(d) if d != allow => day.0 += 1,
                _ => day.2 += 1,
            }
        }
    }

    let rules: Vec<PolicyRuleStat> = by_rule
        .into_iter()
        .map(|(id, days_map)| PolicyRuleStat {
            name: id.clone(),
            id,
            days: days_map
                .into_iter()
                .map(|(date, (blocks, warns, passes))| PolicyDay {
                    date,
                    blocks,
                    warns,
                    passes,
                })
                .collect(),
        })
        .collect();

    (StatusCode::OK, Json(PolicyEffectivenessResponse { rules }))
}

/// Median of a slice of durations (seconds); `0.0` for an empty slice. Sorts in
/// place.
fn median_secs(values: &mut [u64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable();
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2] as f64
    } else {
        (values[n / 2 - 1] as f64 + values[n / 2] as f64) / 2.0
    }
}

/// `GET /api/v1/analytics/approvals` — resolved-approval volume, rate and latency.
///
/// Aggregates the approval queue's resolved history over records whose decision
/// timestamp falls in the window, confined to the caller's tenant (admin sees
/// all teams; a tenant-scoped caller sees only its own team; untagged records
/// are admin-only — matching the `/approvals` list route). `byOutcome` splits
/// approved / rejected / `timed_out` (expired); `volume` is their sum;
/// `approvalRate` = approved / volume; `medianTta` is the median time-to-answer
/// in seconds across decided (non-expired) approvals.
#[utoipa::path(
    get,
    path = "/api/v1/analytics/approvals",
    params(AnalyticsParams),
    responses(
        (status = 200, description = "Approval volume, rate and latency", body = ApprovalAnalyticsResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_approvals(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<AnalyticsParams>,
) -> (StatusCode, Json<ApprovalAnalyticsResponse>) {
    let window = window_secs_from_range(params.range.as_deref());
    let now_secs = now_ns() / 1_000_000_000;
    let since_secs = now_secs.saturating_sub(window);
    let is_admin = caller.scopes.contains(&Scope::Admin);

    let mut approved = 0u64;
    let mut rejected = 0u64;
    let mut expired = 0u64;
    let mut ttas: Vec<u64> = Vec::new();

    for r in state.approval_queue.list_resolved(None, None) {
        // Window filter on the decision timestamp.
        if r.decided_at < since_secs || r.decided_at > now_secs {
            continue;
        }
        // Tenant filter mirroring the /approvals list route.
        let visible = match r.team_id.as_deref() {
            Some(team) => caller.can_access_team(team),
            None => is_admin,
        };
        if !visible {
            continue;
        }
        match r.status.as_str() {
            "approved" => {
                approved += 1;
                ttas.push(r.decided_at.saturating_sub(r.submitted_at));
            }
            "rejected" => {
                rejected += 1;
                ttas.push(r.decided_at.saturating_sub(r.submitted_at));
            }
            "timed_out" => expired += 1,
            _ => {}
        }
    }

    let volume = approved + rejected + expired;
    let approval_rate = if volume == 0 {
        0.0
    } else {
        approved as f64 / volume as f64
    };

    (
        StatusCode::OK,
        Json(ApprovalAnalyticsResponse {
            volume,
            median_tta: median_secs(&mut ttas),
            approval_rate,
            by_outcome: ApprovalOutcome {
                approved,
                rejected,
                expired,
            },
        }),
    )
}

/// Current wall-clock time in epoch milliseconds (JS `Date` convention, which
/// the dashboard sparkline axes format directly).
fn now_ms() -> i64 {
    (now_ns() / 1_000_000) as i64
}

/// Map an agent's registry status to a v1 health score in `[0, 100]`.
fn health_score(status: &AgentStatus) -> i64 {
    match status {
        AgentStatus::Active => 100,
        AgentStatus::Suspended(_) => 40,
        AgentStatus::Deregistered => 0,
    }
}

/// `GET /api/v1/analytics/fleet-health` — per-agent health sparklines.
///
/// The registry exposes point-in-time status, not a health time series, so the
/// v1 view emits a single current sample per agent: `score` = 100 when Active,
/// 40 when Suspended, 0 when Deregistered (see [`health_score`]), stamped with
/// the current epoch-millisecond time. Scoped to the agents the caller may see
/// (admin sees all; a tenant-scoped caller sees only its own team's agents).
#[utoipa::path(
    get,
    path = "/api/v1/analytics/fleet-health",
    params(AnalyticsParams),
    responses(
        (status = 200, description = "Per-agent health sparklines", body = FleetHealthResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_fleet_health(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(_params): Query<AnalyticsParams>,
) -> (StatusCode, Json<FleetHealthResponse>) {
    let t = now_ms();
    let agents: Vec<AgentHealth> = visible_agents(&caller, &state)
        .into_iter()
        .map(|r| {
            let id = hex::encode(r.agent_id);
            let name = if r.name.is_empty() { id.clone() } else { r.name };
            AgentHealth {
                id,
                name,
                points: vec![HealthPoint {
                    t,
                    score: health_score(&r.status),
                }],
            }
        })
        .collect();

    (StatusCode::OK, Json(FleetHealthResponse { agents }))
}

// ---------------------------------------------------------------------------
// enforcement-timeline — windowed decision counts by verdict (AAASM-5031)
// ---------------------------------------------------------------------------

/// Query parameters for `GET /api/v1/overview/enforcement-timeline`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct EnforcementTimelineParams {
    /// Recent window to summarise: `1h` | `24h` | `7d` | `30d`. Defaults to
    /// `24h`; any unrecognised value also falls back to `24h`.
    pub window: Option<String>,
}

/// One time bucket of the enforcement timeline: decision counts by verdict.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EnforcementBucket {
    /// Bucket-start timestamp, epoch milliseconds.
    pub ts: i64,
    /// Permitted decisions (`ToolCallIntercepted` = proto `Decision::ALLOW`).
    pub allow: u64,
    /// Held-for-approval decisions (`ApprovalRequested` = proto `Decision::PENDING`).
    pub narrow: u64,
    /// Blocked decisions (`PolicyViolation` = proto `Decision::DENY`).
    pub deny: u64,
    /// Credential/secret redactions (`CredentialLeakBlocked` = proto `Decision::REDACT`).
    pub scrub: u64,
}

/// Response for `GET /api/v1/overview/enforcement-timeline`.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnforcementTimelineResponse {
    /// Echo of the resolved window preset (`1h` | `24h` | `7d` | `30d`).
    pub window: String,
    /// Width of each bucket in seconds (`window / 24`).
    pub bucket_secs: i64,
    /// Ordered buckets, oldest first — always [`SERIES_BUCKETS`] of them,
    /// including empty buckets, so the timeline renders a continuous axis.
    pub buckets: Vec<EnforcementBucket>,
}

/// The four verdict lanes the enforcement timeline tracks.
enum Verdict {
    Allow,
    Narrow,
    Deny,
    Scrub,
}

/// Resolve a timeline window filter to `(canonical-label, seconds)`.
///
/// The dashboard offers `1h` / `24h` / `7d` / `30d`; any unrecognised or absent
/// value falls back to the `24h` default the Overview header uses. Kept separate
/// from [`window_secs_from_range`] because the timeline's preset set differs
/// (it offers `1h`, not `90d`, and defaults to `24h` rather than `7d`).
fn resolve_window(window: Option<&str>) -> (&'static str, u64) {
    const HOUR: u64 = 3_600;
    const DAY: u64 = 86_400;
    match window {
        Some("1h") => ("1h", HOUR),
        Some("7d") => ("7d", 7 * DAY),
        Some("30d") => ("30d", 30 * DAY),
        _ => ("24h", DAY),
    }
}

/// Map an audit event type onto the timeline verdict lane it contributes to, or
/// `None` for event types the timeline does not track.
///
/// Mirrors the gateway write path `decision_to_event_type_from_response`
/// (`aa-gateway/src/service/policy_service.rs`), which records each proto
/// `Decision` as a distinct `AuditEventType`: `Allow→ToolCallIntercepted`,
/// `Pending→ApprovalRequested`, `Deny→PolicyViolation`,
/// `Redact→CredentialLeakBlocked`. So counting those four discriminants
/// reconstructs the verdict distribution without a new data source.
fn timeline_verdict(ev: AuditEventType) -> Option<Verdict> {
    match ev {
        AuditEventType::ToolCallIntercepted => Some(Verdict::Allow),
        AuditEventType::ApprovalRequested => Some(Verdict::Narrow),
        AuditEventType::PolicyViolation => Some(Verdict::Deny),
        AuditEventType::CredentialLeakBlocked => Some(Verdict::Scrub),
        _ => None,
    }
}

/// Bucket `entries` into [`SERIES_BUCKETS`] equal slices across the half-open
/// window `[since_ns, since_ns + window_ns)`, tallying each entry into its
/// verdict lane. Always returns exactly [`SERIES_BUCKETS`] buckets (including
/// empty ones). Entries older than `since_ns` are ignored; anything at or past
/// the final slice is clamped into it.
fn bucket_enforcement(entries: &[AuditEntry], since_ns: u64, window_ns: u64) -> Vec<EnforcementBucket> {
    let bucket_ns = (window_ns / SERIES_BUCKETS as u64).max(1);
    let mut buckets: Vec<EnforcementBucket> = (0..SERIES_BUCKETS)
        .map(|i| EnforcementBucket {
            ts: ((since_ns + i as u64 * bucket_ns) / 1_000_000) as i64,
            allow: 0,
            narrow: 0,
            deny: 0,
            scrub: 0,
        })
        .collect();

    for e in entries {
        let Some(verdict) = timeline_verdict(e.event_type()) else {
            continue;
        };
        let t = e.timestamp_ns();
        if t < since_ns {
            continue;
        }
        let idx = (((t - since_ns) / bucket_ns) as usize).min(SERIES_BUCKETS - 1);
        let bucket = &mut buckets[idx];
        match verdict {
            Verdict::Allow => bucket.allow += 1,
            Verdict::Narrow => bucket.narrow += 1,
            Verdict::Deny => bucket.deny += 1,
            Verdict::Scrub => bucket.scrub += 1,
        }
    }

    buckets
}

/// `GET /api/v1/overview/enforcement-timeline` — decision counts over time by verdict.
///
/// Buckets the requested window into [`SERIES_BUCKETS`] equal slices and counts
/// audit-recorded enforcement decisions per slice into four verdict lanes —
/// `allow` / `narrow` / `deny` / `scrub` — derived from the [`AuditEventType`]
/// the gateway writes for each proto `Decision` (see [`timeline_verdict`]). This
/// is read-only observability over the existing audit log: no enforcement
/// semantics are touched and no new data source is introduced. Every bucket is
/// emitted (including zeros) so the dashboard timeline renders a continuous
/// axis. Confined to the caller's tenant.
#[utoipa::path(
    get,
    path = "/api/v1/overview/enforcement-timeline",
    params(EnforcementTimelineParams),
    responses(
        (status = 200, description = "Windowed enforcement decision counts by verdict", body = EnforcementTimelineResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "analytics"
)]
pub async fn get_enforcement_timeline(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<EnforcementTimelineParams>,
) -> (StatusCode, Json<EnforcementTimelineResponse>) {
    let (window_label, window_secs) = resolve_window(params.window.as_deref());
    let now = now_ns();
    let window_ns = window_secs.saturating_mul(1_000_000_000);
    let since = now.saturating_sub(window_ns);

    let entries = fetch_window_entries(&caller, &state, since).await;
    let buckets = bucket_enforcement(&entries, since, window_ns);

    (
        StatusCode::OK,
        Json(EnforcementTimelineResponse {
            window: window_label.to_string(),
            bucket_secs: (window_secs / SERIES_BUCKETS as u64) as i64,
            buckets,
        }),
    )
}

// ---------------------------------------------------------------------------
// costs/history — trailing daily spend series (AAASM-5032)
// ---------------------------------------------------------------------------

/// Default and maximum length of the cost-history window, in calendar days.
const COST_HISTORY_DEFAULT_DAYS: u32 = 7;
const COST_HISTORY_MAX_DAYS: u32 = 90;

/// Query parameters for `GET /api/v1/costs/history`.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct CostHistoryParams {
    /// Trailing calendar days to return. Defaults to 7; clamped to 1..=90 so a
    /// single request can never ask for an unbounded series.
    pub days: Option<u32>,
}

/// One calendar day of the spend-history series.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostHistoryPoint {
    /// Calendar date (YYYY-MM-DD, in the tracker's timezone) for this bucket.
    pub date: String,
    /// Total spend recorded on this date in USD, serialized as a decimal string
    /// so money precision is never lost to float rounding (mirrors `/costs`).
    pub spend_usd: String,
}

/// Response for `GET /api/v1/costs/history`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CostHistoryResponse {
    /// Number of days in the returned series (the resolved, clamped `days`).
    pub days: u32,
    /// Daily spend buckets, oldest first, dense (zero-filled) across the window.
    pub points: Vec<CostHistoryPoint>,
}

/// `GET /api/v1/costs/history` — trailing daily spend series.
///
/// Aggregates the budget tracker's per-agent daily spend history into a single
/// dense (zero-filled), oldest-first series over the last `days` days. The set
/// of agents summed is exactly the caller's visible set ([`visible_agents`]):
/// an admin gets the org-wide total, a tenant-scoped caller gets only its own
/// team's total, and an unscoped non-admin caller gets an all-zero series —
/// so the same endpoint serves every scope without leaking cross-tenant spend.
/// Read-only observability over data the tracker already holds; no enforcement
/// or budget-debit path is touched. The history is in-memory (see
/// `BudgetTracker::spend_history_totals_for`) and resets on gateway restart.
#[utoipa::path(
    get,
    path = "/api/v1/costs/history",
    params(CostHistoryParams),
    responses(
        (status = 200, description = "Trailing daily spend history", body = CostHistoryResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "costs"
)]
pub async fn get_cost_history(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<CostHistoryParams>,
) -> (StatusCode, Json<CostHistoryResponse>) {
    let days = params
        .days
        .unwrap_or(COST_HISTORY_DEFAULT_DAYS)
        .clamp(1, COST_HISTORY_MAX_DAYS);
    let agent_ids: Vec<AgentId> = visible_agents(&caller, &state)
        .into_iter()
        .map(|r| AgentId::from_bytes(r.agent_id))
        .collect();
    let points = state
        .budget_tracker
        .spend_history_totals_for(&agent_ids, days)
        .into_iter()
        .map(|(date, spend)| CostHistoryPoint {
            date: date.to_string(),
            spend_usd: spend.to_string(),
        })
        .collect();

    (StatusCode::OK, Json(CostHistoryResponse { days, points }))
}

// ---------------------------------------------------------------------------
// costs/budget-tree — org → team → agent budget inheritance (AAASM-5032)
// ---------------------------------------------------------------------------

/// One node in the budget-inheritance tree.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BudgetTreeNode {
    /// Stable node id: the org id, the team id, or the hex agent id.
    pub id: String,
    /// Human-readable label: org/team id, or the agent's registered name.
    pub label: String,
    /// Node tier: `org` | `team` | `agent`.
    pub kind: String,
    /// Depth from the org root (org = 0, team = 1, agents from 2 and deeper).
    pub depth: u32,
    /// Configured daily budget limit in USD for this node, if any (decimal
    /// string). Agent nodes fall back to the global limit when they carry no
    /// per-agent override, mirroring the enforcement path's resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_limit_usd: Option<String>,
    /// Spend attributable to this node itself, excluding descendants (USD
    /// string). Org and team nodes never spend directly, so this is `"0"`.
    pub own_spend_usd: String,
    /// Spend across this node and its entire subtree (USD string) — the figure a
    /// parent's budget constrains.
    pub subtree_spend_usd: String,
    /// Governance level for agent nodes (e.g. `L0Discover`), read from the
    /// registry record; absent for org/team nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub governance_level: Option<String>,
    /// Child nodes: teams under the org, root agents under a team, spawned
    /// sub-agents under an agent.
    #[schema(schema_with = budget_tree_children_schema)]
    pub children: Vec<BudgetTreeNode>,
}

/// Returns a schema for `Vec<BudgetTreeNode>` using a `$ref` to break the
/// recursive cycle — without it utoipa's `ToSchema` derive recurses infinitely
/// and overflows the stack (mirrors `models::topology::AgentTree`).
fn budget_tree_children_schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{ArrayBuilder, Ref};
    ArrayBuilder::new()
        .items(Ref::from_schema_name("BudgetTreeNode"))
        .build()
        .into()
}

/// Response for `GET /api/v1/costs/budget-tree`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct BudgetTreeResponse {
    /// Org root of the inheritance tree, or `null` when the caller can see no
    /// tenant (an unscoped non-admin caller) so the client renders an empty state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<BudgetTreeNode>,
}

/// Build an agent node and, recursively, its spawned sub-agents.
///
/// Recursion is confined to the `visible` id set so the walk never crosses into
/// another tenant's subtree — the same per-node boundary re-check the topology
/// tree enforces (AAASM-4819). `own_spend` is the agent's own accrued spend;
/// `subtree_spend` rolls in every visible descendant.
fn build_agent_node(state: &AppState, record: &AgentRecord, depth: u32, visible: &HashSet<[u8; 16]>) -> BudgetTreeNode {
    let agent_id = AgentId::from_bytes(record.agent_id);
    let own_spend = state
        .budget_tracker
        .agent_state(&agent_id)
        .map(|s| s.spent_usd)
        .unwrap_or(Decimal::ZERO);
    let descendants: Vec<[u8; 16]> = state
        .agent_registry
        .descendants_of(&record.agent_id)
        .into_iter()
        .filter(|d| visible.contains(d))
        .collect();
    let subtree_spend = state.budget_tracker.subtree_spend(&agent_id, &descendants).usd;
    let budget_limit = state
        .budget_tracker
        .agent_daily_limit_usd(&agent_id)
        .or_else(|| state.budget_tracker.daily_limit_usd());
    let children: Vec<BudgetTreeNode> = state
        .agent_registry
        .children_of(&record.agent_id)
        .into_iter()
        .filter(|c| visible.contains(c))
        .filter_map(|c| state.agent_registry.get(&c))
        .map(|child| build_agent_node(state, &child, depth + 1, visible))
        .collect();

    BudgetTreeNode {
        id: format_id(&record.agent_id),
        label: record.name.clone(),
        kind: "agent".to_string(),
        depth,
        budget_limit_usd: budget_limit.map(|d| d.to_string()),
        own_spend_usd: own_spend.to_string(),
        subtree_spend_usd: subtree_spend.to_string(),
        governance_level: Some(format!("{:?}", record.governance_level)),
        children,
    }
}

/// `GET /api/v1/costs/budget-tree` — org → team → agent budget inheritance tree.
///
/// Joins the agent registry's team/lineage structure with the budget tracker's
/// per-tier spend so each node shows its configured limit, own spend, and the
/// subtree spend a parent's budget constrains. Tenant scope is the visible-agent
/// boundary ([`visible_agents`]): an admin sees the whole org; a tenant-scoped
/// caller sees only its team's subtree; an unscoped non-admin caller gets a
/// `null` root. Within the visible set, an agent is a team-level root when its
/// spawn parent is not itself visible, and its spawned sub-agents nest beneath
/// it (they inherit its budget line) — so every visible agent appears exactly
/// once. Read-only: no enforcement or budget-debit path is touched.
#[utoipa::path(
    get,
    path = "/api/v1/costs/budget-tree",
    responses(
        (status = 200, description = "Org → team → agent budget-inheritance tree", body = BudgetTreeResponse),
        (status = 401, description = "Missing or invalid credentials")
    ),
    tag = "costs"
)]
pub async fn get_budget_tree(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<BudgetTreeResponse>) {
    let records = visible_agents(&caller, &state);
    if records.is_empty() {
        return (StatusCode::OK, Json(BudgetTreeResponse { root: None }));
    }
    let visible: HashSet<[u8; 16]> = records.iter().map(|r| r.agent_id).collect();

    // Team roots: visible agents whose spawn parent is not visible. Every other
    // visible agent is reached by recursion from one of these, so the tree is a
    // clean partition (no agent appears twice). Group roots by their own team.
    let mut team_roots: BTreeMap<String, Vec<AgentRecord>> = BTreeMap::new();
    for r in &records {
        let is_root = match r.parent_key {
            Some(parent) => !visible.contains(&parent),
            None => true,
        };
        if is_root {
            let team = r.team_id.clone().unwrap_or_else(|| "(no team)".to_string());
            team_roots.entry(team).or_default().push(r.clone());
        }
    }

    let team_nodes: Vec<BudgetTreeNode> = team_roots
        .into_iter()
        .map(|(team_id, roots)| {
            let children: Vec<BudgetTreeNode> =
                roots.iter().map(|r| build_agent_node(&state, r, 2, &visible)).collect();
            let subtree: Decimal = children
                .iter()
                .filter_map(|c| c.subtree_spend_usd.parse::<Decimal>().ok())
                .sum();
            let budget_limit = state.budget_tracker.team_daily_limit_usd();
            BudgetTreeNode {
                id: team_id.clone(),
                label: team_id,
                kind: "team".to_string(),
                depth: 1,
                budget_limit_usd: budget_limit.map(|d| d.to_string()),
                own_spend_usd: Decimal::ZERO.to_string(),
                subtree_spend_usd: subtree.to_string(),
                governance_level: None,
                children,
            }
        })
        .collect();

    let org_subtree: Decimal = team_nodes
        .iter()
        .filter_map(|t| t.subtree_spend_usd.parse::<Decimal>().ok())
        .sum();
    let org_id = caller.tenant.org_id.clone().unwrap_or_else(|| "org".to_string());
    let org_limit = state
        .budget_tracker
        .org_daily_limit_usd()
        .or_else(|| state.budget_tracker.daily_limit_usd());

    let root = BudgetTreeNode {
        id: org_id.clone(),
        label: org_id,
        kind: "org".to_string(),
        depth: 0,
        budget_limit_usd: org_limit.map(|d| d.to_string()),
        own_spend_usd: Decimal::ZERO.to_string(),
        subtree_spend_usd: org_subtree.to_string(),
        governance_level: None,
        children: team_nodes,
    };

    (StatusCode::OK, Json(BudgetTreeResponse { root: Some(root) }))
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

    /// AAASM-4147: `fetch_window_entries` now pushes the `since_ns` window into
    /// the reader (`list_windowed`) instead of over-reading then client-filtering.
    /// For a window inside the data the result must be exactly the in-window
    /// entries — identical to the pre-change `list()`-then-`>= since` behaviour —
    /// so analytics aggregations are unaffected.
    #[tokio::test]
    async fn fetch_window_entries_returns_only_in_window_entries() {
        use aa_core::audit::Lineage;
        use aa_core::{AgentId, SessionId};
        use aa_gateway::AuditReader;
        use std::sync::Arc;

        fn entry(seq: u64, ts: u64) -> AuditEntry {
            AuditEntry::new_with_lineage(
                seq,
                ts,
                AuditEventType::ToolCallIntercepted,
                AgentId::from_bytes([0xAB; 16]),
                SessionId::from_bytes([0xEE; 16]),
                "{}".to_string(),
                [0u8; 32],
                Lineage::default(),
            )
        }

        // Seed a temp audit dir: two entries older than the window, two within.
        let dir = std::env::temp_dir().join(format!("aa-4147-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create audit dir");
        let entries = [entry(0, 100), entry(1, 200), entry(2, 300), entry(3, 400)];
        let mut contents = String::new();
        for e in &entries {
            contents.push_str(&serde_json::to_string(e).unwrap());
            contents.push('\n');
        }
        std::fs::write(dir.join("audit.jsonl"), contents).expect("write jsonl");

        let mut state = AppState::local_in_memory().expect("state builds");
        state.audit_reader = Arc::new(AuditReader::new(dir.clone()));

        // Admin caller so tenant scoping is the identity and can't mask the window.
        let caller = AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: crate::auth::Tenant {
                team_id: None,
                org_id: None,
            },
        };

        let since = 300;
        let got = fetch_window_entries(&caller, &state, since).await;

        let mut seqs: Vec<u64> = got.iter().map(|e| e.seq()).collect();
        seqs.sort_unstable();
        assert_eq!(seqs, vec![2, 3], "only entries with timestamp_ns >= since are returned");

        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn analytics_audit_read_is_bounded_not_unbounded() {
        // AAASM-4145: the analytics handlers must cap the audit-log read rather
        // than pull the whole log (`usize::MAX`) per request. `black_box` keeps
        // this a runtime check so a regression to an unbounded read is caught.
        let cap = std::hint::black_box(MAX_ANALYTICS_AUDIT_EVENTS);
        assert!(cap < usize::MAX, "analytics audit read must be bounded, not usize::MAX");
        assert_eq!(cap, 100_000);
    }

    // --- enforcement-timeline (AAASM-5031) ---------------------------------

    fn tl_entry(ts: u64, ev: AuditEventType) -> AuditEntry {
        use aa_core::audit::Lineage;
        use aa_core::{AgentId, SessionId};
        AuditEntry::new_with_lineage(
            0,
            ts,
            ev,
            AgentId::from_bytes([0x11; 16]),
            SessionId::from_bytes([0x22; 16]),
            "{}".to_string(),
            [0u8; 32],
            Lineage::default(),
        )
    }

    #[test]
    fn resolve_window_presets_and_default() {
        assert_eq!(resolve_window(Some("1h")), ("1h", 3_600));
        assert_eq!(resolve_window(Some("24h")), ("24h", 86_400));
        assert_eq!(resolve_window(Some("7d")), ("7d", 604_800));
        assert_eq!(resolve_window(Some("30d")), ("30d", 2_592_000));
        // Absent or unrecognised falls back to the 24h Overview default.
        assert_eq!(resolve_window(None), ("24h", 86_400));
        assert_eq!(resolve_window(Some("bogus")), ("24h", 86_400));
    }

    #[test]
    fn timeline_verdict_maps_recorded_decision_event_types() {
        assert!(matches!(
            timeline_verdict(AuditEventType::ToolCallIntercepted),
            Some(Verdict::Allow)
        ));
        assert!(matches!(
            timeline_verdict(AuditEventType::ApprovalRequested),
            Some(Verdict::Narrow)
        ));
        assert!(matches!(
            timeline_verdict(AuditEventType::PolicyViolation),
            Some(Verdict::Deny)
        ));
        assert!(matches!(
            timeline_verdict(AuditEventType::CredentialLeakBlocked),
            Some(Verdict::Scrub)
        ));
        // An event type outside the four verdict lanes contributes to none.
        assert!(timeline_verdict(AuditEventType::ToolDispatched).is_none());
    }

    #[test]
    fn bucket_enforcement_always_emits_full_bucket_count() {
        let buckets = bucket_enforcement(&[], 0, 24 * 1_000_000_000);
        assert_eq!(buckets.len(), SERIES_BUCKETS);
        assert!(buckets
            .iter()
            .all(|b| b.allow == 0 && b.narrow == 0 && b.deny == 0 && b.scrub == 0));
    }

    #[test]
    fn bucket_enforcement_tallies_each_verdict_into_its_slice() {
        let bucket_ns: u64 = 1_000_000_000;
        let window_ns: u64 = SERIES_BUCKETS as u64 * bucket_ns;
        let entries = [
            tl_entry(0, AuditEventType::ToolCallIntercepted), // bucket 0 allow
            tl_entry(bucket_ns / 2, AuditEventType::ToolCallIntercepted), // bucket 0 allow
            tl_entry(bucket_ns, AuditEventType::ApprovalRequested), // bucket 1 narrow
            tl_entry(2 * bucket_ns, AuditEventType::PolicyViolation), // bucket 2 deny
            tl_entry(3 * bucket_ns, AuditEventType::CredentialLeakBlocked), // bucket 3 scrub
            tl_entry(5 * bucket_ns, AuditEventType::ToolDispatched), // untracked -> ignored
        ];
        let buckets = bucket_enforcement(&entries, 0, window_ns);
        assert_eq!(buckets[0].allow, 2);
        assert_eq!(buckets[1].narrow, 1);
        assert_eq!(buckets[2].deny, 1);
        assert_eq!(buckets[3].scrub, 1);
        assert_eq!(
            buckets[5].allow + buckets[5].narrow + buckets[5].deny + buckets[5].scrub,
            0,
            "untracked event type must not be counted"
        );
        // `ts` is the bucket-start timestamp in epoch milliseconds.
        assert_eq!(buckets[0].ts, 0);
        assert_eq!(buckets[1].ts, (bucket_ns / 1_000_000) as i64);
    }

    #[test]
    fn bucket_enforcement_drops_pre_window_and_clamps_post_window() {
        let bucket_ns: u64 = 1_000_000_000;
        let window_ns: u64 = SERIES_BUCKETS as u64 * bucket_ns;
        let since: u64 = bucket_ns;
        let before = tl_entry(since - 1, AuditEventType::PolicyViolation);
        let after = tl_entry(since + window_ns + 5, AuditEventType::PolicyViolation);
        let buckets = bucket_enforcement(&[before, after], since, window_ns);
        let total_deny: u64 = buckets.iter().map(|b| b.deny).sum();
        assert_eq!(total_deny, 1, "pre-window entry dropped, post-window entry clamped in");
        assert_eq!(buckets[SERIES_BUCKETS - 1].deny, 1);
    }

    // --- tool-usage error classification (AAASM-5035) ----------------------

    /// AAASM-5035: the gateway writes the audit `decision` field as the proto
    /// `Decision` enum's integer discriminant, not a string. `decision_is_error`
    /// must read that integer — the old `as_str()` reader never matched, so every
    /// tool call was silently classified as a success.
    #[test]
    fn decision_is_error_reads_integer_discriminant() {
        use aa_proto::assembly::common::v1::Decision;
        // Payload shaped exactly as the gateway emits it (integer decision).
        let allow = serde_json::json!({ "action_type": "shell", "decision": Decision::Allow as i32 });
        let deny = serde_json::json!({ "action_type": "shell", "decision": Decision::Deny as i32 });
        let pending = serde_json::json!({ "action_type": "shell", "decision": Decision::Pending as i32 });
        let redact = serde_json::json!({ "action_type": "shell", "decision": Decision::Redact as i32 });
        assert!(!decision_is_error(&allow), "an allow is not an error");
        assert!(decision_is_error(&deny), "a deny is an error");
        assert!(decision_is_error(&pending), "a held decision is an error");
        assert!(decision_is_error(&redact), "a redact is an error");
        // A missing decision stays a success (unchanged contract).
        assert!(!decision_is_error(&serde_json::json!({ "action_type": "shell" })));
        // Regression guard: a *string* "allow" (the old on-wire assumption) is
        // not what the gateway writes and must not be silently treated as allow.
        let stringy = serde_json::json!({ "action_type": "shell", "decision": "allow" });
        assert!(
            !decision_is_error(&stringy),
            "a non-integer decision is absent -> treated as success, not a false allow-match"
        );
    }

    /// End-to-end regression through `get_tool_usage`: seed audit events exactly
    /// as the gateway writes them (integer `decision`) and assert the per-tool
    /// error rate reflects the denied calls. Under the pre-fix string reader the
    /// error rate collapsed to `0.0` regardless of the real decisions.
    #[tokio::test]
    async fn get_tool_usage_classifies_errors_from_integer_decision() {
        use aa_core::audit::Lineage;
        use aa_core::{AgentId, SessionId};
        use aa_gateway::AuditReader;
        use aa_proto::assembly::common::v1::Decision;
        use std::sync::Arc;

        // One dispatched tool event, payload shaped as the gateway emits it: a
        // string `action_type` (the tool-name fallback) and an integer `decision`.
        fn event(seq: u64, ts: u64, decision: Decision) -> AuditEntry {
            let payload = serde_json::json!({
                "action_type": "shell",
                "decision": decision as i32,
                "reason": "",
                "policy_rule": "",
                "latency_us": 0,
            })
            .to_string();
            AuditEntry::new_with_lineage(
                seq,
                ts,
                AuditEventType::ToolDispatched,
                AgentId::from_bytes([0xAB; 16]),
                SessionId::from_bytes([0xEE; 16]),
                payload,
                [0u8; 32],
                Lineage::default(),
            )
        }

        // Stamp events at "now" so they land inside the default 7d window.
        let now = now_ns();
        let entries = [
            event(0, now, Decision::Allow),
            event(1, now, Decision::Deny),
            event(2, now, Decision::Allow),
            event(3, now, Decision::Deny),
        ];

        let dir = std::env::temp_dir().join(format!("aa-5035-toolusage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create audit dir");
        let mut contents = String::new();
        for e in &entries {
            contents.push_str(&serde_json::to_string(e).unwrap());
            contents.push('\n');
        }
        std::fs::write(dir.join("audit.jsonl"), contents).expect("write jsonl");

        let mut state = AppState::local_in_memory().expect("state builds");
        state.audit_reader = Arc::new(AuditReader::new(dir.clone()));

        let caller = AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: crate::auth::Tenant {
                team_id: None,
                org_id: None,
            },
        };

        let (status, Json(resp)) = get_tool_usage(
            RequireRead(caller),
            Extension(state),
            Query(AnalyticsParams {
                range: None,
                agents: None,
                teams: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.tools.len(), 1, "single tool aggregated");
        let tool = &resp.tools[0];
        assert_eq!(tool.name, "shell");
        assert_eq!(tool.calls, 4);
        // Two of four decisions were a Deny -> error_rate 0.5. The pre-fix string
        // reader would have produced 0.0 here.
        assert_eq!(tool.error_rate, 0.5, "denied calls are counted as errors");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// End-to-end regression through `get_policy_effectiveness`: the non-dry-run
    /// `blocks`-vs-`passes` split reads the audit `decision` field, which the
    /// gateway writes as the proto `Decision` integer discriminant (AAASM-5035).
    /// A non-`PolicyViolation` event carrying a non-allow decision (here a
    /// `Redact`) must land in `blocks`; under the pre-fix string reader its
    /// integer decision never matched and it was silently counted as a `pass`.
    #[tokio::test]
    async fn get_policy_effectiveness_classifies_blocks_from_integer_decision() {
        use aa_core::audit::Lineage;
        use aa_core::{AgentId, SessionId};
        use aa_gateway::AuditReader;
        use aa_proto::assembly::common::v1::Decision;
        use std::sync::Arc;

        // Audit entry shaped as the gateway writes it: a `policy_rule` string and
        // an integer `decision`. `dry_run` is only emitted on shadow evaluations.
        fn event(seq: u64, ts: u64, ev: AuditEventType, decision: Decision, dry_run: bool) -> AuditEntry {
            let mut payload = serde_json::json!({
                "action_type": "shell",
                "decision": decision as i32,
                "policy_rule": "rule-x",
            });
            if dry_run {
                payload["dry_run"] = serde_json::Value::Bool(true);
            }
            AuditEntry::new_with_lineage(
                seq,
                ts,
                ev,
                AgentId::from_bytes([0xAB; 16]),
                SessionId::from_bytes([0xEE; 16]),
                payload.to_string(),
                [0u8; 32],
                Lineage::default(),
            )
        }

        // Same UTC day so all three land in one `PolicyDay` bucket.
        let now = now_ns();
        let entries = [
            // Allow, non-dry-run -> pass.
            event(0, now, AuditEventType::ToolCallIntercepted, Decision::Allow, false),
            // Redact, non-dry-run, NOT a PolicyViolation -> block *only* via the
            // integer decision comparison (the crux of this regression).
            event(1, now, AuditEventType::CredentialLeakBlocked, Decision::Redact, false),
            // Dry-run -> warn, regardless of decision.
            event(2, now, AuditEventType::ToolCallIntercepted, Decision::Allow, true),
        ];

        let dir = std::env::temp_dir().join(format!("aa-5035-policyeff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create audit dir");
        let mut contents = String::new();
        for e in &entries {
            contents.push_str(&serde_json::to_string(e).unwrap());
            contents.push('\n');
        }
        std::fs::write(dir.join("audit.jsonl"), contents).expect("write jsonl");

        let mut state = AppState::local_in_memory().expect("state builds");
        state.audit_reader = Arc::new(AuditReader::new(dir.clone()));

        let caller = AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes: vec![Scope::Admin],
            tenant: crate::auth::Tenant {
                team_id: None,
                org_id: None,
            },
        };

        let (status, Json(resp)) = get_policy_effectiveness(
            RequireRead(caller),
            Extension(state),
            Query(AnalyticsParams {
                range: None,
                agents: None,
                teams: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(resp.rules.len(), 1, "single rule aggregated");
        let rule = &resp.rules[0];
        assert_eq!(rule.id, "rule-x");
        assert_eq!(rule.days.len(), 1, "all events share one UTC day");
        let day = &rule.days[0];
        // block from the Redact decision, pass from the Allow, warn from dry-run.
        // The pre-fix string reader would have yielded blocks=0, passes=2.
        assert_eq!(day.blocks, 1, "non-allow decision counted as a block");
        assert_eq!(day.passes, 1, "the allow decision counted as a pass");
        assert_eq!(day.warns, 1, "the dry-run evaluation counted as a warn");

        std::fs::remove_dir_all(&dir).ok();
    }
}
