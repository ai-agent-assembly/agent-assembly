//! Sensitive-data analytics and drill-down over the durable projection
//! (AAASM-5359, ADR 0032 §8/§9).
//!
//! # What these endpoints read
//!
//! Every handler here queries the
//! [`SensitiveDataProjection`](aa_gateway::storage::sensitive_data::SensitiveDataProjection)
//! that AAASM-5357 landed and AAASM-5440 writes — a durable, tenant-keyed,
//! time-indexed table. Nothing here re-scans the audit JSONL per request, and
//! nothing here is subject to the fixed 100 000-event ceiling that makes
//! `GET /api/v1/analytics/agent-enforcement` under-report a busy tenant without
//! saying so. The **time window is the bound**: an aggregate reads every row in
//! the window, because a governance counter that silently stops counting is
//! worse than a slow one, and a caller that wants less asks for a shorter
//! window.
//!
//! # Tenancy
//!
//! There is no unscoped read. The storage filter takes a
//! [`TenantScope`](aa_gateway::storage::sensitive_data::TenantScope) by value,
//! and [`resolve_scope`] is the only thing that builds one: it takes the org
//! from the **verified caller** and accepts a request-supplied `org_id` only
//! after [`AuthenticatedCaller::can_access_org`] agrees. A tenant-scoped caller
//! naming another org is refused with 403, not answered with an empty list —
//! an empty list is indistinguishable from "that tenant has no data", which
//! leaks the same fact more quietly.
//!
//! # What is never in a response
//!
//! ADR 0032 §9: no raw values, no byte offsets, no lengths, no fingerprints.
//! The projection's row types carry none of those by construction, and the DTOs
//! below are built field-by-field from them rather than by re-serializing a row,
//! so a column added upstream cannot appear here without someone adding it.
//! Field **paths** are permitted and are the drill-down granularity §9 grants in
//! place of offsets.
//!
//! # Labels versus filters — the distinction §9 turns on
//!
//! `agent_id`, `destination`, `session_id` and `trace_id` are forbidden as
//! **metric labels** and are exactly right as **queryable event-store
//! dimensions**. So they are accepted as filters, returned as drill-down
//! columns, and used as the grouping key of `/top-offenders` — which is a
//! ranked list over the event store, not a time series — while
//! [`MetricDimension`] (the only thing `/breakdown` will group by) admits none
//! of them.

mod access_log;
mod metrics;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::time::Timestamp;
use aa_gateway::storage::sensitive_data::{
    SensitiveDataEventFilter, SensitiveDataEventRow, SensitiveDataFindingRow, TenantScope,
};

use crate::auth::scope::{RequireAdmin, RequireRead};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::state::AppState;

pub use access_log::{ExportAccessLog, ExportAccessRecord, InMemoryExportAccessLog};
pub use metrics::{group_findings, DimensionBucket, MetricDimension, SensitiveDataCounters, SensitiveDataRates};

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// The filter every sensitive-data read accepts.
///
/// `from`/`to` (RFC 3339) win over `range` when both are supplied; `range`
/// reuses the analytics presets so a dashboard can pass the same value it
/// passes everywhere else.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SensitiveDataFilterParams {
    /// Organisation to read. Optional for a tenant-scoped caller (its own org
    /// is used); **required** for a cross-tenant admin, because there is no
    /// unscoped read to fall back to.
    pub org_id: Option<String>,
    /// Time-range preset (`24h`, `7d`, `30d`, `90d`) or `YYYY-MM-DD..YYYY-MM-DD`.
    /// Defaults to `7d`. Ignored when `from`/`to` are given.
    pub range: Option<String>,
    /// Inclusive lower bound, RFC 3339.
    pub from: Option<String>,
    /// Exclusive upper bound, RFC 3339.
    pub to: Option<String>,
    /// Restrict to one acting agent. A drill-down dimension, never a metric label.
    pub agent_id: Option<String>,
    /// Restrict to one delegation-root agent.
    pub root_agent_id: Option<String>,
    /// Restrict to one team.
    pub team_id: Option<String>,
    /// Restrict to one tool — a destination whose kind is `tool`.
    pub tool: Option<String>,
    /// Restrict to one destination of any kind.
    pub destination: Option<String>,
    /// Restrict to one operation kind (`tool_call`, `network_egress`, …).
    pub operation: Option<String>,
    /// Restrict to one enforcement outcome (`allow`, `narrow`, `scrub`,
    /// `pending`, `deny`).
    pub outcome: Option<String>,
    /// Restrict to one policy document.
    pub policy_document_id: Option<String>,
    /// Restrict to events carrying a finding of this category.
    pub category: Option<String>,
    /// Restrict to events carrying a finding from this recognizer.
    pub provider: Option<String>,
    /// Restrict to events carrying a finding in this confidence band.
    pub confidence: Option<String>,
    /// Restrict to events carrying a finding in this triage status.
    pub status: Option<String>,
    /// Restrict to events carrying a finding of this severity.
    pub severity: Option<String>,
    /// Restrict to events carrying a finding produced by this detection method.
    pub detection_method: Option<String>,
    /// Maximum rows on the **list** surfaces. Aggregates are never capped.
    pub limit: Option<u32>,
}

/// `group_by` for `/breakdown`, on top of the shared filter.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BreakdownParams {
    /// Which bounded dimension to group by. Defaults to `category`. Only ADR
    /// 0032 §9's six labels are accepted — anything else is a 400.
    pub group_by: Option<String>,
}

/// `bucket` for `/timeseries`, on top of the shared filter.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimeseriesParams {
    /// Bucket width: `1h`, `6h`, `1d` or `7d`. Defaults to `1d`.
    pub bucket: Option<String>,
}

/// `dimension` for `/top-offenders`, on top of the shared filter.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TopOffendersParams {
    /// Rank by `agent`, `tool` or `destination`. Defaults to `agent`.
    pub dimension: Option<String>,
}

/// The explicit authorisation the compliance export requires.
#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportParams {
    /// Must be `true`. An export is a deliberate act with a recorded principal,
    /// so it is not something a caller performs by navigating to a URL — the
    /// admin scope says *who may*, this says *this one, on purpose*.
    pub acknowledge_export: Option<bool>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// The window and tenant a response describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct QueryScope {
    /// Organisation read.
    pub org_id: String,
    /// Tenant read.
    pub tenant_id: String,
    /// Inclusive lower bound, epoch nanoseconds.
    pub from_ns: u64,
    /// Exclusive upper bound, epoch nanoseconds.
    pub to_ns: u64,
}

/// Response for `GET /api/v1/sensitive-data/summary`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataSummaryResponse {
    /// What was read.
    pub scope: QueryScope,
    /// The ADR 0032 §8 counters.
    pub counters: SensitiveDataCounters,
    /// The derived ratios. Absent rather than zero where undefined.
    pub rates: SensitiveDataRates,
    /// Findings grouped by category, highest first.
    pub by_category: Vec<DimensionBucket>,
}

/// One bucket of the timeseries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TimeseriesPoint {
    /// Bucket start, epoch nanoseconds.
    pub start_ns: u64,
    /// Bucket end (exclusive), epoch nanoseconds.
    pub end_ns: u64,
    /// The counters for the events in this bucket.
    pub counters: SensitiveDataCounters,
}

/// Response for `GET /api/v1/sensitive-data/timeseries`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataTimeseriesResponse {
    /// What was read.
    pub scope: QueryScope,
    /// Bucket width in seconds.
    pub bucket_seconds: u64,
    /// Buckets in ascending time order. Empty buckets are present with zeroed
    /// counters so a chart shows a gap rather than joining across it.
    pub points: Vec<TimeseriesPoint>,
}

/// Response for `GET /api/v1/sensitive-data/breakdown`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataBreakdownResponse {
    /// What was read.
    pub scope: QueryScope,
    /// The dimension grouped by.
    pub group_by: MetricDimension,
    /// Groups, highest finding count first.
    pub buckets: Vec<DimensionBucket>,
}

/// One event on the drill-down list.
///
/// Built field-by-field from the projection row. No offsets, no lengths, no
/// payload — see the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataEventSummary {
    /// The event's identity, and the key for the detail endpoint.
    pub event_id: String,
    /// When the action was inspected, epoch nanoseconds.
    pub occurred_at_ns: u64,
    /// The agent that acted.
    pub acting_agent_id: String,
    /// The agent at the root of the delegation chain.
    pub root_agent_id: String,
    /// The agent that delegated, if any.
    pub parent_agent_id: Option<String>,
    /// Delegation hops from the root.
    pub delegation_depth: u32,
    /// Owning team, when attributable.
    pub team_id: Option<String>,
    /// Agent session, when recorded. A correlation id, not a value.
    pub session_id: Option<String>,
    /// Distributed-trace id, when recorded.
    pub trace_id: Option<String>,
    /// What kind of operation it was.
    pub operation: String,
    /// What kind of thing the destination is.
    pub destination_kind: String,
    /// The destination's name.
    pub destination_id: String,
    /// How far outside the boundary the destination sits.
    pub trust_zone: String,
    /// Which way the payload was travelling.
    pub direction: String,
    /// The enforcement outcome (ADR 0018's frozen verdict).
    pub verdict: String,
    /// Where the decision was applied. Prevention condition 1.
    pub enforcement_point: String,
    /// What was observed about the forwarded bytes. Prevention condition 3.
    pub transmission_evidence: String,
    /// Whether enforcement was applied or merely computed. Prevention condition 4.
    pub enforcement_mode: String,
    /// How the detection pass terminated. Never a synonym for "found nothing".
    pub inspection_failure_path: String,
    /// Whether this event meets all four §8 prevention conditions. Derived from
    /// the three evidence columns on read, never stored.
    pub prevented_transmission: bool,
    /// Policy document in force, when attributed.
    pub policy_document_id: Option<String>,
    /// Rules that matched.
    pub matched_rule_ids: Vec<String>,
    /// Names of the inspected fields — the §9 drill-down granularity.
    pub inspected_field_paths: Vec<String>,
    /// How many findings this action carried.
    pub finding_count: u32,
    /// How many of them were rewritten before the decision was applied.
    pub transformed_finding_count: u32,
    /// Machine-aggregatable reasons for the decision.
    pub reason_codes: Vec<String>,
}

/// One finding on the drill-down detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataFindingDetail {
    /// Position within its event.
    pub finding_ordinal: u32,
    /// What was found, in provider-neutral terms.
    pub category: String,
    /// How damaging exposure would be.
    pub severity: String,
    /// How much the recognizer trusted it. Never an authorisation input.
    pub confidence: String,
    /// The technique that produced it.
    pub method: String,
    /// Its triage state. Nothing in this vocabulary means "clean".
    pub status: String,
    /// Which recognizer claims to have produced it.
    pub recognizer: String,
    /// That recognizer's version. Descriptive, not a trust signal.
    pub recognizer_version: String,
    /// The inspected field's **name**. §9's drill-down granularity, in place of
    /// an offset.
    pub field_path: String,
    /// The `[REDACTED:…]` label this finding redacts to. A label, not a value.
    pub redaction_label: String,
}

/// Response for `GET /api/v1/sensitive-data/events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataEventsResponse {
    /// What was read.
    pub scope: QueryScope,
    /// **Every** matching event in the window, not the length of `events`. A UI
    /// pairing the two must label this as the total.
    pub total: u64,
    /// The page, newest first.
    pub events: Vec<SensitiveDataEventSummary>,
}

/// Response for `GET /api/v1/sensitive-data/events/{event_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SensitiveDataEventDetailResponse {
    /// The event.
    pub event: SensitiveDataEventSummary,
    /// Its normalized findings, in ordinal order.
    pub findings: Vec<SensitiveDataFindingDetail>,
}

/// Which way a top-offender entry moved against the preceding window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    /// More findings than in the preceding window.
    Up,
    /// Fewer.
    Down,
    /// The same number.
    Flat,
    /// Absent from the preceding window entirely — a first appearance, which is
    /// not the same as "up from zero" and is worth its own value.
    New,
}

/// One ranked offender, with its comparison against the preceding window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TopOffenderEntry {
    /// The agent id, tool name or destination this row ranks.
    pub key: String,
    /// Counters over the requested window.
    pub counters: SensitiveDataCounters,
    /// Counters over the window of the same length immediately before it.
    pub previous: SensitiveDataCounters,
    /// `finding_count` minus the previous window's, as a signed change.
    pub finding_count_delta: i64,
    /// Which way it moved.
    pub trend: TrendDirection,
}

/// Response for `GET /api/v1/sensitive-data/top-offenders`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TopOffendersResponse {
    /// What was read.
    pub scope: QueryScope,
    /// The preceding window the trend compares against.
    pub comparison_from_ns: u64,
    /// Its exclusive upper bound — equal to `scope.from_ns`.
    pub comparison_to_ns: u64,
    /// Which drill-down dimension was ranked.
    pub dimension: String,
    /// Entries, highest current finding count first.
    pub entries: Vec<TopOffenderEntry>,
}

/// Response for `GET /api/v1/sensitive-data/export`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ComplianceExportResponse {
    /// What was exported.
    pub scope: QueryScope,
    /// The access record written **before** this body was produced.
    pub access_record: ExportAccessRecord,
    /// Every matching event in the window.
    pub events: Vec<SensitiveDataEventSummary>,
    /// Their findings, keyed by `event_id`.
    pub findings: Vec<ExportedFindings>,
}

/// One event's findings, in the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExportedFindings {
    /// The event these belong to.
    pub event_id: String,
    /// Its findings, in ordinal order.
    pub findings: Vec<SensitiveDataFindingDetail>,
}

// ---------------------------------------------------------------------------
// Scope, window and loading
// ---------------------------------------------------------------------------

/// 503 when the deployment has no projection wired.
///
/// Distinct from an empty result on purpose: "the projection is off" and "the
/// window was quiet" are different answers, and a governance surface that
/// renders the first as the second reports a clean posture for a system that is
/// not recording.
fn projection_unavailable() -> ProblemDetail {
    ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE).with_detail(
        "the sensitive-data projection is not enabled on this deployment; \
         no analytics can be reported from it",
    )
}

/// Resolve the tenant scope from the verified caller and an optional request org.
///
/// The request `org_id` is a *selection* among the orgs the caller may already
/// see, never a grant: it is checked with [`AuthenticatedCaller::can_access_org`]
/// before it is used, so a tenant-scoped caller naming someone else's org is
/// refused. A caller with no org scope and no admin has nothing to select from
/// and is refused too — deliberately not defaulted to some org.
pub(crate) fn resolve_scope(
    caller: &AuthenticatedCaller,
    requested_org: Option<&str>,
) -> Result<TenantScope, ProblemDetail> {
    let org = match requested_org.map(str::trim).filter(|o| !o.is_empty()) {
        Some(requested) => {
            if !caller.can_access_org(requested) {
                return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN).with_detail(format!(
                    "caller is not authorised to read sensitive-data records for organisation `{requested}`"
                )));
            }
            requested.to_string()
        }
        None => match caller.storage_tenant_org() {
            Some(org) => org.to_string(),
            None => {
                return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(
                    "a cross-tenant caller must name the organisation to read via `org_id`; \
                     the sensitive-data projection has no unscoped read",
                ))
            }
        },
    };

    // The producer writes `tenant_id == org_id` (AAASM-5440); the scope keeps
    // both so a future per-org multi-tenant split is a change here and not a
    // change to every query.
    TenantScope::new(org.clone(), org)
        .map_err(|e| ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(e.to_string()))
}

/// Current wall-clock in epoch nanoseconds.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Resolve `[from, to)` in epoch nanoseconds from the filter.
///
/// Explicit RFC 3339 bounds win; otherwise the `range` preset is taken back from
/// now. An unparseable explicit bound is a 400 rather than a silent fallback to
/// the default window — a caller that asked for January and got last week would
/// have no way to tell.
fn resolve_window(params: &SensitiveDataFilterParams) -> Result<(u64, u64), ProblemDetail> {
    let parse = |label: &str, value: &str| -> Result<u64, ProblemDetail> {
        chrono::DateTime::parse_from_rfc3339(value.trim())
            .map_err(|e| {
                ProblemDetail::from_status(StatusCode::BAD_REQUEST)
                    .with_detail(format!("`{label}` is not an RFC 3339 timestamp: {e}"))
            })
            .map(|t| t.timestamp_nanos_opt().unwrap_or(0).max(0) as u64)
    };

    let to = match params.to.as_deref() {
        Some(value) => parse("to", value)?,
        None => now_ns(),
    };
    let from = match params.from.as_deref() {
        Some(value) => parse("from", value)?,
        None => {
            let window_ns =
                crate::routes::analytics::window_secs_from_range(params.range.as_deref()).saturating_mul(1_000_000_000);
            to.saturating_sub(window_ns)
        }
    };
    if from > to {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("`from` is after `to`; an inverted window has no meaning"));
    }
    Ok((from, to))
}

/// Everything one request needs from the projection, already filtered.
struct LoadedWindow {
    scope: QueryScope,
    events: Vec<SensitiveDataEventRow>,
    findings: Vec<SensitiveDataFindingRow>,
}

/// Read one window from the durable projection and apply the request's filters.
///
/// The storage filter carries the tenant and the time bounds — the two things
/// that must not be applied in Rust, because the first is the isolation boundary
/// and the second is what keeps the read bounded. Everything else is applied
/// here: the projection's filter has no predicate for an agent, a destination or
/// a finding category, and adding one is `aa-gateway`'s change to make, not a
/// reason for this layer to fall back to re-scanning the audit log.
///
/// **No `limit` is set on the storage filter.** See the module doc: the window
/// is the bound, and a silent row ceiling is the defect this endpoint set exists
/// not to repeat.
async fn load_window(
    state: &AppState,
    caller: &AuthenticatedCaller,
    params: &SensitiveDataFilterParams,
    from_ns: u64,
    to_ns: u64,
) -> Result<LoadedWindow, ProblemDetail> {
    let projection = state.sensitive_data.as_ref().ok_or_else(projection_unavailable)?;
    let scope = resolve_scope(caller, params.org_id.as_deref())?;

    let mut filter = SensitiveDataEventFilter::new(scope.clone())
        .between(Timestamp::from_nanos(from_ns), Timestamp::from_nanos(to_ns));
    // `outcome` is the one request filter the storage layer can apply itself, on
    // both tables — so it is pushed down rather than re-implemented here.
    if let Some(outcome) = params.outcome.as_deref() {
        filter = filter.with_verdict(outcome);
    }

    let events = projection
        .query_sensitive_data_events(&filter)
        .await
        .map_err(storage_error)?;
    let findings = projection
        .query_sensitive_data_findings(&filter)
        .await
        .map_err(storage_error)?;

    let findings: Vec<SensitiveDataFindingRow> = findings.into_iter().filter(|f| finding_matches(params, f)).collect();

    // An event survives a finding-level predicate when it carried a finding
    // that matched. The counters then describe those whole actions — a
    // finding-level filter selects *events*, it does not re-tally them, and the
    // response documents that.
    let matched_events: BTreeSet<&str> = findings.iter().map(|f| f.event_id.as_str()).collect();
    let finding_predicate_used = has_finding_predicate(params);

    let events: Vec<SensitiveDataEventRow> = events
        .into_iter()
        .filter(|e| event_matches(params, e))
        .filter(|e| !finding_predicate_used || matched_events.contains(e.event_id.as_str()))
        .collect();

    let kept: BTreeSet<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
    let findings = findings
        .into_iter()
        .filter(|f| kept.contains(f.event_id.as_str()))
        .collect();

    Ok(LoadedWindow {
        scope: QueryScope {
            org_id: filter.scope().org_id().to_string(),
            tenant_id: filter.scope().tenant_id().to_string(),
            from_ns,
            to_ns,
        },
        events,
        findings,
    })
}

/// Render a storage failure without echoing driver internals to the caller.
fn storage_error(err: aa_gateway::storage::StorageError) -> ProblemDetail {
    tracing::error!(error = %err, "sensitive-data projection query failed");
    ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR)
        .with_detail("the sensitive-data projection could not be queried")
}

/// Whether any finding-level predicate was supplied.
fn has_finding_predicate(params: &SensitiveDataFilterParams) -> bool {
    params.category.is_some()
        || params.provider.is_some()
        || params.confidence.is_some()
        || params.status.is_some()
        || params.severity.is_some()
        || params.detection_method.is_some()
}

/// Case-sensitive equality against an optional filter, absent meaning "any".
fn matches_opt(filter: Option<&String>, value: &str) -> bool {
    // `map_or(true, …)` rather than `is_none_or`: the workspace MSRV is 1.75
    // and `Option::is_none_or` is 1.82.
    filter.map_or(true, |f| f == value)
}

/// Event-level predicates.
fn event_matches(params: &SensitiveDataFilterParams, event: &SensitiveDataEventRow) -> bool {
    matches_opt(params.agent_id.as_ref(), &event.acting_agent_id)
        && matches_opt(params.root_agent_id.as_ref(), &event.root_agent_id)
        && matches_opt(params.operation.as_ref(), &event.operation)
        && matches_opt(params.destination.as_ref(), &event.destination_id)
        && matches_opt(params.outcome.as_ref(), &event.verdict)
        && params
            .team_id
            .as_ref()
            .map_or(true, |t| event.team_id.as_deref() == Some(t.as_str()))
        && params
            .policy_document_id
            .as_ref()
            .map_or(true, |p| event.policy_document_id.as_deref() == Some(p.as_str()))
        // A tool is a destination whose kind says so. Matching the identifier
        // alone would let `?tool=api.example.com` select an HTTP host.
        && params
            .tool
            .as_ref()
            .map_or(true, |t| event.destination_kind == "tool" && &event.destination_id == t)
}

/// Finding-level predicates.
fn finding_matches(params: &SensitiveDataFilterParams, finding: &SensitiveDataFindingRow) -> bool {
    matches_opt(params.category.as_ref(), &finding.category)
        && matches_opt(params.provider.as_ref(), &finding.recognizer)
        && matches_opt(params.confidence.as_ref(), &finding.confidence)
        && matches_opt(params.status.as_ref(), &finding.status)
        && matches_opt(params.severity.as_ref(), &finding.severity)
        && matches_opt(params.detection_method.as_ref(), &finding.method)
}

// ---------------------------------------------------------------------------
// DTO projection
// ---------------------------------------------------------------------------

impl From<&SensitiveDataEventRow> for SensitiveDataEventSummary {
    fn from(row: &SensitiveDataEventRow) -> Self {
        Self {
            event_id: row.event_id.clone(),
            occurred_at_ns: row.occurred_at_ns,
            acting_agent_id: row.acting_agent_id.clone(),
            root_agent_id: row.root_agent_id.clone(),
            parent_agent_id: row.parent_agent_id.clone(),
            delegation_depth: row.delegation_depth,
            team_id: row.team_id.clone(),
            session_id: row.session_id.clone(),
            trace_id: row.trace_id.clone(),
            operation: row.operation.clone(),
            destination_kind: row.destination_kind.clone(),
            destination_id: row.destination_id.clone(),
            trust_zone: row.trust_zone.clone(),
            direction: row.direction.clone(),
            verdict: row.verdict.clone(),
            enforcement_point: row.enforcement_point.clone(),
            transmission_evidence: row.transmission_evidence.clone(),
            enforcement_mode: row.enforcement_mode.clone(),
            inspection_failure_path: row.inspection_failure_path.clone(),
            prevented_transmission: row.counts_as_prevented_transmission(),
            policy_document_id: row.policy_document_id.clone(),
            matched_rule_ids: row.matched_rule_ids.clone(),
            inspected_field_paths: row.inspected_field_paths.clone(),
            finding_count: row.finding_count,
            transformed_finding_count: row.transformed_finding_count,
            reason_codes: row.reason_codes.clone(),
        }
    }
}

impl From<&SensitiveDataFindingRow> for SensitiveDataFindingDetail {
    fn from(row: &SensitiveDataFindingRow) -> Self {
        Self {
            finding_ordinal: row.finding_ordinal,
            category: row.category.clone(),
            severity: row.severity.clone(),
            confidence: row.confidence.clone(),
            method: row.method.clone(),
            status: row.status.clone(),
            recognizer: row.recognizer.clone(),
            recognizer_version: row.recognizer_version.clone(),
            field_path: row.field_path.clone(),
            redaction_label: row.redaction_label.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/sensitive-data/summary` — the ADR 0032 §8 metric dictionary
/// over a window.
///
/// Read scope, tenant-confined by [`resolve_scope`]. Every counter is derived
/// from the durable projection; see [`metrics`] for why two of them deliberately
/// do not read the column that shares their name.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/summary",
    params(SensitiveDataFilterParams),
    responses(
        (status = 200, description = "Sensitive-data counters and rates over the window", body = SensitiveDataSummaryResponse),
        (status = 400, description = "Malformed window, or a cross-tenant caller that named no organisation"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn get_summary(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
) -> Result<Json<SensitiveDataSummaryResponse>, ProblemDetail> {
    let (from_ns, to_ns) = resolve_window(&params)?;
    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;
    let counters = SensitiveDataCounters::tally(&loaded.events);
    Ok(Json(SensitiveDataSummaryResponse {
        scope: loaded.scope,
        rates: counters.rates(),
        counters,
        by_category: group_findings(MetricDimension::Category, &loaded.findings),
    }))
}

/// Bucket width in seconds, or `None` for an unknown preset.
fn bucket_seconds(bucket: Option<&str>) -> Option<u64> {
    match bucket.unwrap_or("1d") {
        "1h" => Some(3_600),
        "6h" => Some(21_600),
        "1d" => Some(86_400),
        "7d" => Some(604_800),
        _ => None,
    }
}

/// Most buckets a single response may carry.
///
/// A bound on the *response*, not on the rows read: every event in the window
/// still contributes to exactly one bucket, so no count is lost by the cap —
/// the request is refused instead, which is the difference between this and a
/// row ceiling that silently under-reports.
const MAX_TIMESERIES_BUCKETS: u64 = 750;

/// `GET /api/v1/sensitive-data/timeseries` — the counters, bucketed.
///
/// Read scope, tenant-confined. Empty buckets are emitted with zeroed counters
/// so a chart renders a gap rather than interpolating across one.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/timeseries",
    params(SensitiveDataFilterParams, TimeseriesParams),
    responses(
        (status = 200, description = "Bucketed sensitive-data counters", body = SensitiveDataTimeseriesResponse),
        (status = 400, description = "Unknown bucket width, malformed window, or too many buckets"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn get_timeseries(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
    Query(series): Query<TimeseriesParams>,
) -> Result<Json<SensitiveDataTimeseriesResponse>, ProblemDetail> {
    let bucket_secs = bucket_seconds(series.bucket.as_deref()).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("`bucket` must be one of `1h`, `6h`, `1d`, `7d`")
    })?;
    let (from_ns, to_ns) = resolve_window(&params)?;

    let bucket_ns = bucket_secs.saturating_mul(1_000_000_000);
    let span = to_ns.saturating_sub(from_ns);
    let count = span.div_ceil(bucket_ns).max(1);
    if count > MAX_TIMESERIES_BUCKETS {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
            "the requested window needs {count} buckets of `{}`; the maximum is {MAX_TIMESERIES_BUCKETS}. \
             Widen the bucket or shorten the window",
            series.bucket.as_deref().unwrap_or("1d")
        )));
    }

    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;

    let mut bucketed: Vec<Vec<&SensitiveDataEventRow>> = vec![Vec::new(); count as usize];
    for event in &loaded.events {
        let offset = event.occurred_at_ns.saturating_sub(from_ns) / bucket_ns;
        // An event exactly on `to_ns` cannot occur (the bound is exclusive in
        // the storage query); clamping guards the integer edge rather than the
        // data.
        let index = (offset as usize).min(bucketed.len() - 1);
        bucketed[index].push(event);
    }

    let points = bucketed
        .into_iter()
        .enumerate()
        .map(|(index, rows)| {
            let start_ns = from_ns + (index as u64) * bucket_ns;
            TimeseriesPoint {
                start_ns,
                end_ns: (start_ns + bucket_ns).min(to_ns.max(start_ns)),
                counters: SensitiveDataCounters::tally(rows),
            }
        })
        .collect();

    Ok(Json(SensitiveDataTimeseriesResponse {
        scope: loaded.scope,
        bucket_seconds: bucket_secs,
        points,
    }))
}

/// `GET /api/v1/sensitive-data/breakdown` — findings grouped by one bounded
/// dimension.
///
/// Read scope, tenant-confined. `group_by` admits only ADR 0032 §9's six
/// permitted labels; `agent_id`, `destination`, `session_id`, `trace_id` and any
/// fingerprint are refused with 400 and named in the message, because those are
/// event-store dimensions and grouping a series by one is unbounded cardinality.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/breakdown",
    params(SensitiveDataFilterParams, BreakdownParams),
    responses(
        (status = 200, description = "Findings grouped by a bounded dimension", body = SensitiveDataBreakdownResponse),
        (status = 400, description = "`group_by` is not one of the six ADR 0032 §9 labels"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn get_breakdown(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
    Query(breakdown): Query<BreakdownParams>,
) -> Result<Json<SensitiveDataBreakdownResponse>, ProblemDetail> {
    let requested = breakdown.group_by.as_deref().unwrap_or("category");
    let group_by: MetricDimension =
        serde_json::from_value(serde_json::Value::String(requested.to_string())).map_err(|_| {
            ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!(
                "`group_by={requested}` is not a permitted metric dimension. ADR 0032 §9 bounds metric labels to \
                 {:?}; `agent_id`, `destination`, `session_id`, `trace_id` and fingerprints are unbounded and \
                 belong to the event store — filter or drill down by them instead",
                MetricDimension::names()
            ))
        })?;

    let (from_ns, to_ns) = resolve_window(&params)?;
    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;

    Ok(Json(SensitiveDataBreakdownResponse {
        scope: loaded.scope,
        group_by,
        buckets: group_findings(group_by, &loaded.findings),
    }))
}

/// Default page size for the drill-down list.
const DEFAULT_EVENT_PAGE: usize = 100;
/// Largest page a caller may ask for.
const MAX_EVENT_PAGE: usize = 1_000;

/// `GET /api/v1/sensitive-data/events` — the drill-down list behind an aggregate.
///
/// Read scope, tenant-confined. `total` is the true count for the filter, not
/// the length of the page — the storage layer documents that pairing a capped
/// list with an uncapped count is deliberate, and the field names say which is
/// which.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/events",
    params(SensitiveDataFilterParams),
    responses(
        (status = 200, description = "Matching events, newest first", body = SensitiveDataEventsResponse),
        (status = 400, description = "Malformed window, or a cross-tenant caller that named no organisation"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn list_events(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
) -> Result<Json<SensitiveDataEventsResponse>, ProblemDetail> {
    let (from_ns, to_ns) = resolve_window(&params)?;
    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;

    let limit = params
        .limit
        .map(|l| (l as usize).min(MAX_EVENT_PAGE))
        .unwrap_or(DEFAULT_EVENT_PAGE);
    let total = loaded.events.len() as u64;
    let events = loaded
        .events
        .iter()
        .take(limit)
        .map(SensitiveDataEventSummary::from)
        .collect();

    Ok(Json(SensitiveDataEventsResponse {
        scope: loaded.scope,
        total,
        events,
    }))
}

/// `GET /api/v1/sensitive-data/events/{event_id}` — one event and its findings.
///
/// Read scope, tenant-confined: the lookup runs inside the caller's scope, so an
/// event id belonging to another tenant is a 404 rather than a cross-tenant
/// read. That the id exists elsewhere is itself not something to disclose.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/events/{event_id}",
    params(
        ("event_id" = String, Path, description = "The event's identity"),
        SensitiveDataFilterParams,
    ),
    responses(
        (status = 200, description = "The event and its findings", body = SensitiveDataEventDetailResponse),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 404, description = "No such event within the caller's tenant and window"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn get_event(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Path(event_id): Path<String>,
    Query(params): Query<SensitiveDataFilterParams>,
) -> Result<Json<SensitiveDataEventDetailResponse>, ProblemDetail> {
    let (from_ns, to_ns) = resolve_window(&params)?;
    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;

    let event = loaded.events.iter().find(|e| e.event_id == event_id).ok_or_else(|| {
        ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail("no sensitive-data event with that id in this tenant and window")
    })?;

    let mut findings: Vec<&SensitiveDataFindingRow> =
        loaded.findings.iter().filter(|f| f.event_id == event_id).collect();
    findings.sort_by_key(|f| f.finding_ordinal);

    Ok(Json(SensitiveDataEventDetailResponse {
        event: SensitiveDataEventSummary::from(event),
        findings: findings.into_iter().map(SensitiveDataFindingDetail::from).collect(),
    }))
}

/// How many offenders a single response ranks.
const DEFAULT_OFFENDER_LIMIT: usize = 20;

/// The key one offender row is ranked by.
fn offender_key<'a>(dimension: &str, event: &'a SensitiveDataEventRow) -> Option<&'a str> {
    match dimension {
        "agent" => Some(event.acting_agent_id.as_str()),
        "root_agent" => Some(event.root_agent_id.as_str()),
        "tool" => (event.destination_kind == "tool").then_some(event.destination_id.as_str()),
        "destination" => Some(event.destination_id.as_str()),
        _ => None,
    }
}

/// `GET /api/v1/sensitive-data/top-offenders` — the worst agents, tools or
/// destinations, with a trend against the preceding window.
///
/// Read scope, tenant-confined.
///
/// **This ranks the event store, not a metric series.** ADR 0032 §9 forbids
/// `agent_id` and `destination` as *metric labels* because a label multiplies
/// series; a ranked list over a queryable store is exactly what §9 sends those
/// dimensions to instead, and it returns a bounded number of rows by
/// construction.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/top-offenders",
    params(SensitiveDataFilterParams, TopOffendersParams),
    responses(
        (status = 200, description = "Ranked offenders with trend comparison", body = TopOffendersResponse),
        (status = 400, description = "`dimension` is not `agent`, `root_agent`, `tool` or `destination`"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller may not read the requested organisation"),
        (status = 503, description = "The sensitive-data projection is not enabled")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn get_top_offenders(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
    Query(top): Query<TopOffendersParams>,
) -> Result<Json<TopOffendersResponse>, ProblemDetail> {
    let dimension = top.dimension.as_deref().unwrap_or("agent").to_string();
    if !matches!(dimension.as_str(), "agent" | "root_agent" | "tool" | "destination") {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail("`dimension` must be one of `agent`, `root_agent`, `tool`, `destination`"));
    }

    let (from_ns, to_ns) = resolve_window(&params)?;
    let span = to_ns.saturating_sub(from_ns);
    let prev_from = from_ns.saturating_sub(span);

    let current = load_window(&state, &caller, &params, from_ns, to_ns).await?;
    let previous = load_window(&state, &caller, &params, prev_from, from_ns).await?;

    let group = |rows: &[SensitiveDataEventRow]| -> BTreeMap<String, SensitiveDataCounters> {
        let mut by_key: BTreeMap<String, Vec<&SensitiveDataEventRow>> = BTreeMap::new();
        for row in rows {
            if let Some(key) = offender_key(&dimension, row) {
                by_key.entry(key.to_string()).or_default().push(row);
            }
        }
        by_key
            .into_iter()
            .map(|(key, rows)| (key, SensitiveDataCounters::tally(rows)))
            .collect()
    };

    let current_by_key = group(&current.events);
    let previous_by_key = group(&previous.events);

    let mut entries: Vec<TopOffenderEntry> = current_by_key
        .into_iter()
        .map(|(key, counters)| {
            let previous = previous_by_key.get(&key).copied();
            let previous_counters = previous.unwrap_or_default();
            let delta = counters.finding_count as i64 - previous_counters.finding_count as i64;
            let trend = match previous {
                // Absent from the previous window is `New`, not `Up` from zero:
                // a first appearance and a rise are different operator signals.
                None => TrendDirection::New,
                Some(_) if delta > 0 => TrendDirection::Up,
                Some(_) if delta < 0 => TrendDirection::Down,
                Some(_) => TrendDirection::Flat,
            };
            TopOffenderEntry {
                key,
                counters,
                previous: previous_counters,
                finding_count_delta: delta,
                trend,
            }
        })
        .collect();

    entries.sort_by(|a, b| {
        b.counters
            .finding_count
            .cmp(&a.counters.finding_count)
            .then_with(|| a.key.cmp(&b.key))
    });
    let limit = params
        .limit
        .map(|l| (l as usize).min(MAX_EVENT_PAGE))
        .unwrap_or(DEFAULT_OFFENDER_LIMIT);
    entries.truncate(limit);

    Ok(Json(TopOffendersResponse {
        scope: current.scope,
        comparison_from_ns: prev_from,
        comparison_to_ns: from_ns,
        dimension,
        entries,
    }))
}

/// `GET /api/v1/sensitive-data/export` — the compliance export.
///
/// **Authorisation**: `Scope::Admin` *and* an explicit `acknowledge_export=true`.
/// The scope says who may export; the acknowledgement says that this particular
/// export was intended, so a link followed by accident does not release a
/// tenant's whole governance record.
///
/// **Access logging**: the export is recorded in
/// [`AppState::sensitive_data_export_log`] **before** the body is produced, and
/// a record that cannot be written is a 503 with nothing released. An export
/// nobody can attribute is the outcome this ordering exists to prevent.
///
/// Tenant-confined by [`resolve_scope`] like every other endpoint here: admin
/// scope authorises the *act*, it does not widen the *rows* — a cross-tenant
/// admin still names the organisation it is exporting.
#[utoipa::path(
    get,
    path = "/api/v1/sensitive-data/export",
    params(SensitiveDataFilterParams, ExportParams),
    responses(
        (status = 200, description = "The exported events and findings, plus the access record written for them", body = ComplianceExportResponse),
        (status = 400, description = "`acknowledge_export=true` was not supplied, or the window is malformed"),
        (status = 401, description = "Missing or invalid credentials"),
        (status = 403, description = "Caller lacks admin scope, or may not read the requested organisation"),
        (status = 503, description = "The projection is not enabled, or the export could not be recorded")
    ),
    security(("bearer_auth" = [])),
    tag = "sensitive-data"
)]
pub async fn export_compliance_records(
    RequireAdmin(caller): RequireAdmin,
    Extension(state): Extension<AppState>,
    Query(params): Query<SensitiveDataFilterParams>,
    Query(export): Query<ExportParams>,
) -> Result<Json<ComplianceExportResponse>, ProblemDetail> {
    if export.acknowledge_export != Some(true) {
        return Err(ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(
            "a compliance export must be explicitly acknowledged with `acknowledge_export=true`; \
             it releases a tenant's sensitive-data record and is written to the export access log",
        ));
    }

    let (from_ns, to_ns) = resolve_window(&params)?;
    let loaded = load_window(&state, &caller, &params, from_ns, to_ns).await?;

    let record = ExportAccessRecord {
        at: chrono::Utc::now().to_rfc3339(),
        principal: caller.key_id.clone(),
        org_id: loaded.scope.org_id.clone(),
        tenant_id: loaded.scope.tenant_id.clone(),
        from_ns,
        to_ns,
        event_count: loaded.events.len() as u64,
        finding_count: loaded.findings.len() as u64,
    };
    // Recorded before the body exists. If this fails, nothing is released.
    state.sensitive_data_export_log.record(record.clone()).map_err(|e| {
        tracing::error!(error = %e, "refusing a compliance export that could not be access-logged");
        ProblemDetail::from_status(StatusCode::SERVICE_UNAVAILABLE)
            .with_detail("the compliance export could not be recorded in the access log, so nothing was exported")
    })?;
    tracing::info!(
        principal = %record.principal,
        org_id = %record.org_id,
        event_count = record.event_count,
        finding_count = record.finding_count,
        "sensitive-data compliance export authorised"
    );

    let mut by_event: BTreeMap<&str, Vec<&SensitiveDataFindingRow>> = BTreeMap::new();
    for finding in &loaded.findings {
        by_event.entry(finding.event_id.as_str()).or_default().push(finding);
    }

    let findings = loaded
        .events
        .iter()
        .map(|event| {
            let mut rows = by_event.remove(event.event_id.as_str()).unwrap_or_default();
            rows.sort_by_key(|f| f.finding_ordinal);
            ExportedFindings {
                event_id: event.event_id.clone(),
                findings: rows.into_iter().map(SensitiveDataFindingDetail::from).collect(),
            }
        })
        .collect();

    Ok(Json(ComplianceExportResponse {
        scope: loaded.scope.clone(),
        access_record: record,
        events: loaded.events.iter().map(SensitiveDataEventSummary::from).collect(),
        findings,
    }))
}

/// The export access log a fresh deployment starts with.
pub fn default_export_access_log() -> Arc<dyn ExportAccessLog> {
    Arc::new(InMemoryExportAccessLog::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::scope::Scope;
    use crate::auth::Tenant;

    fn caller(scopes: Vec<Scope>, org: Option<&str>) -> AuthenticatedCaller {
        AuthenticatedCaller {
            key_id: "k".to_string(),
            scopes,
            tenant: Tenant {
                team_id: None,
                org_id: org.map(str::to_string),
            },
        }
    }

    /// **AC6, at the scope resolver.** A tenant-scoped caller naming another
    /// org is refused, not answered with an empty window.
    #[test]
    fn a_tenant_scoped_caller_cannot_name_another_organisation() {
        let acme = caller(vec![Scope::Read], Some("acme"));
        let denied = resolve_scope(&acme, Some("globex")).expect_err("cross-tenant read must be refused");
        assert_eq!(denied.status, StatusCode::FORBIDDEN.as_u16());

        let allowed = resolve_scope(&acme, Some("acme")).expect("its own org resolves");
        assert_eq!(allowed.org_id(), "acme");

        let implied = resolve_scope(&acme, None).expect("its own org is the default");
        assert_eq!(implied.org_id(), "acme");
    }

    /// A caller with neither an org nor admin has nothing to select, and is
    /// refused rather than defaulted into somebody's tenant.
    #[test]
    fn a_caller_with_no_tenant_and_no_admin_gets_no_default_organisation() {
        let anonymous = caller(vec![Scope::Read], None);
        let refused = resolve_scope(&anonymous, None).expect_err("there is no unscoped read");
        assert_eq!(refused.status, StatusCode::BAD_REQUEST.as_u16());
        // …and it may not reach for one either.
        let denied = resolve_scope(&anonymous, Some("acme")).expect_err("naming an org it cannot access is refused");
        assert_eq!(denied.status, StatusCode::FORBIDDEN.as_u16());
    }

    /// An admin must still name the tenant it is reading — admin scope
    /// authorises the act, it does not synthesise a scope.
    #[test]
    fn an_admin_must_name_the_organisation_it_reads() {
        let admin = caller(vec![Scope::Admin], None);
        let refused = resolve_scope(&admin, None).expect_err("an admin has no implicit tenant");
        assert_eq!(refused.status, StatusCode::BAD_REQUEST.as_u16());
        assert_eq!(
            resolve_scope(&admin, Some("globex"))
                .expect("an admin may select any org")
                .org_id(),
            "globex"
        );
    }

    /// An explicit bound that does not parse is a 400, not a silent fall back
    /// to the default window.
    #[test]
    fn an_unparseable_bound_is_refused_rather_than_defaulted() {
        let params = SensitiveDataFilterParams {
            from: Some("last tuesday".to_string()),
            ..Default::default()
        };
        let err = resolve_window(&params).expect_err("an unparseable bound is refused");
        assert_eq!(err.status, StatusCode::BAD_REQUEST.as_u16());
    }

    /// An inverted window is refused rather than silently emptied.
    #[test]
    fn an_inverted_window_is_refused() {
        let params = SensitiveDataFilterParams {
            from: Some("2026-02-01T00:00:00Z".to_string()),
            to: Some("2026-01-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_window(&params).expect_err("inverted").status,
            StatusCode::BAD_REQUEST.as_u16()
        );
    }

    /// Only the four documented bucket widths resolve.
    #[test]
    fn only_the_documented_bucket_widths_resolve() {
        assert_eq!(bucket_seconds(None), Some(86_400));
        assert_eq!(bucket_seconds(Some("1h")), Some(3_600));
        assert_eq!(bucket_seconds(Some("7d")), Some(604_800));
        assert_eq!(bucket_seconds(Some("13m")), None);
    }
}
