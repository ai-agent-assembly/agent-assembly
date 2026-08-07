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

use std::sync::Arc;

pub use access_log::{ExportAccessLog, ExportAccessRecord, InMemoryExportAccessLog};
pub use metrics::{group_findings, DimensionBucket, MetricDimension, SensitiveDataCounters, SensitiveDataRates};

/// The export access log a fresh deployment starts with.
///
/// A constructor rather than a `Default` impl on the trait object, so the one
/// place a deployment's log is chosen is greppable.
pub fn default_export_access_log() -> Arc<dyn ExportAccessLog> {
    Arc::new(InMemoryExportAccessLog::new())
}
