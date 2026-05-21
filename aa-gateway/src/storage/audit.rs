//! Audit-event storage value types — record + query filter.

use aa_core::identity::AgentId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::agent::TeamId;

/// Storage-layer audit event — the persisted shape of a policy / tool-call decision.
///
/// Kept distinct from [`aa_core::audit::AuditEntry`] (the in-memory enrichment
/// shape used by the runtime audit pipeline). `AuditEvent` mirrors the columns
/// the spec defines for the `audit_events` hypertable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Event timestamp (UTC).
    pub ts: DateTime<Utc>,
    /// Stable event identifier.
    pub event_id: Uuid,
    /// Agent the event was attributed to.
    pub agent_id: AgentId,
    /// Owning team, when known.
    pub team_id: Option<TeamId>,
    /// Action label (e.g. `"tool_call"`, `"policy_decision"`).
    pub action: String,
    /// Decision label (e.g. `"allow"`, `"deny"`, `"shadow"`).
    pub decision: String,
    /// True if the decision was produced in dry-run / shadow mode.
    pub dry_run: bool,
    /// Decision the gateway would have made in real mode, when `dry_run` is true.
    pub shadow_decision: Option<String>,
    /// Identifier of the policy rule that matched, if any.
    pub matched_rule_id: Option<String>,
    /// Free-form JSON payload (wire-protocol record, redactions, lineage…).
    pub payload: Option<serde_json::Value>,
}

/// Filter applied to audit-event queries.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Restrict to events for this agent.
    pub agent_id: Option<AgentId>,
    /// Restrict to events for this team.
    pub team_id: Option<TeamId>,
    /// Inclusive lower bound (UTC).
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper bound (UTC).
    pub to: Option<DateTime<Utc>>,
    /// When true, only dry-run events are returned.
    pub dry_run_only: bool,
    /// Maximum number of events to return.
    pub limit: Option<u32>,
    /// Offset into the result set (for paging).
    pub offset: Option<u32>,
}
