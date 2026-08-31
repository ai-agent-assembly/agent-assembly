//! [`ApprovalStore`] — shared persistence for pending/resolved approval requests.
//!
//! AAASM-5657: `aa-gateway` and `aa-api` each run an in-process
//! `ApprovalQueue` (`aa-runtime`), and without a shared backing store those
//! two queues never see each other's requests or decisions — a hold created
//! by the gateway's policy pipeline is invisible to the dashboard/CLI, and
//! vice versa. This trait is the seam a backend implements so both processes
//! can treat one durable table as their approval queue's ground truth
//! instead of two disconnected in-memory maps.
//!
//! Request/decision/routing are three narrow methods rather than one wide
//! "upsert everything" call because a caller only ever has one of the three
//! at a time (submission, a human's decision, a routing update), and a
//! narrower write is a narrower race window.

use super::Result;
use async_trait::async_trait;

/// A pending approval request as persisted.
///
/// `fallback_json` is the request's fallback `aa_core::PolicyResult`,
/// serialized by the caller (`aa-core` has no reason to know `ApprovalQueue`'s
/// in-memory representation) — carried as an opaque string so a rehydrated
/// request that later times out still has its fallback decision after a
/// process restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// Request id (UUID, hyphenated string form).
    pub request_id: String,
    /// The agent that triggered the approval requirement.
    pub agent_id: String,
    /// Human-readable description of the action awaiting approval.
    pub action: String,
    /// Name or description of the policy condition that triggered this request.
    pub condition_triggered: String,
    /// Unix epoch seconds.
    pub submitted_at: u64,
    /// Seconds before the request times out.
    pub timeout_secs: u64,
    /// Team identifier, if any.
    pub team_id: Option<String>,
    /// `serde_json`-encoded `aa_core::PolicyResult`.
    pub fallback_json: String,
}

/// A settled decision as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecisionRow {
    /// Request id (UUID, hyphenated string form).
    pub request_id: String,
    /// `"approved"` | `"rejected"` | `"timed_out"`.
    pub status: String,
    /// Unix epoch seconds.
    pub decided_at: u64,
    /// Identifier of the operator who decided, or `"timeout"` for auto-expiry.
    pub decided_by: String,
    /// Optional free-text rationale. `None` for timeouts.
    pub decision_reason: Option<String>,
    /// Structured approval-condition slugs (AAASM-5095). Empty for
    /// rejections and timeouts.
    pub decision_conditions: Vec<String>,
}

/// Routing metadata for a pending request, as persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRoutingRow {
    /// Request id (UUID, hyphenated string form).
    pub request_id: String,
    /// Current routing status string (e.g. `"routed_to_team_admin"`).
    pub routing_status: Option<String>,
    /// Role the request is currently routed to.
    pub target_role: Option<String>,
    /// Unix epoch seconds.
    pub routed_at: Option<u64>,
    /// Unix epoch seconds.
    pub escalate_at: Option<u64>,
    /// `serde_json`-encoded `Vec` of routing-history entries; opaque here for
    /// the same reason as [`ApprovalRecord::fallback_json`].
    pub routing_history_json: String,
}

/// Persists pending approval requests, their decisions, and their routing
/// metadata so more than one process can observe and act on the same
/// approval queue.
///
/// A backend is free to store pending and resolved rows in one table
/// discriminated by status (the SQLite driver does) or in separate tables —
/// this trait only constrains the read/write contract, not the schema.
#[async_trait]
pub trait ApprovalStore: Send + Sync {
    /// Persist a newly submitted request. Overwrites any existing row with
    /// the same `request_id` (submission is not expected to race a decision
    /// for the same id, but the write must not panic if it does).
    async fn insert_pending(&self, record: &ApprovalRecord) -> Result<()>;

    /// Record a decision, but only if the row is still pending.
    ///
    /// Returns `Ok(true)` if the write applied, `Ok(false)` if the row was
    /// already decided (or unknown) — the conditional-on-pending semantics
    /// are what let more than one process race to settle the same
    /// already-decided id (e.g. a lazy timeout sweep racing a human's
    /// decision) without one clobbering the other's record.
    async fn record_decision(&self, request_id: &str, decision: &ApprovalDecisionRow) -> Result<bool>;

    /// All rows currently pending, across every submitting process.
    async fn list_pending(&self) -> Result<Vec<ApprovalRecord>>;

    /// Decisions for the given ids that have been recorded. Ids with no
    /// recorded decision (still pending, or unknown) are omitted from the
    /// result rather than erroring.
    async fn list_resolved_for(&self, request_ids: &[String]) -> Result<Vec<ApprovalDecisionRow>>;

    /// Persist routing metadata for a still-pending request. A no-op write
    /// (not an error) if the request is not pending.
    async fn update_routing(&self, request_id: &str, routing: &ApprovalRoutingRow) -> Result<()>;
}
