//! Output types for policy simulation results.

use serde::Serialize;

/// The outcome of evaluating a single event against a policy in dry-run mode.
#[derive(Debug, Clone, Serialize)]
pub struct EventOutcome {
    /// Zero-based index of the event in the input sequence.
    pub event_index: usize,
    /// Human-readable description of the action that was evaluated.
    pub action: String,
    /// The policy decision: "allow", "deny", or "requires_approval".
    pub decision: String,
    /// Explanation of why this decision was reached.
    pub reason: String,
}

/// Aggregate report produced by a simulation run.
#[derive(Debug, Clone, Serialize)]
pub struct SimulationReport {
    /// Total number of events evaluated.
    pub total_events: usize,
    /// Number of events that would have been denied.
    pub denied: usize,
    /// Number of events that would have been allowed.
    pub allowed: usize,
    /// Number of events that would have required human approval.
    pub approval_required: usize,
    /// Number of events that could not be evaluated — e.g. a payload that
    /// failed to deserialize (a malformed or schema-drifted audit log). These
    /// yield a per-event `decision = "error"` and must fail an exit-gated run:
    /// a simulation that could not actually evaluate its input is not a PASS.
    pub errored: usize,
    /// Estimated budget impact in USD (if budget policy is present).
    pub budget_impact_usd: Option<f64>,
    /// Per-event outcomes for events that were not simply allowed.
    pub flagged_outcomes: Vec<EventOutcome>,
}
