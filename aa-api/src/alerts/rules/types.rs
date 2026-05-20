//! Alert-rule domain types and validation (AAASM-1386).
//!
//! Wire shape matches the Story description verbatim: see
//! `https://lightning-dust-mite.atlassian.net/browse/AAASM-1386` for the
//! canonical JSON example.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Metric a rule evaluates against. Snake-case wire form matches the
/// Story's enum exactly so the dashboard rule-builder dropdown can map
/// 1:1 onto these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuleMetric {
    /// Percentage of the daily budget consumed (0-100).
    BudgetSpentPct,
    /// Anomaly score from the gateway anomaly detector. Full hookup is
    /// deferred — see the MVP evaluator note on AAASM-1386.
    AnomalyScore,
    /// Age (seconds) of the oldest pending approval request.
    ApprovalPendingAge,
    /// Count of policy violations within the evaluation window.
    PolicyViolationCount,
}

/// Comparison operator applied between the metric's current value and
/// the rule's threshold. Wire form is the literal symbol (e.g. `">"`),
/// matching the Story description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum RuleOperator {
    /// Strictly greater than.
    #[serde(rename = ">")]
    Gt,
    /// Greater than or equal to.
    #[serde(rename = ">=")]
    Gte,
    /// Strictly less than.
    #[serde(rename = "<")]
    Lt,
    /// Equal to.
    #[serde(rename = "=")]
    Eq,
}

/// Severity assigned to alerts that this rule fires. Wire form is the
/// uppercase string matching the Story (e.g. `"CRITICAL"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Read-only view of the destination registry that an alert rule's
/// `destination_ids` are validated against. Kept as a trait here so the
/// validation logic does not depend on the concrete in-memory registry
/// (delivered separately under AAASM-1617).
pub trait DestinationRegistryLookup {
    /// Returns true when `id` is a known destination.
    fn contains(&self, id: &str) -> bool;
}

/// A persisted alert rule. Same shape is used for request bodies on
/// POST / PUT and for response bodies on GET, matching the Story
/// description verbatim.
///
/// `id`, `created_at`, and `updated_at` are server-assigned; clients
/// must omit them on POST (the in-memory store will populate them) and
/// the store will overwrite them on PUT to preserve `id` + `created_at`
/// and bump `updated_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct AlertRule {
    /// Server-assigned ULID-style identifier.
    pub id: String,
    /// Human-readable rule name. Must be 1-128 characters and unique
    /// per tenant (uniqueness is enforced at the store layer).
    pub name: String,
    /// Free-form description displayed in the dashboard rule list.
    pub description: String,
    /// Metric the rule polls.
    pub metric: RuleMetric,
    /// Comparison operator applied between the metric value and
    /// [`Self::threshold`].
    pub operator: RuleOperator,
    /// Numeric threshold. Must be 0-100 for percentage metrics
    /// (see [`AlertRule::validate`]).
    pub threshold: f64,
    /// Evaluation window in seconds — must be one of `{300, 900, 3600}`.
    pub evaluation_window_seconds: u32,
    /// Severity propagated to alerts emitted by this rule.
    pub severity: RuleSeverity,
    /// Destinations the alert is routed to. Non-empty; each id must
    /// exist in the destination registry.
    pub destination_ids: Vec<String>,
    /// Window in seconds during which repeat firings are deduplicated.
    pub dedup_window_seconds: u32,
    /// Optional free-form `key=value` suppression labels.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub suppression_labels: HashMap<String, String>,
    /// Whether the rule is actively evaluated.
    pub enabled: bool,
    /// RFC 3339 timestamp when the rule was first created.
    pub created_at: String,
    /// RFC 3339 timestamp of the last mutation.
    pub updated_at: String,
}
