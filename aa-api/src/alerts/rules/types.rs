//! Alert-rule domain types and validation (AAASM-1386).
//!
//! Wire shape matches the Story description verbatim: see
//! `https://lightning-dust-mite.atlassian.net/browse/AAASM-1386` for the
//! canonical JSON example.

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
