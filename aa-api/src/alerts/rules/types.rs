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

/// Validation failure surfaced from [`AlertRule::validate`].
///
/// Each variant carries an `error_code()` matching the Story's wire
/// contract. `invalid_metric` is not represented here because that case
/// is caught by serde during request deserialization (the unknown
/// `metric` string never round-trips into [`AlertRule`] in the first
/// place); the handler in AAASM-1620 maps the serde error to a 400 with
/// `error: "invalid_metric"`.
///
/// `invalid_name` and `invalid_evaluation_window` are extension codes
/// covering the validation rules the Story's prose lists but does not
/// label in its HTTP error table.
#[derive(Debug, Clone, PartialEq)]
pub enum AlertRuleValidationError {
    /// Name length is outside `[1, 128]` characters.
    InvalidName {
        /// Why the name was rejected (e.g. `"name must be 1-128 chars"`).
        reason: String,
    },
    /// `threshold` is out of the metric's allowed range
    /// (e.g. 0-100 for percentage metrics).
    InvalidThreshold {
        /// Metric whose unit constraint was violated.
        metric: RuleMetric,
        /// Submitted threshold value.
        value: f64,
        /// Reason the value was rejected.
        reason: String,
    },
    /// `evaluation_window_seconds` is not in the allowed set
    /// `{300, 900, 3600}`.
    InvalidEvaluationWindow {
        /// Submitted window value.
        value: u32,
    },
    /// `destination_ids` is empty.
    EmptyDestinations,
    /// `destination_ids` references an id the registry does not know.
    UnknownDestination {
        /// The id that was rejected.
        id: String,
    },
}

impl AlertRuleValidationError {
    /// Stable error code returned in the RFC 7807 response.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidName { .. } => "invalid_name",
            Self::InvalidThreshold { .. } => "invalid_threshold",
            Self::InvalidEvaluationWindow { .. } => "invalid_evaluation_window",
            Self::EmptyDestinations | Self::UnknownDestination { .. } => "destination_unknown",
        }
    }
}

impl std::fmt::Display for AlertRuleValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName { reason } => write!(f, "invalid name: {reason}"),
            Self::InvalidThreshold { metric, value, reason } => {
                write!(f, "invalid threshold {value} for metric {metric:?}: {reason}")
            }
            Self::InvalidEvaluationWindow { value } => write!(
                f,
                "invalid evaluation_window_seconds {value}: must be 300, 900, or 3600",
            ),
            Self::EmptyDestinations => write!(f, "destination_ids must be non-empty"),
            Self::UnknownDestination { id } => write!(f, "destination_unknown: {id}"),
        }
    }
}

impl std::error::Error for AlertRuleValidationError {}

/// Maximum name length per the Story spec ("`name` 1-128 chars").
const NAME_MAX_LEN: usize = 128;

/// Allowed `evaluation_window_seconds` values per the Story spec.
const ALLOWED_EVAL_WINDOWS: [u32; 3] = [300, 900, 3600];

impl AlertRule {
    /// Validate the rule against the constraints enumerated in the
    /// Story's "Validation rules" section. Returns the first failure
    /// encountered — callers are expected to fix one issue at a time
    /// based on the surfaced `error_code`.
    pub fn validate<R: DestinationRegistryLookup + ?Sized>(
        &self,
        destinations: &R,
    ) -> Result<(), AlertRuleValidationError> {
        // name: 1-128 chars
        if self.name.is_empty() {
            return Err(AlertRuleValidationError::InvalidName {
                reason: "name must not be empty".to_string(),
            });
        }
        if self.name.chars().count() > NAME_MAX_LEN {
            return Err(AlertRuleValidationError::InvalidName {
                reason: format!("name must be at most {NAME_MAX_LEN} chars"),
            });
        }

        // threshold: range per metric
        if let Some(reason) = threshold_range_violation(self.metric, self.threshold) {
            return Err(AlertRuleValidationError::InvalidThreshold {
                metric: self.metric,
                value: self.threshold,
                reason,
            });
        }

        // evaluation_window_seconds ∈ {300, 900, 3600}
        if !ALLOWED_EVAL_WINDOWS.contains(&self.evaluation_window_seconds) {
            return Err(AlertRuleValidationError::InvalidEvaluationWindow {
                value: self.evaluation_window_seconds,
            });
        }

        // destination_ids: non-empty + each must exist in registry
        if self.destination_ids.is_empty() {
            return Err(AlertRuleValidationError::EmptyDestinations);
        }
        for id in &self.destination_ids {
            if !destinations.contains(id) {
                return Err(AlertRuleValidationError::UnknownDestination { id: id.clone() });
            }
        }

        Ok(())
    }
}

/// Returns `Some(reason)` when `value` is out of the metric's allowed
/// range, `None` when valid. Centralized so the per-metric units stay
/// in one place.
fn threshold_range_violation(metric: RuleMetric, value: f64) -> Option<String> {
    if !value.is_finite() {
        return Some("threshold must be a finite number".to_string());
    }
    match metric {
        RuleMetric::BudgetSpentPct => {
            if !(0.0..=100.0).contains(&value) {
                Some("budget_spent_pct threshold must be in [0, 100]".to_string())
            } else {
                None
            }
        }
        RuleMetric::AnomalyScore => {
            if value < 0.0 {
                Some("anomaly_score threshold must be >= 0".to_string())
            } else {
                None
            }
        }
        RuleMetric::ApprovalPendingAge => {
            if value < 0.0 {
                Some("approval_pending_age threshold (seconds) must be >= 0".to_string())
            } else {
                None
            }
        }
        RuleMetric::PolicyViolationCount => {
            if value < 0.0 {
                Some("policy_violation_count threshold must be >= 0".to_string())
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Minimal in-test destination registry. The real seeded
    /// implementation ships under AAASM-1617.
    struct TestRegistry {
        ids: HashSet<String>,
    }

    impl TestRegistry {
        fn with(ids: &[&str]) -> Self {
            Self {
                ids: ids.iter().map(|s| (*s).to_string()).collect(),
            }
        }
    }

    impl DestinationRegistryLookup for TestRegistry {
        fn contains(&self, id: &str) -> bool {
            self.ids.contains(id)
        }
    }

    fn valid_rule() -> AlertRule {
        AlertRule {
            id: "01HX0000000000000000000000".to_string(),
            name: "Budget > 90%".to_string(),
            description: "Fire CRITICAL when budget spend exceeds 90% over 5m".to_string(),
            metric: RuleMetric::BudgetSpentPct,
            operator: RuleOperator::Gt,
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: RuleSeverity::Critical,
            destination_ids: vec!["slack-ops".to_string()],
            dedup_window_seconds: 600,
            suppression_labels: HashMap::new(),
            enabled: true,
            created_at: "2026-05-13T09:00:00Z".to_string(),
            updated_at: "2026-05-13T09:00:00Z".to_string(),
        }
    }

    #[test]
    fn valid_rule_passes_validation() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = valid_rule();
        assert_eq!(rule.validate(&registry), Ok(()));
    }

    #[test]
    fn empty_name_rejected_as_invalid_name() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            name: String::new(),
            ..valid_rule()
        };
        let err = rule.validate(&registry).expect_err("empty name must fail");
        assert!(matches!(err, AlertRuleValidationError::InvalidName { .. }));
        assert_eq!(err.error_code(), "invalid_name");
    }

    #[test]
    fn name_over_128_chars_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            name: "x".repeat(129),
            ..valid_rule()
        };
        let err = rule.validate(&registry).expect_err("long name must fail");
        assert!(matches!(err, AlertRuleValidationError::InvalidName { .. }));
    }

    #[test]
    fn budget_threshold_above_100_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            threshold: 101.0,
            ..valid_rule()
        };
        let err = rule
            .validate(&registry)
            .expect_err("threshold 101 must fail for budget_spent_pct");
        assert!(matches!(err, AlertRuleValidationError::InvalidThreshold { .. }));
        assert_eq!(err.error_code(), "invalid_threshold");
    }

    #[test]
    fn budget_threshold_below_zero_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            threshold: -1.0,
            ..valid_rule()
        };
        let err = rule
            .validate(&registry)
            .expect_err("negative threshold must fail for budget_spent_pct");
        assert!(matches!(err, AlertRuleValidationError::InvalidThreshold { .. }));
    }

    #[test]
    fn non_finite_threshold_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            threshold: f64::NAN,
            ..valid_rule()
        };
        let err = rule.validate(&registry).expect_err("NaN threshold must fail");
        assert!(matches!(err, AlertRuleValidationError::InvalidThreshold { .. }));
    }

    #[test]
    fn anomaly_threshold_negative_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            metric: RuleMetric::AnomalyScore,
            threshold: -0.1,
            ..valid_rule()
        };
        let err = rule
            .validate(&registry)
            .expect_err("negative anomaly_score threshold must fail");
        assert!(matches!(err, AlertRuleValidationError::InvalidThreshold { .. }));
    }

    #[test]
    fn evaluation_window_not_in_allowed_set_rejected() {
        let registry = TestRegistry::with(&["slack-ops"]);
        let rule = AlertRule {
            evaluation_window_seconds: 600,
            ..valid_rule()
        };
        let err = rule.validate(&registry).expect_err("600 is not in {300, 900, 3600}");
        assert!(matches!(
            err,
            AlertRuleValidationError::InvalidEvaluationWindow { value: 600 }
        ));
        assert_eq!(err.error_code(), "invalid_evaluation_window");
    }
}
