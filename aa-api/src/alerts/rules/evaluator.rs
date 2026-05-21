//! Minimum-viable alert-rule evaluator (AAASM-1386).
//!
//! Polls a [`MetricSource`] at each rule's `evaluation_window_seconds`
//! cadence; when the condition holds the rule "fires" and an entry is
//! recorded into the [`AlertStore`]. The full hookup for non-budget
//! metrics is deferred per the Story AC — those metric variants return
//! `None` here and are silently skipped by the evaluator.

use crate::alerts::rules::types::{AlertRule, RuleMetric, RuleOperator};

/// Read-only source of metric values that the evaluator consults to
/// decide whether to fire a rule.
pub trait MetricSource: Send + Sync {
    /// Current value for `metric`, or `None` when the metric has no
    /// observation yet (e.g. anomaly detector not wired in MVP).
    fn current_value(&self, metric: RuleMetric) -> Option<f64>;
}

/// MVP metric source — returns `None` for every metric. Wired into
/// `run_server` so the evaluator's plumbing is exercised end-to-end
/// without claiming MVP scope covers the anomaly/approval-age/violation
/// hookups (those are explicit follow-ups in the Story AC).
#[allow(dead_code)]
pub struct NullMetricSource;

impl MetricSource for NullMetricSource {
    fn current_value(&self, _metric: RuleMetric) -> Option<f64> {
        None
    }
}

/// Returns true when the current metric `value` satisfies the rule's
/// `operator` ⟂ `threshold` condition.
#[allow(dead_code)]
pub fn evaluate(rule: &AlertRule, value: f64) -> bool {
    match rule.operator {
        RuleOperator::Gt => value > rule.threshold,
        RuleOperator::Gte => value >= rule.threshold,
        RuleOperator::Lt => value < rule.threshold,
        RuleOperator::Eq => (value - rule.threshold).abs() < f64::EPSILON,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::rules::types::{RuleMetric, RuleOperator, RuleSeverity};
    use std::collections::HashMap;

    fn rule(operator: RuleOperator, threshold: f64) -> AlertRule {
        AlertRule {
            id: String::new(),
            name: format!("rule-{operator:?}-{threshold}"),
            description: String::new(),
            metric: RuleMetric::BudgetSpentPct,
            operator,
            threshold,
            evaluation_window_seconds: 300,
            severity: RuleSeverity::Critical,
            destination_ids: vec!["slack-ops".to_string()],
            dedup_window_seconds: 600,
            suppression_labels: HashMap::new(),
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn evaluate_honors_gt_operator() {
        assert!(evaluate(&rule(RuleOperator::Gt, 90.0), 91.0));
        assert!(!evaluate(&rule(RuleOperator::Gt, 90.0), 90.0));
        assert!(!evaluate(&rule(RuleOperator::Gt, 90.0), 89.0));
    }

    #[test]
    fn evaluate_honors_gte_operator() {
        assert!(evaluate(&rule(RuleOperator::Gte, 90.0), 90.0));
        assert!(evaluate(&rule(RuleOperator::Gte, 90.0), 91.0));
        assert!(!evaluate(&rule(RuleOperator::Gte, 90.0), 89.0));
    }

    #[test]
    fn evaluate_honors_lt_operator() {
        assert!(evaluate(&rule(RuleOperator::Lt, 50.0), 49.0));
        assert!(!evaluate(&rule(RuleOperator::Lt, 50.0), 50.0));
    }

    #[test]
    fn evaluate_honors_eq_operator() {
        assert!(evaluate(&rule(RuleOperator::Eq, 50.0), 50.0));
        assert!(!evaluate(&rule(RuleOperator::Eq, 50.0), 49.0));
    }
}
