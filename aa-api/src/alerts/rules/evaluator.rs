//! Minimum-viable alert-rule evaluator (AAASM-1386).
//!
//! Polls a [`MetricSource`] at each rule's `evaluation_window_seconds`
//! cadence; when the condition holds the rule "fires" and an entry is
//! recorded into the [`AlertStore`]. The full hookup for non-budget
//! metrics is deferred per the Story AC — those metric variants return
//! `None` here and are silently skipped by the evaluator.

use std::sync::Arc;
use std::time::Duration;

use aa_core::AgentId;
use aa_gateway::budget::types::BudgetAlert;
use tokio::task::JoinHandle;

use crate::alerts::rules::store::AlertRuleStore;
use crate::alerts::rules::types::{AlertRule, RuleMetric, RuleOperator};
use crate::alerts::AlertStore;

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
pub struct NullMetricSource;

impl MetricSource for NullMetricSource {
    fn current_value(&self, _metric: RuleMetric) -> Option<f64> {
        None
    }
}

/// Returns true when the current metric `value` satisfies the rule's
/// `operator` ⟂ `threshold` condition.
pub fn evaluate(rule: &AlertRule, value: f64) -> bool {
    match rule.operator {
        RuleOperator::Gt => value > rule.threshold,
        RuleOperator::Gte => value >= rule.threshold,
        RuleOperator::Lt => value < rule.threshold,
        RuleOperator::Eq => (value - rule.threshold).abs() < f64::EPSILON,
    }
}

/// Run one evaluation pass over every enabled rule, recording an alert
/// into `alerts` when the condition holds. Returns the number of
/// alerts recorded by this pass.
pub fn evaluate_once<S: MetricSource + ?Sized>(
    rules: &dyn AlertRuleStore,
    metrics: &S,
    alerts: &dyn AlertStore,
) -> usize {
    let mut fired = 0;
    for rule in rules.list(Some(true)) {
        let Some(value) = metrics.current_value(rule.metric) else {
            continue;
        };
        if !evaluate(&rule, value) {
            continue;
        }
        // Synthetic budget-shaped alert is the only one the existing
        // AlertStore knows how to ingest — non-budget rule firings are
        // intentionally swallowed in the MVP and tracked as follow-ups.
        if matches!(rule.metric, RuleMetric::BudgetSpentPct) {
            let synthetic = BudgetAlert {
                agent_id: AgentId::from_bytes([0u8; 16]),
                team_id: None,
                threshold_pct: rule.threshold.clamp(0.0, 100.0) as u8,
                spent_usd: value,
                limit_usd: 100.0,
            };
            alerts.record(&synthetic);
            fired += 1;
        }
    }
    fired
}

/// Spawn the evaluator on a background tokio task. The loop ticks at
/// `tick_period` (chosen by the caller — production uses 60 seconds;
/// tests use much shorter) and calls [`evaluate_once`] on every tick.
///
/// Cancel the returned [`JoinHandle`] to stop the loop.
pub fn spawn_rule_evaluator<S>(
    rules: Arc<dyn AlertRuleStore>,
    metrics: Arc<S>,
    alerts: Arc<dyn AlertStore>,
    tick_period: Duration,
) -> JoinHandle<()>
where
    S: MetricSource + 'static,
{
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tick_period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            evaluate_once(rules.as_ref(), metrics.as_ref(), alerts.as_ref());
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::rules::store::InMemoryAlertRuleStore;
    use crate::alerts::rules::types::{RuleMetric, RuleOperator, RuleSeverity};
    use crate::alerts::store::InMemoryAlertStore;
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

    struct FixedMetric(f64);

    impl MetricSource for FixedMetric {
        fn current_value(&self, metric: RuleMetric) -> Option<f64> {
            if matches!(metric, RuleMetric::BudgetSpentPct) {
                Some(self.0)
            } else {
                None
            }
        }
    }

    #[test]
    fn evaluate_once_fires_only_when_condition_holds() {
        let rules = InMemoryAlertRuleStore::new();
        rules.create(rule(RuleOperator::Gt, 90.0)).expect("create");
        let alerts = InMemoryAlertStore::new();

        // Below threshold -> no fire
        let fired = evaluate_once(&rules, &FixedMetric(80.0), &alerts);
        assert_eq!(fired, 0);

        // Above threshold -> fires once
        let fired = evaluate_once(&rules, &FixedMetric(95.0), &alerts);
        assert_eq!(fired, 1);
    }

    #[test]
    fn evaluate_once_skips_disabled_rules() {
        let rules = InMemoryAlertRuleStore::new();
        let mut disabled = rule(RuleOperator::Gt, 90.0);
        disabled.enabled = false;
        rules.create(disabled).expect("create");
        let alerts = InMemoryAlertStore::new();

        let fired = evaluate_once(&rules, &FixedMetric(95.0), &alerts);
        assert_eq!(fired, 0);
    }

    #[test]
    fn null_metric_source_never_fires() {
        let rules = InMemoryAlertRuleStore::new();
        rules.create(rule(RuleOperator::Gt, 90.0)).expect("create");
        let alerts = InMemoryAlertStore::new();

        let fired = evaluate_once(&rules, &NullMetricSource, &alerts);
        assert_eq!(fired, 0);
    }
}
