//! Rich detail types backing the `GET /api/v1/alerts/{id}` response.
//!
//! These types describe the rule-based alert payload from the AAASM-1385
//! spec — rule snapshot at fire time, routing-log entries written by the
//! connector framework, and active silence records.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Snapshot of the rule definition at the moment the alert fired.
///
/// Recording the rule inline keeps alert detail self-contained — operators
/// see the exact thresholds and windows that triggered the fire, even if
/// the underlying rule has since been edited.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RuleSnapshot {
    /// Metric the rule evaluates (e.g. `"budget_spent_pct"`).
    pub metric: String,
    /// Comparison operator (`">"`, `"<"`, `">="`, etc.).
    pub operator: String,
    /// Numeric threshold the metric is compared against.
    pub threshold: f64,
    /// Window over which the metric is aggregated before evaluation.
    pub evaluation_window_seconds: u32,
    /// Severity level emitted when the rule fires (e.g. `"CRITICAL"`).
    pub severity: String,
    /// Window during which subsequent fires are deduplicated. `0`
    /// disables deduplication.
    pub dedup_window_seconds: u32,
    /// Label selectors used to suppress otherwise-matching alerts. The
    /// `BTreeMap` ordering keeps OpenAPI examples deterministic.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub suppression_labels: BTreeMap<String, String>,
}

/// One delivery attempt by the connector framework for a routed alert.
///
/// Each entry records the outcome of fanning an alert out to a configured
/// destination — Slack, PagerDuty, webhook, etc. The framework appends a
/// new entry per attempt; dedup-suppressed re-fires must NOT add entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct RoutingLogEntry {
    /// Identifier of the destination the alert was routed to.
    pub destination_id: String,
    /// ISO 8601 timestamp at which the connector framework completed
    /// the delivery attempt.
    pub delivered_at: String,
    /// Outcome label — typically `"ok"`, `"error"`, or a connector-
    /// specific status string.
    pub status: String,
}

/// Rich rule-based context attached to an alert.
///
/// Populated when an alert was produced by the rule engine (rather than
/// the legacy budget/secret-detection pipelines). The `GET /api/v1/alerts/{id}`
/// endpoint surfaces this payload so the dashboard detail drawer can render
/// the rule definition, routing log, and dedup state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct RuleContext {
    /// Identifier of the rule that produced the alert.
    pub rule_id: String,
    /// Human-readable rule name as configured in the dashboard.
    pub rule_name: String,
    /// Snapshot of the rule definition at fire time.
    pub rule_snapshot: RuleSnapshot,
    /// Destinations the rule was routed to. Order matches the
    /// destination registry's configured priority.
    #[serde(default)]
    pub destination_ids: Vec<String>,
    /// Free-form payload of the triggering event — metric value,
    /// recent samples, or any rule-specific context.
    #[serde(default)]
    pub event_payload: serde_json::Value,
    /// Connector-framework delivery log. One entry per successful
    /// attempt; dedup-suppressed re-fires do not append entries.
    #[serde(default)]
    pub routing_log: Vec<RoutingLogEntry>,
    /// Active silence record, if one was applied. `None` when the
    /// alert is firing normally.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub silence: Option<Silence>,
    /// Number of times this alert has matched within the active dedup
    /// window, including the fire that opened it. `1` when no
    /// deduplication has happened yet.
    pub dedup_occurrence_count: u32,
    /// Timestamp when the active dedup window ends. `None` when the
    /// alert is not inside a dedup window (e.g. resolved alerts or
    /// rules with `dedup_window_seconds == 0`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dedup_window_expires_at: Option<String>,
}

/// Active silence record attached to an alert.
///
/// Present when an operator has acknowledged the alert and asked the
/// notification framework to suppress further routing until `expires_at`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Silence {
    /// Stable identifier of the silence record.
    pub id: String,
    /// ISO 8601 timestamp at which the silence expires.
    pub expires_at: String,
    /// Optional free-text reason captured at silence creation time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule_snapshot() -> RuleSnapshot {
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        RuleSnapshot {
            metric: "budget_spent_pct".to_string(),
            operator: ">".to_string(),
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: "CRITICAL".to_string(),
            dedup_window_seconds: 600,
            suppression_labels: labels,
        }
    }

    #[test]
    fn rule_context_round_trips_with_routing_log_and_silence() {
        let ctx = RuleContext {
            rule_id: "rule-budget-90".to_string(),
            rule_name: "Budget threshold > 90%".to_string(),
            rule_snapshot: sample_rule_snapshot(),
            destination_ids: vec!["slack-ops".to_string()],
            event_payload: serde_json::json!({ "metric_value": 92.3 }),
            routing_log: vec![RoutingLogEntry {
                destination_id: "slack-ops".to_string(),
                delivered_at: "2026-05-13T09:12:01Z".to_string(),
                status: "ok".to_string(),
            }],
            silence: Some(Silence {
                id: "sil-001".to_string(),
                expires_at: "2026-05-13T10:12:00Z".to_string(),
                reason: None,
            }),
            dedup_occurrence_count: 1,
            dedup_window_expires_at: Some("2026-05-13T09:22:00Z".to_string()),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: RuleContext = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ctx);
    }

    #[test]
    fn rule_context_omits_silence_and_dedup_expiry_when_none() {
        let ctx = RuleContext {
            rule_id: "rule-budget-90".to_string(),
            rule_name: "Budget threshold > 90%".to_string(),
            rule_snapshot: sample_rule_snapshot(),
            destination_ids: vec![],
            event_payload: serde_json::Value::Null,
            routing_log: vec![],
            silence: None,
            dedup_occurrence_count: 1,
            dedup_window_expires_at: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("\"silence\""), "silence must be omitted when None");
        assert!(
            !json.contains("dedup_window_expires_at"),
            "dedup_window_expires_at must be omitted when None",
        );
    }

    #[test]
    fn rule_snapshot_round_trips_with_suppression_labels() {
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "prod".to_string());
        labels.insert("region".to_string(), "us-west".to_string());

        let snapshot = RuleSnapshot {
            metric: "budget_spent_pct".to_string(),
            operator: ">".to_string(),
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: "CRITICAL".to_string(),
            dedup_window_seconds: 600,
            suppression_labels: labels,
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: RuleSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn rule_snapshot_omits_empty_suppression_labels() {
        let snapshot = RuleSnapshot {
            metric: "p95_latency_ms".to_string(),
            operator: ">".to_string(),
            threshold: 250.0,
            evaluation_window_seconds: 60,
            severity: "HIGH".to_string(),
            dedup_window_seconds: 0,
            suppression_labels: BTreeMap::new(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(
            !json.contains("suppression_labels"),
            "empty suppression_labels must be omitted from JSON",
        );
    }

    #[test]
    fn routing_log_entry_round_trips() {
        let entry = RoutingLogEntry {
            destination_id: "slack-ops".to_string(),
            delivered_at: "2026-05-13T09:12:01Z".to_string(),
            status: "ok".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RoutingLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn silence_round_trips_with_reason() {
        let silence = Silence {
            id: "sil-001".to_string(),
            expires_at: "2026-05-20T10:00:00Z".to_string(),
            reason: Some("planned maintenance".to_string()),
        };
        let json = serde_json::to_string(&silence).unwrap();
        let parsed: Silence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, silence);
    }

    #[test]
    fn silence_omits_reason_when_none() {
        let silence = Silence {
            id: "sil-002".to_string(),
            expires_at: "2026-05-20T10:00:00Z".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&silence).unwrap();
        assert!(!json.contains("reason"), "reason field must be omitted when None");
        let parsed: Silence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.reason, None);
    }
}
