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
