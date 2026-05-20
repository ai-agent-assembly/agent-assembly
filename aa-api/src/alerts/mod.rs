//! Alert storage and capture for the API layer.
//!
//! Budget alerts are broadcast ephemerally via `tokio::broadcast`. This module
//! provides persistent storage so the `GET /api/v1/alerts` endpoint can return
//! historical alerts.

pub mod capture;
pub mod detail;
pub mod event;
pub mod silence;
pub mod store;

pub use event::AlertEvent;

use aa_gateway::alerts::SecretAlert;
use aa_gateway::budget::types::BudgetAlert;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::alerts::detail::RuleContext;

/// Stored representation of an alert with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAlert {
    /// Lexicographically sortable, URL-safe ULID identifier (26 chars).
    pub id: String,
    /// Alert severity level derived from `threshold_pct`.
    pub severity: AlertSeverity,
    /// Source classification — `Budget` today, `SecretDetected` once
    /// secret-detection alerts are emitted (AAASM-1545).
    pub category: AlertCategory,
    /// Human-readable alert message.
    pub message: String,
    /// Hex-encoded agent ID that triggered the alert.
    pub agent_id: String,
    /// Team attribution propagated from the request context. `None` for
    /// alerts where no team was associated (e.g. legacy budget alerts
    /// emitted without a team).
    pub team_id: Option<String>,
    /// ISO 8601 timestamp when the alert was captured.
    pub timestamp: String,
    /// Budget threshold percentage that was crossed.
    pub threshold_pct: u8,
    /// Current spend in USD at the time of the alert.
    pub spent_usd: f64,
    /// Configured daily limit in USD.
    pub limit_usd: f64,
    /// Lifecycle status — `"unresolved"` on capture, flipped to
    /// `"resolved"` once `AlertStore::resolve` is called, or
    /// `"suppressed"` while an active silence covers the alert
    /// (AAASM-1645).
    pub status: String,
    /// Status the alert held immediately before being suppressed
    /// (AAASM-1645). Populated only while `status == "suppressed"`;
    /// the expiry watcher reads it to know whether to restore the
    /// alert to `"unresolved"` or `"resolved"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prior_status: Option<String>,
    /// ISO 8601 timestamp of the last mutation (e.g. resolve). `None`
    /// while the alert is still in its initial captured state.
    pub updated_at: Option<String>,
    /// Primary detected credential kind for `SecretDetected` alerts
    /// (e.g. `"AwsAccessKey"`). `None` for `Budget` alerts.
    pub detected_pattern_type: Option<String>,
    /// `[REDACTED:<Kind>]` label for `SecretDetected` alerts. Never
    /// contains any byte of the original secret. `None` for budget
    /// alerts.
    pub redacted_value: Option<String>,
    /// ISO 8601 timestamp of the first fire — mirrors `timestamp` for
    /// budget/secret alerts and is set explicitly for rule alerts so
    /// re-fires within a dedup window keep the original fire time.
    pub first_fired_at: String,
    /// ISO 8601 timestamp at which the alert was resolved. `None`
    /// while the alert is still firing.
    pub resolved_at: Option<String>,
    /// Rich rule-engine context attached to alerts that came from the
    /// rule engine. `None` for legacy budget/secret alerts. See
    /// AAASM-1385 for the full schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_context: Option<RuleContext>,
}

/// Alert severity level derived from the budget threshold percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// Informational alert (threshold < 75%).
    Info,
    /// Warning alert (75% <= threshold < 90%).
    Warning,
    /// Critical alert (threshold >= 90%).
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Warning => write!(f, "warning"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Classification of an alert by its source signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertCategory {
    /// Budget threshold crossed.
    Budget,
    /// One or more credential / sensitive-value patterns detected in an
    /// outbound payload by the gateway's credential scanner.
    SecretDetected,
}

impl std::fmt::Display for AlertCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertCategory::Budget => write!(f, "budget"),
            AlertCategory::SecretDetected => write!(f, "secret_detected"),
        }
    }
}

/// Derive severity from a budget threshold percentage.
pub fn severity_from_threshold(threshold_pct: u8) -> AlertSeverity {
    if threshold_pct >= 90 {
        AlertSeverity::Critical
    } else if threshold_pct >= 75 {
        AlertSeverity::Warning
    } else {
        AlertSeverity::Info
    }
}

/// Format an `AgentId` as a hex string for display in API responses.
fn format_agent_id(agent_id: &aa_core::AgentId) -> String {
    agent_id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a human-readable alert message from a `BudgetAlert`.
fn build_alert_message(alert: &BudgetAlert) -> String {
    format!(
        "Budget alert: agent {} crossed {}% threshold (${:.2} / ${:.2})",
        format_agent_id(&alert.agent_id),
        alert.threshold_pct,
        alert.spent_usd,
        alert.limit_usd,
    )
}

/// Build a human-readable alert message for a [`SecretAlert`].
fn build_secret_alert_message(alert: &SecretAlert) -> String {
    let kind = alert.primary_kind().as_str();
    if alert.finding_count <= 1 {
        format!(
            "Secret detected: agent {} attempted to send a {} value in outbound payload (redacted)",
            format_agent_id(&alert.agent_id),
            kind,
        )
    } else {
        format!(
            "Secret detected: agent {} attempted to send {} values ({} primary) in outbound payload (redacted)",
            format_agent_id(&alert.agent_id),
            alert.finding_count,
            kind,
        )
    }
}

/// Convert a [`SecretAlert`] into a [`StoredAlert`] with the given ID
/// and timestamp. Severity is always `Critical` per AAASM-1545.
pub fn stored_secret_alert_from(alert: &SecretAlert, id: String, timestamp: String) -> StoredAlert {
    let kind = alert.primary_kind();
    StoredAlert {
        id,
        severity: AlertSeverity::Critical,
        category: AlertCategory::SecretDetected,
        message: build_secret_alert_message(alert),
        agent_id: format_agent_id(&alert.agent_id),
        team_id: alert.team_id.clone(),
        timestamp: timestamp.clone(),
        threshold_pct: 0,
        spent_usd: 0.0,
        limit_usd: 0.0,
        status: "unresolved".to_string(),
        prior_status: None,
        updated_at: None,
        detected_pattern_type: Some(kind.as_str().to_string()),
        redacted_value: Some(alert.redacted_label()),
        first_fired_at: timestamp,
        resolved_at: None,
        rule_context: None,
    }
}

/// Convert a `BudgetAlert` into a `StoredAlert` with the given ID and timestamp.
pub fn stored_alert_from(alert: &BudgetAlert, id: String, timestamp: String) -> StoredAlert {
    StoredAlert {
        id,
        severity: severity_from_threshold(alert.threshold_pct),
        category: AlertCategory::Budget,
        message: build_alert_message(alert),
        agent_id: format_agent_id(&alert.agent_id),
        team_id: alert.team_id.clone(),
        timestamp: timestamp.clone(),
        threshold_pct: alert.threshold_pct,
        spent_usd: alert.spent_usd,
        limit_usd: alert.limit_usd,
        status: "unresolved".to_string(),
        prior_status: None,
        updated_at: None,
        detected_pattern_type: None,
        redacted_value: None,
        first_fired_at: timestamp,
        resolved_at: None,
        rule_context: None,
    }
}

/// Trait for storing and querying alerts.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait AlertStore: Send + Sync {
    /// Record a new budget alert, returning the assigned ULID.
    fn record(&self, alert: &BudgetAlert) -> String;

    /// Record a new secret-detection alert, returning the assigned ULID
    /// (AAASM-1545). The stored alert has `severity=critical` and
    /// `category=secret_detected`.
    fn record_secret(&self, alert: &SecretAlert) -> String;

    /// List stored alerts with pagination.
    ///
    /// Returns `(alerts, total_count)`. Results are ordered newest-first.
    fn list(&self, limit: usize, offset: usize) -> (Vec<StoredAlert>, u64);

    /// Retrieve a single alert by its ULID, or `None` if the ID is
    /// unknown or has been evicted by the ring buffer.
    fn get(&self, id: &str) -> Option<StoredAlert>;

    /// Mark an alert as resolved. Returns the post-mutation record, or
    /// `None` if the ID is unknown / evicted. Must be **idempotent** —
    /// calling `resolve` on an already-resolved alert returns the same
    /// record and does not bump `updated_at`. `_reason` is accepted for
    /// API parity but the in-memory store does not persist it.
    fn resolve(&self, id: &str, _reason: Option<&str>) -> Option<StoredAlert>;

    /// Subscribe to the lifecycle event bus. Each mutation
    /// (`record`/`record_secret` → `Fire`, `resolve` → `Resolve`,
    /// `suppress` → `Silence`) publishes one [`AlertEvent`] carrying
    /// a snapshot of the post-mutation alert. Implementations that
    /// don't emit events should still return a live receiver.
    fn subscribe(&self) -> broadcast::Receiver<AlertEvent>;
}
