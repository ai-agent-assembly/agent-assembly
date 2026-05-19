//! Alert storage and capture for the API layer.
//!
//! Budget alerts are broadcast ephemerally via `tokio::broadcast`. This module
//! provides persistent storage so the `GET /api/v1/alerts` endpoint can return
//! historical alerts.

pub mod capture;
pub mod store;

use aa_gateway::budget::types::BudgetAlert;
use serde::Serialize;

/// Stored representation of an alert with metadata.
#[derive(Debug, Clone, Serialize)]
pub struct StoredAlert {
    /// Auto-incremented alert identifier.
    pub id: u64,
    /// Alert severity level derived from `threshold_pct`.
    pub severity: AlertSeverity,
    /// Source classification — `Budget` today, `SecretDetected` once
    /// secret-detection alerts are emitted (AAASM-1545).
    pub category: AlertCategory,
    /// Human-readable alert message.
    pub message: String,
    /// Hex-encoded agent ID that triggered the alert.
    pub agent_id: String,
    /// ISO 8601 timestamp when the alert was captured.
    pub timestamp: String,
    /// Budget threshold percentage that was crossed.
    pub threshold_pct: u8,
    /// Current spend in USD at the time of the alert.
    pub spent_usd: f64,
    /// Configured daily limit in USD.
    pub limit_usd: f64,
    /// Lifecycle status — `"unresolved"` on capture, flipped to
    /// `"resolved"` once `AlertStore::resolve` is called.
    pub status: String,
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

/// Convert a `BudgetAlert` into a `StoredAlert` with the given ID and timestamp.
pub fn stored_alert_from(alert: &BudgetAlert, id: u64, timestamp: String) -> StoredAlert {
    StoredAlert {
        id,
        severity: severity_from_threshold(alert.threshold_pct),
        category: AlertCategory::Budget,
        message: build_alert_message(alert),
        agent_id: format_agent_id(&alert.agent_id),
        timestamp,
        threshold_pct: alert.threshold_pct,
        spent_usd: alert.spent_usd,
        limit_usd: alert.limit_usd,
        status: "unresolved".to_string(),
        updated_at: None,
        detected_pattern_type: None,
        redacted_value: None,
    }
}

/// Trait for storing and querying alerts.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait AlertStore: Send + Sync {
    /// Record a new budget alert, returning the assigned ID.
    fn record(&self, alert: &BudgetAlert) -> u64;

    /// List stored alerts with pagination.
    ///
    /// Returns `(alerts, total_count)`. Results are ordered newest-first.
    fn list(&self, limit: usize, offset: usize) -> (Vec<StoredAlert>, u64);

    /// Retrieve a single alert by its numeric ID, or `None` if the ID is
    /// unknown or has been evicted by the ring buffer.
    fn get(&self, id: u64) -> Option<StoredAlert>;

    /// Mark an alert as resolved. Returns the post-mutation record, or
    /// `None` if the ID is unknown / evicted. Must be **idempotent** —
    /// calling `resolve` on an already-resolved alert returns the same
    /// record and does not bump `updated_at`. `_reason` is accepted for
    /// API parity but the in-memory store does not persist it.
    fn resolve(&self, id: u64, _reason: Option<&str>) -> Option<StoredAlert>;
}
