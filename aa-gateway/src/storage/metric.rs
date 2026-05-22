//! Metric storage value types — sample record, query, and result point.

use std::collections::BTreeMap;

use aa_core::identity::AgentId;
use chrono::{DateTime, Utc};

/// A single metric sample that may be persisted to storage.
#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    /// Sample timestamp (UTC).
    pub ts: DateTime<Utc>,
    /// Agent the metric is attributed to.
    pub agent_id: AgentId,
    /// Metric name (e.g. `"tokens_used"`, `"events_per_sec"`, `"cost_usd"`).
    pub metric: String,
    /// Numeric sample value.
    pub value: f64,
    /// Free-form labels for slicing (e.g. provider, model, tool).
    pub labels: BTreeMap<String, String>,
}

/// Query parameters for fetching metric points.
#[derive(Debug, Clone, Default)]
pub struct MetricQuery {
    /// Restrict to this agent.
    pub agent_id: Option<AgentId>,
    /// Restrict to this metric name.
    pub metric: Option<String>,
    /// Inclusive lower bound (UTC).
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper bound (UTC).
    pub to: Option<DateTime<Utc>>,
    /// Optional aggregation bucket (e.g. `"1 minute"`, `"1 hour"`).
    pub bucket: Option<String>,
    /// Maximum number of points to return.
    pub limit: Option<u32>,
}

/// A single metric data point returned by [`MetricQuery`].
#[derive(Debug, Clone, PartialEq)]
pub struct MetricPoint {
    /// Bucket timestamp (UTC). For raw samples this is the sample's `ts`.
    pub ts: DateTime<Utc>,
    /// Aggregated or raw value at this timestamp.
    pub value: f64,
}
