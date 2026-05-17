//! Wire-mirror types for the `GET /api/v1/traces/:session_id` response
//! (AAASM-1475).
//!
//! `aa-api` returns `TraceResponse { session_id, agent_id, spans }` where
//! each span is a flat record with `parent_span_id` linking. The CLI
//! consumes a richer hierarchical [`SessionTrace`] (see
//! [`super::models`]). These types let us deserialize the wire shape
//! without forcing `aa-cli` to depend on `aa-api`; the
//! [`From<WireTraceResponse> for SessionTrace`] impl folds the flat
//! span list into the tree the CLI renderer expects.

use chrono::{DateTime, Utc};
use serde::Deserialize;

/// Wire shape of `TraceResponse` from `aa-api`.
#[derive(Debug, Clone, Deserialize)]
pub struct WireTraceResponse {
    pub session_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub spans: Vec<WireTraceSpan>,
}

/// Wire shape of one `TraceSpan` from `aa-api`.
#[derive(Debug, Clone, Deserialize)]
pub struct WireTraceSpan {
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: Option<String>,
    pub operation: String,
    #[serde(default)]
    pub decision: Option<String>,
    pub start_time: DateTime<Utc>,
    #[serde(default)]
    pub end_time: Option<DateTime<Utc>>,
}
