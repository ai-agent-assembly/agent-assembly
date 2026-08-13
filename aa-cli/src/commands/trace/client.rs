//! HTTP client for fetching session traces from the gateway API.
//!
//! `aa-api` returns `TraceResponse { session_id, agent_id, spans }` — a
//! flat list of spans linked via `parent_span_id`. The CLI renderer
//! consumes a hierarchical [`SessionTrace`]. This module deserializes
//! the wire shape into [`WireTraceResponse`] and converts to
//! `SessionTrace` via the `From` impl in [`super::wire`] (AAASM-1475).

use crate::client;
use crate::config::ResolvedContext;
use crate::error::CliError;

use super::models::SessionTrace;
use super::wire::WireTraceResponse;

/// Build the trace request path (relative to `ctx.api_url`, which the shared
/// [`crate::client`] helpers prepend).
pub fn build_trace_path(session_id: &str) -> String {
    format!("/api/v1/traces/{session_id}")
}

/// Fetch a session trace from the gateway API.
///
/// Routed through the shared [`crate::client`] so it gets stored-session auth
/// with silent refresh and actionable `401`/`403` errors like every other
/// remote command (AAASM-5508 / AAASM-5513).
pub async fn fetch_trace(ctx: &ResolvedContext, session_id: &str) -> Result<SessionTrace, CliError> {
    let wire: WireTraceResponse = client::get_json(ctx, &build_trace_path(session_id)).await?;
    Ok(SessionTrace::from(wire))
}
