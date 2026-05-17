//! HTTP client for fetching session traces from the gateway API.
//!
//! `aa-api` returns `TraceResponse { session_id, agent_id, spans }` — a
//! flat list of spans linked via `parent_span_id`. The CLI renderer
//! consumes a hierarchical [`SessionTrace`]. This module deserializes
//! the wire shape into [`WireTraceResponse`] and converts to
//! `SessionTrace` via the `From` impl in [`super::wire`] (AAASM-1475).

use crate::config::ResolvedContext;
use crate::error::CliError;

use super::models::SessionTrace;
use super::wire::WireTraceResponse;

/// Build the full URL for the trace endpoint.
pub fn build_trace_url(ctx: &ResolvedContext, session_id: &str) -> String {
    format!("{}/api/v1/traces/{}", ctx.api_url.trim_end_matches('/'), session_id)
}

/// Fetch a session trace from the gateway API.
pub async fn fetch_trace(ctx: &ResolvedContext, session_id: &str) -> Result<SessionTrace, CliError> {
    let url = build_trace_url(ctx, session_id);
    let client = reqwest::Client::new();

    let mut request = client.get(&url);
    if let Some(ref key) = ctx.api_key {
        request = request.bearer_auth(key);
    }

    let response = request.send().await?.error_for_status()?;
    let wire: WireTraceResponse = response.json().await?;
    Ok(SessionTrace::from(wire))
}
