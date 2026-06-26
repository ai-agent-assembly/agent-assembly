//! Agent session trace endpoints.

use axum::http::StatusCode;
use axum::{Extension, Json};

use aa_gateway::AuditReader;

use crate::auth::scope::{RequireRead, Scope};
use crate::error::ProblemDetail;
use crate::models::trace::{TraceResponse, TraceSpan};
use crate::state::AppState;
use crate::trace_store::SessionTrace;

/// Parse a hex-encoded 16-byte agent id, or `None` if it is not 32 hex chars.
fn parse_hex_agent_id(id: &str) -> Option<[u8; 16]> {
    if id.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(id.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Owning team of the trace's agent, resolved via the registry lineage.
/// Returns `None` when the agent id does not resolve or has no team
/// (admin-only), so an unresolvable id can never widen access.
fn trace_team_id(state: &AppState, agent_id_hex: &str) -> Option<String> {
    let bytes = parse_hex_agent_id(agent_id_hex)?;
    state.agent_registry.lineage(&bytes).and_then(|l| l.team_id)
}

/// `GET /api/v1/traces/:session_id` — full trace for one agent session.
///
/// Retrieve the full ordered trace of spans for one agent session.
#[utoipa::path(
    get,
    path = "/api/v1/traces/{session_id}",
    params(("session_id" = String, Path, description = "Agent session identifier")),
    responses(
        (status = 200, description = "Session trace", body = TraceResponse),
        (status = 404, description = "Session not found")
    ),
    tag = "traces"
)]
pub async fn get_trace(
    RequireRead(caller): RequireRead,
    Extension(state): Extension<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<TraceResponse>), ProblemDetail> {
    // AAASM-3790: deny callers with neither admin scope nor a team scope up
    // front so a session trace (which can expose any agent's activity) is not
    // readable cross-tenant.
    let is_admin = caller.scopes.contains(&Scope::Admin);
    if !is_admin && caller.tenant.team_id.is_none() {
        return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
            .with_detail("This operation requires admin scope or a team scope".to_string()));
    }

    let trace = state
        .trace_store
        .get_trace(&session_id)
        .map_err(|e| ProblemDetail::from_status(StatusCode::INTERNAL_SERVER_ERROR).with_detail(e.to_string()))?;

    // AAASM-3376 — the in-memory `TraceStore` is only populated by live span
    // recording; fall back to reconstructing the trace from the persisted audit
    // log (JSONL) so a session's spans are queryable across restarts and even
    // when no in-process recorder was wired. The CheckAction audit pipeline now
    // carries `trace_id` / `span_id` in the entry payload (see
    // `aa-gateway::service::policy_service::record_audit`).
    let trace = match trace {
        Some(t) => Some(t),
        None => build_trace_from_audit(&state.audit_reader, &session_id).await,
    };

    match trace {
        Some(session_trace) => {
            // AAASM-3790: a tenant-scoped caller may read a trace only when its
            // agent belongs to the caller's team. Traces whose agent has no
            // resolvable team are admin-only.
            let authorized = match trace_team_id(&state, &session_trace.agent_id) {
                Some(team) => caller.can_access_team(&team),
                None => is_admin,
            };
            if !authorized {
                return Err(ProblemDetail::from_status(StatusCode::FORBIDDEN)
                    .with_detail("This operation requires admin scope or membership in the agent's team".to_string()));
            }
            Ok((
                StatusCode::OK,
                Json(TraceResponse {
                    session_id,
                    agent_id: session_trace.agent_id,
                    spans: session_trace.spans,
                }),
            ))
        }
        None => {
            Err(ProblemDetail::from_status(StatusCode::NOT_FOUND)
                .with_detail(format!("Session not found: {session_id}")))
        }
    }
}

/// Reconstruct a [`SessionTrace`] from persisted audit entries.
///
/// AAASM-3376 — scans the audit log for entries whose hex-encoded `session_id`
/// matches `session_id_hex`, mapping each governance event to a [`TraceSpan`].
/// The `span_id` and `trace_id` are read from the entry payload (deposited by
/// the CheckAction audit pipeline); when absent the entry's `seq` is used as a
/// stable fallback span identifier. Returns `None` when no audit entry matches.
async fn build_trace_from_audit(reader: &AuditReader, session_id_hex: &str) -> Option<SessionTrace> {
    // Pull a generous window of recent entries; the reader returns newest-first.
    let (entries, _total) = reader.list(10_000, 0, None, None, None).await.ok()?;

    let mut agent_id = String::new();
    let mut spans: Vec<TraceSpan> = Vec::new();

    for entry in &entries {
        if hex::encode(entry.session_id().as_bytes()) != session_id_hex {
            continue;
        }
        if agent_id.is_empty() {
            agent_id = hex::encode(entry.agent_id().as_bytes());
        }

        let payload: serde_json::Value = serde_json::from_str(entry.payload()).unwrap_or(serde_json::Value::Null);
        let span_id = payload
            .get("span_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| entry.seq().to_string());
        let decision = payload.get("decision").and_then(|v| v.as_i64()).map(|d| d.to_string());

        let ts_secs = (entry.timestamp_ns() / 1_000_000_000) as i64;
        let ts_nanos = (entry.timestamp_ns() % 1_000_000_000) as u32;
        let start_time = chrono::DateTime::from_timestamp(ts_secs, ts_nanos).unwrap_or_default();

        spans.push(TraceSpan {
            span_id,
            parent_span_id: None,
            operation: entry.event_type().as_str().to_string(),
            decision,
            start_time,
            end_time: None,
        });
    }

    if spans.is_empty() {
        return None;
    }

    spans.sort_by_key(|s| s.start_time);
    Some(SessionTrace { agent_id, spans })
}
