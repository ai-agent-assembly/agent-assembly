//! AAASM-3376 — `/api/v1/traces/{session_id}` reconstructs spans from the
//! persisted audit log when the in-memory `TraceStore` is empty.
//!
//! Regression: the in-memory store is never fed by the live pipeline, so the
//! endpoint always returned 404. With trace_id/span_id now carried in the
//! audit payload, the endpoint falls back to the audit log.

mod common;

use std::sync::Arc;

use aa_api::models::trace::TraceResponse;
use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType};
use aa_gateway::AuditReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

/// Mirror `aa-gateway::service::convert::hash_to_16`.
fn hash_to_16(s: &str) -> [u8; 16] {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[tokio::test]
async fn get_trace_reconstructs_spans_from_audit_log() {
    let mut state = common::test_state();

    // Point the audit reader at a fresh directory we control, and write a
    // CheckAction audit entry whose payload carries span_id (as the live
    // pipeline now does).
    let dir = tempfile::tempdir().unwrap();
    let agent = AgentId::from_bytes([3u8; 16]);
    let trace_id = "trace-from-audit-1";
    let session = SessionId::from_bytes(hash_to_16(trace_id));

    let payload = serde_json::json!({
        "action_type": 1,
        "decision": 1,
        "trace_id": trace_id,
        "span_id": "span-aaa",
    })
    .to_string();

    let entry = AuditEntry::new(
        0,
        1_700_000_000_000_000_000,
        AuditEventType::ToolCallIntercepted,
        agent,
        session,
        payload,
        [0u8; 32],
    );

    let path = dir.path().join("agent-3-sess.jsonl");
    std::fs::write(&path, serde_json::to_string(&entry).unwrap() + "\n").unwrap();
    state.audit_reader = Arc::new(AuditReader::new(dir.path().to_path_buf()));

    let app = aa_api::server::build_app(state);

    // Query by the hex-encoded session_id (what /logs renders and clients use).
    let session_hex = hex::encode(session.as_bytes());
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/traces/{session_hex}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "endpoint must reconstruct the trace from the audit log instead of 404"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let trace: TraceResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(trace.session_id, session_hex);
    assert_eq!(trace.agent_id, hex::encode(agent.as_bytes()));
    assert_eq!(trace.spans.len(), 1, "one audit entry yields one span");
    assert_eq!(
        trace.spans[0].span_id, "span-aaa",
        "span_id must come from the audit payload"
    );
}

#[tokio::test]
async fn get_trace_still_404_when_no_audit_entry_matches() {
    let state = common::test_state();
    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/traces/deadbeefdeadbeefdeadbeefdeadbeef")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
