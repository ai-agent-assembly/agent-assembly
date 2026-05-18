//! AAASM-1496 / F122 ST-O — Live-gateway HTTP integration tests for
//! `GET /api/v1/traces/{session_id}`.
//!
//! ## Endpoint surface (aa-api/src/routes/traces.rs)
//!
//! ```text
//! GET /api/v1/traces/{session_id} → 200 | 404
//! {
//!   "session_id": String,
//!   "agent_id":   String,
//!   "spans": [
//!     {
//!       "span_id":        String,
//!       "parent_span_id": String | null,
//!       "operation":      String,
//!       "decision":       String | null,
//!       "start_time":     ISO-8601,
//!       "end_time":       ISO-8601 | null
//!     }
//!   ]
//! }
//! ```
//!
//! ## Handler constraints (documented once, applied throughout)
//!
//! The current handler has **no query-param filtering** — no `span_type`,
//! `max_depth`, `include_internal`, or pagination parameters. Tests that
//! the ticket described as filter/pagination tests are adapted to verify
//! the equivalent behaviour on the actual endpoint surface:
//!
//! * TC-5 (filter_by_span_type) → all seeded operation types present in
//!   the unfiltered response.
//! * TC-6 (filter_by_max_depth) → parent_span_id links preserved at every
//!   depth level.
//! * TC-7 (filter_excludes_internal) → spans with null decision still
//!   included (no server-side exclusion).
//! * TC-8 (pagination_for_large_session) → all 100 spans returned (no
//!   server-side limit within default store capacity of 1 000).
//! * TC-9 (cursor_returns_next_page) → stable chronological ordering as
//!   the pagination-completeness proxy.
//! * TC-10 (empty_session_id) → routing falls through to 404 (no panic).
//!
//! ## Seeding
//!
//! `env.trace_store.record_span(session_id, agent_id, TraceSpan {…})`
//! — same pattern as CLI ST-12 (AAASM-1468).
//!
//! ## Isolation
//!
//! Each test uses a unique session_id prefixed `f122-traces-it-` so tests
//! do not interfere with each other even when sharing a TopologyTestEnv.

mod common;

use aa_api::models::trace::TraceSpan;
use chrono::{TimeZone, Utc};
use common::TopologyTestEnv;

fn make_span(span_id: &str, operation: &str, hour: u32) -> TraceSpan {
    TraceSpan {
        span_id: span_id.to_string(),
        parent_span_id: None,
        operation: operation.to_string(),
        decision: Some("allow".to_string()),
        start_time: Utc.with_ymd_and_hms(2026, 5, 18, hour, 0, 0).unwrap(),
        end_time: None,
    }
}

// ── TC-1: happy path — single span, all fields present ───────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn traces_for_session_with_single_span_returns_span() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let session_id = "f122-traces-it-01";

    env.trace_store
        .record_span(session_id, "agent-it-01", make_span("span-01", "llm_completion", 10))
        .unwrap();

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/traces/{session_id}", env.base_url()))
        .await
        .expect("GET /api/v1/traces/{session_id}")
        .json()
        .await
        .expect("body as JSON");

    assert_eq!(body["session_id"].as_str(), Some(session_id), "session_id mismatch");
    assert_eq!(body["agent_id"].as_str(), Some("agent-it-01"), "agent_id mismatch");

    let spans = body["spans"].as_array().expect("spans should be array");
    assert_eq!(spans.len(), 1, "expected 1 span");
    assert_eq!(spans[0]["span_id"].as_str(), Some("span-01"));
    assert_eq!(spans[0]["operation"].as_str(), Some("llm_completion"));
    assert!(
        spans[0]["start_time"].as_str().is_some(),
        "start_time should be present"
    );
}
