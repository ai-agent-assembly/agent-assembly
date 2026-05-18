//! AAASM-1494 (F122 ST-M) — Live-gateway HTTP integration tests for
//! `/api/v1/ops/{id}/{pause,resume,terminate}`.
//!
//! ## Discovered route surface (aa-api/src/routes/ops.rs — 3 handlers)
//!
//! All three handlers are **intentional stubs** — no in-flight-ops registry
//! exists in the gateway yet. The stubs exist so the Live Ops dashboard can
//! call the conventional paths without 404-ing. Real state-machine enforcement
//! is tracked in a separate architecture follow-up.
//!
//! Stub behaviour:
//! - Any non-empty `{id}` → `202 Accepted` + `OpActionAck { op_id, action, accepted_at }`
//! - Whitespace-only `{id}` → `400 Bad Request` (validated by `validate_op_id`)
//! - No 404 for "unknown" IDs (no registry to look up)
//! - No state machine → no 409 conflicts
//!
//! ## Seeding strategy
//!
//! None required. The stubs accept any string op_id and return 202 regardless
//! of whether the operation "exists". Tests supply arbitrary string IDs.
//!
//! ## Ignored tests
//!
//! Tests covering state-machine behaviour (pause/resume/terminate state
//! transitions, 409 conflicts, 404 for unknown IDs, GET list/inspect) are
//! `#[ignore]`d because the backing registry is not yet implemented. They
//! document the intended contract and should be un-ignored once the ops
//! registry architecture lands.

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;

// ── helpers ───────────────────────────────────────────────────────────────────

async fn post_op(base_url: &str, op_id: &str, action: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/api/v1/ops/{op_id}/{action}"))
        .send()
        .await
        .expect("POST op action should send")
}

// ── TC-1: pause returns 202 with correct ack shape ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_pause_returns_202_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let resp = post_op(&env.base_url(), "op-abc-1", "pause").await;

    assert_eq!(resp.status(), StatusCode::ACCEPTED, "pause should return 202");

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["action"], "pause", "action field should be 'pause'");
    assert!(body["op_id"].as_str().is_some(), "op_id should be a string");
    assert!(body["accepted_at"].as_str().is_some(), "accepted_at should be a string");
}

// ── TC-2: resume returns 202 with correct ack shape ──────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_resume_returns_202_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let resp = post_op(&env.base_url(), "op-abc-2", "resume").await;

    assert_eq!(resp.status(), StatusCode::ACCEPTED, "resume should return 202");

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["action"], "resume", "action field should be 'resume'");
    assert!(body["op_id"].as_str().is_some(), "op_id should be a string");
    assert!(body["accepted_at"].as_str().is_some(), "accepted_at should be a string");
}

// ── TC-3: terminate returns 202 with correct ack shape ───────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_terminate_returns_202_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let resp = post_op(&env.base_url(), "op-abc-3", "terminate").await;

    assert_eq!(resp.status(), StatusCode::ACCEPTED, "terminate should return 202");

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["action"], "terminate", "action field should be 'terminate'");
    assert!(body["op_id"].as_str().is_some(), "op_id should be a string");
    assert!(body["accepted_at"].as_str().is_some(), "accepted_at should be a string");
}

// ── TC-4: ack op_id echoes the URL path segment ──────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_ack_op_id_echoes_path_segment() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let op_id = "my-special-op-99";
    let resp = post_op(&env.base_url(), op_id, "pause").await;

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(
        body["op_id"].as_str(),
        Some(op_id),
        "op_id in response should echo the URL path segment",
    );
}

// ── TC-5: accepted_at is a non-empty RFC 3339 timestamp ──────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_ack_accepted_at_is_rfc3339() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let resp = post_op(&env.base_url(), "op-ts-check", "terminate").await;

    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    let ts = body["accepted_at"].as_str().expect("accepted_at should be a string");

    // Basic RFC 3339 structural check: contains 'T' (date-time separator) and '+'/Z.
    assert!(!ts.is_empty(), "accepted_at must not be empty");
    assert!(
        ts.contains('T'),
        "accepted_at should contain 'T' date-time separator, got: {ts}",
    );
    assert!(
        ts.contains('+') || ts.ends_with('Z'),
        "accepted_at should contain timezone offset, got: {ts}",
    );
}

// ── TC-6: whitespace-only op_id returns 400 ──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_whitespace_only_id_returns_400() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    // URL-encode a single space so Axum routes it as a path segment rather than
    // a missing segment (which would 404 at the router level).
    let resp = reqwest::Client::new()
        .post(format!("{}/api/v1/ops/%20/pause", env.base_url()))
        .send()
        .await
        .expect("request should send");

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "whitespace-only op id should return 400",
    );
}

// ── #[ignore] — lifecycle state machine not yet implemented ───────────────────

#[tokio::test(flavor = "multi_thread")]
#[ignore = "ops registry not yet implemented; pause currently returns 202 for any id regardless of state"]
async fn ops_pause_running_updates_state() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    // When the ops registry lands: seed a running op, POST /pause, assert 200,
    // then GET /ops/{id} and verify status == "paused".
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "ops registry not yet implemented; resume currently returns 202 for any id regardless of state"]
async fn ops_resume_paused_returns_running() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "ops registry not yet implemented; terminate currently returns 202 for any id regardless of state"]
async fn ops_terminate_already_terminated_is_idempotent() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    // Two consecutive terminate POSTs on the same op should both return 200
    // once a state machine is in place.
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "ops registry not yet implemented; stub returns 202 not 409 when terminating then pausing"]
async fn ops_pause_terminated_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "ops registry not yet implemented; stub returns 202 not 409 for invalid state transitions"]
async fn ops_resume_when_running_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "stub returns 202 for all string ids; 404 requires an ops registry lookup"]
async fn ops_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = &env;
    todo!("requires ops registry on AppState")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "GET /api/v1/ops route not registered; requires ops registry + list handler"]
async fn ops_list_returns_all_active() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = &env;
    todo!("GET /ops not registered")
}
