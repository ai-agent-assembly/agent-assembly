//! AAASM-1525 — Live-gateway HTTP integration tests for the ops lifecycle
//! endpoints (`GET /api/v1/ops`, `POST /api/v1/ops`,
//! `POST /api/v1/ops/{id}/{pause,resume,terminate}`).
//!
//! The ops registry state machine is now backed by `OpsRegistry` on `AppState`
//! (AAASM-1525). Every lifecycle test registers an op first via
//! `POST /api/v1/ops` before driving transitions.

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;

// ── helpers ───────────────────────────────────────────────────────────────────

async fn register_op(base_url: &str, op_id: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/api/v1/ops"))
        .json(&serde_json::json!({"op_id": op_id}))
        .send()
        .await
        .expect("POST /ops should send")
}

async fn post_op(base_url: &str, op_id: &str, action: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/api/v1/ops/{op_id}/{action}"))
        .send()
        .await
        .expect("POST op action should send")
}

// ── TC-1: pause returns 200 with correct ack shape ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_pause_returns_200_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-abc-1").await;
    let resp = post_op(&env.base_url(), "op-abc-1", "pause").await;

    assert_eq!(resp.status(), StatusCode::OK, "pause should return 200");

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["action"], "pause", "action field should be 'pause'");
    assert!(body["op_id"].as_str().is_some(), "op_id should be a string");
    assert!(body["accepted_at"].as_str().is_some(), "accepted_at should be a string");
}

// ── TC-2: resume returns 200 with correct ack shape ──────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_resume_returns_200_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-abc-2").await;
    post_op(&env.base_url(), "op-abc-2", "pause").await;
    let resp = post_op(&env.base_url(), "op-abc-2", "resume").await;

    assert_eq!(resp.status(), StatusCode::OK, "resume should return 200");

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["action"], "resume", "action field should be 'resume'");
    assert!(body["op_id"].as_str().is_some(), "op_id should be a string");
    assert!(body["accepted_at"].as_str().is_some(), "accepted_at should be a string");
}

// ── TC-3: terminate returns 200 with correct ack shape ───────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_terminate_returns_200_with_ack() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-abc-3").await;
    let resp = post_op(&env.base_url(), "op-abc-3", "terminate").await;

    assert_eq!(resp.status(), StatusCode::OK, "terminate should return 200");

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
    register_op(&env.base_url(), op_id).await;
    let resp = post_op(&env.base_url(), op_id, "pause").await;

    assert_eq!(resp.status(), StatusCode::OK);
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
    register_op(&env.base_url(), "op-ts-check").await;
    let resp = post_op(&env.base_url(), "op-ts-check", "terminate").await;

    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    let ts = body["accepted_at"].as_str().expect("accepted_at should be a string");

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

// ── state-machine behaviour tests (AAASM-1525) ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn ops_pause_running_updates_state() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-state-1").await;
    let resp = post_op(&env.base_url(), "op-state-1", "pause").await;
    assert_eq!(resp.status(), StatusCode::OK, "pause of running op should return 200");

    let list: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/v1/ops", env.base_url()))
        .send()
        .await
        .expect("GET /ops should send")
        .json()
        .await
        .expect("list should be JSON");

    let record = list
        .as_array()
        .expect("list should be array")
        .iter()
        .find(|r| r["op_id"] == "op-state-1")
        .expect("op-state-1 should appear in list");
    assert_eq!(record["state"], "paused", "state should be paused after pause");
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_resume_paused_returns_running() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-state-2").await;
    post_op(&env.base_url(), "op-state-2", "pause").await;
    let resp = post_op(&env.base_url(), "op-state-2", "resume").await;
    assert_eq!(resp.status(), StatusCode::OK, "resume of paused op should return 200");

    let list: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/v1/ops", env.base_url()))
        .send()
        .await
        .expect("GET /ops should send")
        .json()
        .await
        .expect("list should be JSON");

    let record = list
        .as_array()
        .expect("list should be array")
        .iter()
        .find(|r| r["op_id"] == "op-state-2")
        .expect("op-state-2 should appear in list");
    assert_eq!(record["state"], "running", "state should be running after resume");
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_terminate_already_terminated_is_idempotent() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-idem").await;
    let first = post_op(&env.base_url(), "op-idem", "terminate").await;
    assert_eq!(first.status(), StatusCode::OK, "first terminate should return 200");
    let second = post_op(&env.base_url(), "op-idem", "terminate").await;
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "second terminate should also return 200"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_pause_terminated_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-conflict-1").await;
    post_op(&env.base_url(), "op-conflict-1", "terminate").await;
    let resp = post_op(&env.base_url(), "op-conflict-1", "pause").await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "pausing a terminated op should return 409",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_resume_when_running_returns_409() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "op-conflict-2").await;
    let resp = post_op(&env.base_url(), "op-conflict-2", "resume").await;
    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "resuming an already-running op should return 409",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let resp = post_op(&env.base_url(), "completely-unknown-id", "pause").await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "unknown op id should return 404",);
}

#[tokio::test(flavor = "multi_thread")]
async fn ops_list_returns_all_active() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    register_op(&env.base_url(), "list-op-a").await;
    register_op(&env.base_url(), "list-op-b").await;
    register_op(&env.base_url(), "list-op-c").await;

    let list: serde_json::Value = reqwest::Client::new()
        .get(format!("{}/api/v1/ops", env.base_url()))
        .send()
        .await
        .expect("GET /ops should send")
        .json()
        .await
        .expect("list should be JSON");

    let arr = list.as_array().expect("response should be an array");
    let ids: Vec<&str> = arr.iter().filter_map(|r| r["op_id"].as_str()).collect();
    assert!(ids.contains(&"list-op-a"), "list should include list-op-a");
    assert!(ids.contains(&"list-op-b"), "list should include list-op-b");
    assert!(ids.contains(&"list-op-c"), "list should include list-op-c");
}
