//! Integration tests for `POST /api/v1/alerts/silence` (AAASM-1387 /
//! AAASM-1649). Each test boots a fresh `test_state()` so they're fully
//! isolated and parallel-safe.

mod common;

use aa_core::AgentId;
use aa_gateway::budget::types::BudgetAlert;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

/// Record one budget alert directly into the test env's store. Used by
/// every test that needs an existing alert to silence.
fn seed_alert(state: &aa_api::state::AppState) -> String {
    state.alert_store.record(&BudgetAlert {
        agent_id: AgentId::from_bytes([0xAB; 16]),
        team_id: None,
        threshold_pct: 80,
        spent_usd: 8.0,
        limit_usd: 10.0,
    })
}

/// POST a JSON body to /api/v1/alerts/silence and return the response.
async fn post_silence(state: aa_api::state::AppState, body: serde_json::Value) -> axum::http::Response<Body> {
    let app = aa_api::server::build_app(state);
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/alerts/silence")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn body_json(response: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn silence_returns_201_and_flips_status_to_suppressed() {
    let state = common::test_state();
    let alert_id = seed_alert(&state);

    let resp = post_silence(
        state.clone(),
        json!({ "alert_id": alert_id, "duration_seconds": 3600, "reason": "maintenance" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = body_json(resp).await;
    assert_eq!(body["alert_id"].as_str(), Some(alert_id.as_str()));
    assert_eq!(body["reason"].as_str(), Some("maintenance"));
    assert_eq!(body["created_by"].as_str(), Some("__bypass__"));
    assert_eq!(body["silence_id"].as_str().unwrap().len(), 26, "silence_id is a ULID");
    assert!(body["starts_at"].is_string());
    assert!(body["expires_at"].is_string());

    // Follow-up GET reflects the new suppressed status + prior_status.
    let stored = state.alert_store.get_by_id(&alert_id).unwrap();
    assert_eq!(stored.status, "suppressed");
    assert_eq!(stored.prior_status.as_deref(), Some("unresolved"));
}

#[tokio::test]
async fn silence_emits_alert_event_silence_on_bus() {
    use aa_api::alerts::AlertEvent;
    use std::time::Duration;

    let state = common::test_state();
    let alert_id = seed_alert(&state);

    // Subscribe BEFORE the silence so the Fire event from `seed_alert`
    // is in the past and the next event we see is the Silence one.
    let mut rx = state.alert_store.subscribe();

    let resp = post_silence(state.clone(), json!({ "alert_id": alert_id, "duration_seconds": 60 })).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("AlertEvent::Silence must arrive within 200 ms")
        .expect("bus must deliver an event");

    match event {
        AlertEvent::Silence(stored) => {
            assert_eq!(stored.id, alert_id, "event carries the suppressed alert id");
            assert_eq!(stored.status, "suppressed");
            assert_eq!(stored.prior_status.as_deref(), Some("unresolved"));
        }
        other => panic!("expected AlertEvent::Silence, got {other:?}"),
    }
}

#[tokio::test]
async fn silence_expiry_restores_prior_status() {
    use aa_api::alerts::silence_watcher;
    use chrono::{Duration as ChronoDuration, Utc};

    let state = common::test_state();
    let alert_id = seed_alert(&state);

    // 1 s silence — must be in the past by the time we tick().
    let resp = post_silence(state.clone(), json!({ "alert_id": alert_id, "duration_seconds": 1 })).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(state.alert_store.get_by_id(&alert_id).unwrap().status, "suppressed");

    // Skip clock — drive the watcher with a future `now` past expires_at.
    // No real sleep, fully deterministic.
    let future = Utc::now() + ChronoDuration::seconds(5);
    let expired = silence_watcher::tick(state.silence_store.as_ref(), state.alert_store.as_ref(), future);
    assert_eq!(expired, 1, "watcher must drain the expired silence");

    let restored = state.alert_store.get_by_id(&alert_id).unwrap();
    assert_eq!(restored.status, "unresolved", "alert must be restored to prior_status");
    assert!(restored.prior_status.is_none(), "prior_status must be cleared");
}

#[tokio::test]
async fn silence_409_alert_already_silenced() {
    let state = common::test_state();
    let alert_id = seed_alert(&state);

    // First silence succeeds.
    let first = post_silence(state.clone(), json!({ "alert_id": alert_id, "duration_seconds": 3600 })).await;
    assert_eq!(first.status(), StatusCode::CREATED);

    // Second silence on the same alert while the first is still active.
    let second = post_silence(state, json!({ "alert_id": alert_id, "duration_seconds": 3600 })).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = body_json(second).await;
    assert!(body["detail"]
        .as_str()
        .unwrap_or("")
        .starts_with("alert_already_silenced:"));
}

#[tokio::test]
async fn silence_404_alert_not_found() {
    let state = common::test_state();
    // No alert seeded; use a syntactically valid but unrecorded ULID.
    let resp = post_silence(
        state,
        json!({ "alert_id": "00000000000000000000000000", "duration_seconds": 3600 }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap_or("").starts_with("alert_not_found:"));
}

#[tokio::test]
async fn silence_400_reason_too_long() {
    let state = common::test_state();
    let alert_id = seed_alert(&state);

    let long_reason = "x".repeat(501); // 1 over the 500-char cap
    let resp = post_silence(
        state,
        json!({ "alert_id": alert_id, "duration_seconds": 3600, "reason": long_reason }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap_or("").starts_with("reason_too_long:"));
}

#[tokio::test]
async fn silence_400_invalid_duration_too_large() {
    let state = common::test_state();
    let alert_id = seed_alert(&state);

    // 604_801 = 1 second over the 7-day cap.
    let resp = post_silence(state, json!({ "alert_id": alert_id, "duration_seconds": 604_801 })).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body["detail"].as_str().unwrap_or("").starts_with("invalid_duration:"));
}

#[tokio::test]
async fn silence_400_invalid_duration_zero() {
    let state = common::test_state();
    let alert_id = seed_alert(&state);

    let resp = post_silence(state, json!({ "alert_id": alert_id, "duration_seconds": 0 })).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(
        body["detail"].as_str().unwrap_or("").starts_with("invalid_duration:"),
        "detail must carry invalid_duration code, got {:?}",
        body["detail"]
    );
}
