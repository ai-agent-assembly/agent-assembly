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
