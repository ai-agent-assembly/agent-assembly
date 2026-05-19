//! AAASM-1545 — secret-detection alerts flow from the broadcast bus
//! into the `AlertStore` and out through `/api/v1/alerts`.
//!
//! These tests verify the boundary between `aa_gateway::alerts::SecretAlert`
//! producers (PolicyService) and the public API by injecting alerts
//! directly on `EventBroadcast::secret_sender()` — i.e. the exact path
//! the production `spawn_secret_alert_capture` task consumes.
//!
//! Synthetic secret fixtures only — `AKIAIOSFODNN7EXAMPLE` is a public
//! AWS documentation value, never a live credential.

mod common;

use std::time::Duration;

use aa_core::{AgentId, CredentialKind};
use aa_gateway::alerts::SecretAlert;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn aws_secret_alert() -> SecretAlert {
    SecretAlert {
        agent_id: AgentId::from_bytes([0xAB; 16]),
        team_id: Some("team-pioneer".to_string()),
        kinds: vec![CredentialKind::AwsAccessKey],
        finding_count: 1,
    }
}

#[tokio::test]
async fn list_alerts_returns_secret_alert_after_broadcast_capture() {
    let state = common::test_state();
    let secret_tx = state.events.secret_sender();
    let secret_rx = state.events.subscribe_secret();
    let alert_store = state.alert_store.clone();

    let _handle = aa_api::alerts::capture::spawn_secret_alert_capture(secret_rx, alert_store);

    secret_tx.send(aws_secret_alert()).unwrap();

    tokio::time::sleep(Duration::from_millis(80)).await;

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["category"], "secret_detected");
    assert_eq!(items[0]["severity"], "critical");
    assert_eq!(items[0]["detected_pattern_type"], "AwsAccessKey");
    assert_eq!(items[0]["redacted_value"], "[REDACTED:AwsAccessKey]");
    assert!(items[0]["id"].is_string());
    assert!(items[0]["timestamp"].is_string());
}

#[tokio::test]
async fn secret_alert_response_never_contains_raw_secret_bytes() {
    let state = common::test_state();
    let secret_tx = state.events.secret_sender();
    let secret_rx = state.events.subscribe_secret();
    let alert_store = state.alert_store.clone();

    let _handle = aa_api::alerts::capture::spawn_secret_alert_capture(secret_rx, alert_store);

    secret_tx.send(aws_secret_alert()).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let raw = std::str::from_utf8(&body).expect("response body is UTF-8");
    assert!(
        !raw.contains(FAKE_AWS_ACCESS_KEY),
        "raw secret must never appear in alert API response; body was: {raw}"
    );
}

#[tokio::test]
async fn get_alert_returns_secret_payload_with_critical_severity() {
    let state = common::test_state();
    let secret_tx = state.events.secret_sender();
    let secret_rx = state.events.subscribe_secret();
    let alert_store = state.alert_store.clone();

    let _handle = aa_api::alerts::capture::spawn_secret_alert_capture(secret_rx, alert_store.clone());

    secret_tx.send(aws_secret_alert()).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Resolve the assigned id from the store directly so the test does not
    // depend on the global id counter starting at 1.
    let (items, _) = alert_store.list(10, 0);
    let id = items.first().expect("a secret alert must be recorded").id;

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/alerts/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["category"], "secret_detected");
    assert_eq!(json["severity"], "critical");
    assert_eq!(json["detected_pattern_type"], "AwsAccessKey");
    assert_eq!(json["redacted_value"], "[REDACTED:AwsAccessKey]");
}
