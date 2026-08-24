//! AAASM-5871 — a cross-process proxy REDACT event, delivered over the real
//! `RedactionTelemetryService` gRPC transport, surfaces on `/api/v1/alerts`.
//!
//! Unlike `secret_alerts.rs` (which injects a `SecretAlert` directly onto the
//! broadcast bus), these tests drive the *actual* ingest: they stand up
//! `serve_telemetry_grpc` on a loopback port over the API's own secret-alert
//! sender, connect a real gRPC client, and assert the event flows through the
//! shipped capture → alert store → REST path. This is the production telemetry
//! hop the out-of-process `aa-proxy` uses.
//!
//! Synthetic fixtures only — no live credential, and by construction the wire
//! carries no secret value at all (only finding *kinds*).

mod common;

use std::time::Duration;

use aa_proto::assembly::telemetry::v1::redaction_telemetry_service_client::RedactionTelemetryServiceClient;
use aa_proto::assembly::telemetry::v1::{RedactionEvent, ReportRedactionRequest};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::net::TcpListener;
use tower::ServiceExt;

/// A public AWS documentation value — never a live credential. It is
/// deliberately NOT sent over the wire; the assertion that it is absent from
/// the API response documents that the telemetry surface carries no value.
const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn redaction_event(event_id: &str) -> RedactionEvent {
    RedactionEvent {
        event_id: event_id.to_string(),
        occurred_at_ms: 1_700_000_000_000,
        agent_id: vec![0xAB; 16],
        team_id: "team-pioneer".to_string(),
        destination_host: "api.anthropic.com".to_string(),
        finding_kinds: vec!["AwsAccessKey".to_string()],
        finding_count: 1,
    }
}

/// Stand up the telemetry ingest on an ephemeral loopback port over
/// `secret_tx`, returning the endpoint URI once it is accepting connections.
async fn spawn_ingest(secret_tx: tokio::sync::broadcast::Sender<aa_gateway::alerts::SecretAlert>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        aa_api::server::serve_telemetry_grpc(listener, secret_tx, std::future::pending::<()>())
            .await
            .unwrap();
    });
    // Give the server a moment to begin accepting before the client dials.
    tokio::time::sleep(Duration::from_millis(50)).await;
    format!("http://{addr}")
}

#[tokio::test]
async fn proxy_redaction_event_surfaces_on_alerts_api() {
    let state = common::test_state();
    let _handle =
        aa_api::alerts::capture::spawn_secret_alert_capture(state.events.subscribe_secret(), state.alert_store.clone());

    let endpoint = spawn_ingest(state.events.secret_sender()).await;
    let mut client = RedactionTelemetryServiceClient::connect(endpoint).await.unwrap();

    let resp = client
        .report_redaction(ReportRedactionRequest {
            event: Some(redaction_event("evt-1")),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.recorded, "a fresh event_id must record a new alert");

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
    assert_eq!(items[0]["team_id"], "team-pioneer");
}

#[tokio::test]
async fn duplicate_event_id_is_idempotent() {
    let state = common::test_state();
    let _handle =
        aa_api::alerts::capture::spawn_secret_alert_capture(state.events.subscribe_secret(), state.alert_store.clone());

    let endpoint = spawn_ingest(state.events.secret_sender()).await;
    let mut client = RedactionTelemetryServiceClient::connect(endpoint).await.unwrap();

    let first = client
        .report_redaction(ReportRedactionRequest {
            event: Some(redaction_event("evt-dup")),
        })
        .await
        .unwrap()
        .into_inner();
    let second = client
        .report_redaction(ReportRedactionRequest {
            event: Some(redaction_event("evt-dup")),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(first.recorded, "first delivery records");
    assert!(!second.recorded, "replayed event_id must not record a second alert");

    tokio::time::sleep(Duration::from_millis(80)).await;

    let (items, total) = state.alert_store.list(10, 0);
    assert_eq!(total, 1, "a replayed event_id must not double-count");
    assert_eq!(items.len(), 1);
}

#[tokio::test]
async fn alerts_response_never_contains_a_raw_secret() {
    let state = common::test_state();
    let _handle =
        aa_api::alerts::capture::spawn_secret_alert_capture(state.events.subscribe_secret(), state.alert_store.clone());

    let endpoint = spawn_ingest(state.events.secret_sender()).await;
    let mut client = RedactionTelemetryServiceClient::connect(endpoint).await.unwrap();
    client
        .report_redaction(ReportRedactionRequest {
            event: Some(redaction_event("evt-clean")),
        })
        .await
        .unwrap();

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
        "no raw secret may appear in the alert API response; body was: {raw}"
    );
}

#[tokio::test]
async fn empty_finding_kinds_is_rejected() {
    let state = common::test_state();
    let endpoint = spawn_ingest(state.events.secret_sender()).await;
    let mut client = RedactionTelemetryServiceClient::connect(endpoint).await.unwrap();

    let mut bad = redaction_event("evt-bad");
    bad.finding_kinds.clear();
    let status = client
        .report_redaction(ReportRedactionRequest { event: Some(bad) })
        .await
        .expect_err("an event with no finding kinds must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}
