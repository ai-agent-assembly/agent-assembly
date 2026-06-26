//! Integration tests for the notification connectors (AAASM-1388 / AAASM-3175).
//!
//! The webhook and Slack connectors POST to the destination-configured URL, so
//! they can be exercised end-to-end against an `httpmock` server: success (2xx
//! → `DispatchOutcome`), failure (non-2xx → `ConnectorError::Http`), header and
//! payload shaping, and response-body truncation. The wrong-destination-type
//! guard on every connector is a synchronous early-return that needs no server.
//!
//! PagerDuty and OpsGenie hardcode their vendor API URLs (`events.pagerduty.com`
//! / `api.opsgenie.com`), so their dispatch happy-path cannot be redirected to a
//! mock server; only their wrong-type guards are covered here.

use aa_api::destinations::connectors::slack::SlackConnector;
use aa_api::destinations::connectors::webhook::WebhookConnector;
use aa_api::destinations::connectors::{ConnectorError, DispatchRequest, NotificationConnector};
use aa_api::destinations::types::{Destination, DestinationConfig};
use httpmock::prelude::*;
use httpmock::Method::POST as MOCK_POST;

/// Wrap a `DestinationConfig` in a `Destination` with throwaway metadata.
fn destination(config: DestinationConfig) -> Destination {
    Destination {
        id: "dst_test".to_string(),
        name: "test-destination".to_string(),
        config,
        enabled: true,
        created_at: "2026-06-18T00:00:00Z".to_string(),
        updated_at: "2026-06-18T00:00:00Z".to_string(),
    }
}

fn request(severity: &str, message: &str) -> DispatchRequest {
    DispatchRequest {
        severity: severity.to_string(),
        message: message.to_string(),
    }
}

#[test]
fn dispatch_request_default_has_low_severity_and_canned_message() {
    let req = DispatchRequest::default();
    assert_eq!(req.severity, "LOW");
    assert_eq!(req.message, "AAASM test fire");
}

// ── Webhook connector ──────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_dispatch_posts_payload_and_returns_outcome_on_2xx() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST)
            .path("/hook")
            .json_body_includes(r#"{ "severity": "HIGH", "message": "disk full" }"#);
        then.status(202).body("queued");
    });

    let dst = destination(DestinationConfig::Webhook {
        url: server.url("/hook"),
        secret_header: None,
    });

    let outcome = WebhookConnector
        .dispatch(&dst, &request("HIGH", "disk full"))
        .await
        .expect("2xx is a success");

    mock.assert();
    assert_eq!(outcome.connector_response_status, 202);
    // AAASM-3789: the upstream body is no longer reflected to the caller.
    assert!(
        outcome.connector_response_body.is_empty(),
        "upstream webhook body must not be reflected"
    );
    assert!(!outcome.delivered_at.is_empty());
}

#[tokio::test]
async fn webhook_dispatch_includes_secret_header_when_configured() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST).path("/secure").header("X-AAASM-Token", "s3cr3t");
        then.status(200);
    });

    let dst = destination(DestinationConfig::Webhook {
        url: server.url("/secure"),
        secret_header: Some("s3cr3t".to_string()),
    });

    WebhookConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect("authenticated webhook succeeds");

    // The mock only matches when the secret header is present.
    mock.assert();
}

#[tokio::test]
async fn webhook_dispatch_maps_non_2xx_to_http_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(MOCK_POST).path("/hook");
        then.status(500).body("upstream boom");
    });

    let dst = destination(DestinationConfig::Webhook {
        url: server.url("/hook"),
        secret_header: None,
    });

    let err = WebhookConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("500 must surface as an error");

    match err {
        ConnectorError::Http { status, body } => {
            assert_eq!(status, 500);
            // AAASM-3789: the upstream error body must not be reflected either.
            assert!(body.is_empty(), "upstream webhook error body must not be reflected");
        }
        other => panic!("expected Http error, got {other:?}"),
    }
}

#[tokio::test]
async fn webhook_dispatch_never_reflects_response_body() {
    // AAASM-3789: regardless of how much the upstream returns, none of it may
    // leak back to the caller via the outcome — the webhook test-fire is an
    // SSRF data-exfiltration sink otherwise.
    let server = MockServer::start();
    let big = "x".repeat(3000);
    server.mock(|when, then| {
        when.method(MOCK_POST).path("/hook");
        then.status(200).body(&big);
    });

    let dst = destination(DestinationConfig::Webhook {
        url: server.url("/hook"),
        secret_header: None,
    });

    let outcome = WebhookConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .unwrap();

    assert!(
        outcome.connector_response_body.is_empty(),
        "no part of the upstream body may be reflected"
    );
}

#[tokio::test]
async fn webhook_dispatch_transport_error_on_unreachable_host() {
    // Port 1 never listens; the connect attempt fails before any HTTP response.
    let dst = destination(DestinationConfig::Webhook {
        url: "http://127.0.0.1:1/hook".to_string(),
        secret_header: None,
    });

    let err = WebhookConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("unreachable host must be a transport error");

    assert!(matches!(err, ConnectorError::Transport(_)));
}

#[tokio::test]
async fn webhook_connector_rejects_non_webhook_destination() {
    let dst = destination(DestinationConfig::Slack {
        webhook_url: "https://hooks.slack.test/x".to_string(),
        channel_override: None,
    });

    let err = WebhookConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("wrong destination kind must be rejected");

    match err {
        ConnectorError::Transport(msg) => assert!(msg.contains("non-webhook")),
        other => panic!("expected Transport guard error, got {other:?}"),
    }
}

// ── Slack connector ────────────────────────────────────────────────────────

#[tokio::test]
async fn slack_dispatch_posts_text_payload_and_returns_outcome() {
    let server = MockServer::start();
    // The mock only matches when the request body carries the formatted
    // `"[SEVERITY] message"` text, so a passing `mock.assert()` verifies the
    // payload shaping without needing to capture the raw body.
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST)
            .path("/slack")
            .json_body_includes(r#"{ "text": "[CRITICAL] pipeline down" }"#);
        then.status(200).body("ok");
    });

    let dst = destination(DestinationConfig::Slack {
        webhook_url: server.url("/slack"),
        channel_override: None,
    });

    let outcome = SlackConnector
        .dispatch(&dst, &request("CRITICAL", "pipeline down"))
        .await
        .expect("slack 200 is a success");

    mock.assert();
    assert_eq!(outcome.connector_response_status, 200);
    assert_eq!(outcome.connector_response_body, "ok");
}

#[tokio::test]
async fn slack_dispatch_includes_channel_override_when_configured() {
    let server = MockServer::start();
    // The matcher requires the `channel` key, so a passing assert proves the
    // override was injected into the payload.
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST)
            .path("/slack")
            .json_body_includes(r##"{ "channel": "#alerts" }"##);
        then.status(200);
    });

    let dst = destination(DestinationConfig::Slack {
        webhook_url: server.url("/slack"),
        channel_override: Some("#alerts".to_string()),
    });

    SlackConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .unwrap();

    mock.assert();
}

#[tokio::test]
async fn slack_dispatch_maps_non_2xx_to_http_error() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(MOCK_POST).path("/slack");
        then.status(404).body("no_such_hook");
    });

    let dst = destination(DestinationConfig::Slack {
        webhook_url: server.url("/slack"),
        channel_override: None,
    });

    let err = SlackConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("404 must surface as an error");

    match err {
        ConnectorError::Http { status, .. } => assert_eq!(status, 404),
        other => panic!("expected Http error, got {other:?}"),
    }
}

#[tokio::test]
async fn slack_connector_rejects_non_slack_destination() {
    let dst = destination(DestinationConfig::Webhook {
        url: "https://example.test/hook".to_string(),
        secret_header: None,
    });

    let err = SlackConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("wrong destination kind must be rejected");

    match err {
        ConnectorError::Transport(msg) => assert!(msg.contains("non-slack")),
        other => panic!("expected Transport guard error, got {other:?}"),
    }
}

// ── Feature-gated connectors: wrong-type guards only ────────────────────────
//
// PagerDuty / OpsGenie dispatch to hardcoded vendor URLs, so only the
// synchronous wrong-destination-type guard is reachable without network.

#[cfg(feature = "connector-pagerduty")]
#[tokio::test]
async fn pagerduty_connector_rejects_non_pagerduty_destination() {
    use aa_api::destinations::connectors::pagerduty::PagerDutyConnector;

    let dst = destination(DestinationConfig::Webhook {
        url: "https://example.test/hook".to_string(),
        secret_header: None,
    });

    let err = PagerDutyConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("wrong destination kind must be rejected");

    assert!(matches!(err, ConnectorError::Transport(msg) if msg.contains("non-pagerduty")));
}

#[cfg(feature = "connector-opsgenie")]
#[tokio::test]
async fn opsgenie_connector_rejects_non_opsgenie_destination() {
    use aa_api::destinations::connectors::opsgenie::OpsGenieConnector;

    let dst = destination(DestinationConfig::Webhook {
        url: "https://example.test/hook".to_string(),
        secret_header: None,
    });

    let err = OpsGenieConnector
        .dispatch(&dst, &DispatchRequest::default())
        .await
        .expect_err("wrong destination kind must be rejected");

    assert!(matches!(err, ConnectorError::Transport(msg) if msg.contains("non-opsgenie")));
}
