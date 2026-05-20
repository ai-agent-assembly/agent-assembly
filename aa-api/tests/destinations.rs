//! Integration tests for `/api/v1/alerts/destinations` (AAASM-1388).
//!
//! Most cases drive the default test app. Two scenarios (`destination_in_use`
//! and the webhook test-fire flow) substitute in a custom AppState so they
//! can observe the connector / rule-reference behaviour end-to-end.

mod common;

use std::sync::Arc;

use aa_api::destinations::store::{InMemoryDestinationStore, RuleReferenceChecker};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use httpmock::prelude::*;
use httpmock::Method::POST as MOCK_POST;
use serde_json::{json, Value};
use tower::ServiceExt;

fn json_request(method: &str, uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn raw_request(method: &str, uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn webhook_payload(name: &str, url: &str) -> Value {
    json!({
        "name": name,
        "kind": "webhook",
        "config": { "url": url },
        "enabled": true,
    })
}

fn slack_payload(name: &str, url: &str) -> Value {
    json!({
        "name": name,
        "kind": "slack",
        "config": { "webhook_url": url },
        "enabled": true,
    })
}

#[tokio::test]
async fn create_then_get_webhook_round_trips() {
    let app = common::test_app();

    // POST
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("alpha", "https://example.com/hook"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let created = body_json(resp).await;
    assert!(created["id"].as_str().unwrap().starts_with("dst_"));
    assert_eq!(created["name"], "alpha");
    assert_eq!(created["kind"], "webhook");
    assert_eq!(created["config"]["url"], "https://example.com/hook");
    assert_eq!(created["enabled"], true);

    // GET
    let id = created["id"].as_str().unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/alerts/destinations/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let fetched = body_json(resp).await;
    assert_eq!(fetched["id"], id);
    assert_eq!(fetched["name"], "alpha");
}

#[tokio::test]
async fn list_filters_by_kind() {
    let app = common::test_app();

    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("wh", "https://example.com/h"),
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            slack_payload("sl", "https://hooks.slack.com/services/X/Y/Z"),
        ))
        .await
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts/destinations?kind=slack")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let items = json.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], "slack");
    assert_eq!(items[0]["name"], "sl");
}

#[tokio::test]
async fn put_preserves_created_at_and_bumps_updated_at() {
    let app = common::test_app();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("orig", "https://example.com/hook"),
        ))
        .await
        .unwrap();
    let created = body_json(resp).await;
    let id = created["id"].as_str().unwrap().to_string();
    let original_created_at = created["created_at"].as_str().unwrap().to_string();
    let original_updated_at = created["updated_at"].as_str().unwrap().to_string();

    tokio::time::sleep(std::time::Duration::from_millis(15)).await;

    let resp = app
        .oneshot(json_request(
            "PUT",
            &format!("/api/v1/alerts/destinations/{id}"),
            json!({ "name": "renamed" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = body_json(resp).await;
    assert_eq!(updated["created_at"], original_created_at);
    assert_ne!(updated["updated_at"], original_updated_at);
    assert_eq!(updated["name"], "renamed");
}

#[tokio::test]
async fn delete_returns_204_when_no_references() {
    let app = common::test_app();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("doomed", "https://example.com/hook"),
        ))
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/alerts/destinations/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/alerts/destinations/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_returns_409_destination_in_use() {
    struct AlwaysReferenced;
    impl RuleReferenceChecker for AlwaysReferenced {
        fn is_referenced(&self, _id: &str) -> bool {
            true
        }
    }
    let store = Arc::new(InMemoryDestinationStore::new(Arc::new(AlwaysReferenced)));
    let state = common::test_state_with_destination_store(store);
    let app = aa_api::server::build_app(state);

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("ref", "https://example.com/hook"),
        ))
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/alerts/destinations/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = body_json(resp).await;
    assert_eq!(body["detail"], "destination_in_use");
}

#[tokio::test]
async fn create_invalid_config_returns_400() {
    let app = common::test_app();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            json!({
                "name": "bad",
                "kind": "webhook",
                "config": { "url": "not-a-url" },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert!(body["detail"]
        .as_str()
        .unwrap()
        .contains("webhook.url is not a valid URL"));
}

#[tokio::test]
async fn create_invalid_kind_returns_400() {
    let app = common::test_app();

    let resp = app
        .oneshot(raw_request(
            "POST",
            "/api/v1/alerts/destinations",
            r#"{"name":"x","kind":"carrier_pigeon","config":{}}"#,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp).await;
    assert_eq!(body["detail"], "invalid_kind");
}

#[tokio::test]
async fn get_unknown_returns_404_destination_not_found() {
    let app = common::test_app();

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/alerts/destinations/dst_doesnotexist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp).await;
    assert_eq!(body["detail"], "destination_not_found");
}

#[tokio::test]
async fn test_webhook_returns_200_and_hits_connector() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST).path("/hook");
        then.status(200).body("ok");
    });

    let app = common::test_app();
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("hook", &server.url("/hook")),
        ))
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/alerts/destinations/{id}/test"),
            json!({ "severity": "CRITICAL" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["connector_response_status"], 200);
    mock.assert();
}

#[tokio::test]
async fn test_webhook_returns_502_connector_failed() {
    let server = MockServer::start();
    let mock = server.mock(|when, then| {
        when.method(MOCK_POST).path("/hook");
        then.status(401).body("Invalid token");
    });

    let app = common::test_app();
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/api/v1/alerts/destinations",
            webhook_payload("hook", &server.url("/hook")),
        ))
        .await
        .unwrap();
    let id = body_json(resp).await["id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(json_request(
            "POST",
            &format!("/api/v1/alerts/destinations/{id}/test"),
            json!({ "severity": "LOW" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let body = body_json(resp).await;
    assert_eq!(body["error"], "connector_failed");
    assert_eq!(body["connector_status"], 401);
    assert_eq!(body["connector_body"], "Invalid token");
    mock.assert();
}
