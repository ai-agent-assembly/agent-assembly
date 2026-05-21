//! Integration tests for `/api/v1/alerts/rules` (AAASM-1386).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

fn valid_rule_body() -> serde_json::Value {
    json!({
        "name": "Budget > 90%",
        "description": "Fire CRITICAL when budget spend exceeds 90%",
        "metric": "budget_spent_pct",
        "operator": ">",
        "threshold": 90,
        "evaluationWindowSeconds": 300,
        "severity": "CRITICAL",
        "destinationIds": ["slack-ops"],
        "dedupWindowSeconds": 600,
        "enabled": true
    })
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn put(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn full_crud_round_trip() {
    let app = common::test_app();

    // POST → 201 + assigned id/timestamps
    let response = app
        .clone()
        .oneshot(post("/api/v1/alerts/rules", valid_rule_body()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = read_json(response).await;
    let id = created["id"].as_str().expect("id assigned").to_string();
    assert!(!id.is_empty());
    assert!(!created["createdAt"].as_str().unwrap().is_empty());
    let original_created_at = created["createdAt"].as_str().unwrap().to_string();

    // GET list contains the rule (bare array, matching dashboard hooks
    // from AAASM-1075)
    let response = app.clone().oneshot(get("/api/v1/alerts/rules")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let list = read_json(response).await;
    let arr = list.as_array().expect("list response must be a JSON array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], id);

    // GET by id → 200
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // PUT → 200 with bumped updatedAt + preserved createdAt
    // sleep a tick so updatedAt is observably different
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let mut updated_body = valid_rule_body();
    updated_body["threshold"] = json!(95);
    let response = app
        .clone()
        .oneshot(put(&format!("/api/v1/alerts/rules/{id}"), updated_body))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let updated = read_json(response).await;
    assert_eq!(updated["id"], id);
    assert_eq!(updated["createdAt"], original_created_at);
    assert_ne!(updated["updatedAt"], original_created_at);
    assert_eq!(updated["threshold"], 95.0);

    // DELETE → 204
    let response = app
        .clone()
        .oneshot(delete(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // GET after delete → 404
    let response = app
        .clone()
        .oneshot(get(&format!("/api/v1/alerts/rules/{id}")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "rule_not_found");
}

#[tokio::test]
async fn create_with_unknown_metric_returns_invalid_metric() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["metric"] = json!("not_a_real_metric");
    let response = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "invalid_metric");
}

#[tokio::test]
async fn create_with_out_of_range_threshold_returns_invalid_threshold() {
    let app = common::test_app();
    let mut body = valid_rule_body();
    body["threshold"] = json!(200);
    let response = app.oneshot(post("/api/v1/alerts/rules", body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let problem = read_json(response).await;
    assert_eq!(problem["error_code"], "invalid_threshold");
}
