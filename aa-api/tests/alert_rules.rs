//! Integration tests for `/api/v1/alerts/rules` (AAASM-1386).

mod common;

use axum::body::Body;
use axum::http::Request;
use serde_json::json;

#[allow(dead_code)]
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

#[allow(dead_code)]
async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[allow(dead_code)]
fn post(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[allow(dead_code)]
fn put(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[allow(dead_code)]
fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[allow(dead_code)]
fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}
