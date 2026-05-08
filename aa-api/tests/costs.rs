//! Integration tests for the cost/budget summary endpoint.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn get_cost_summary_returns_200() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["daily_spend_usd"].as_str().is_some());
    assert!(json["date"].as_str().is_some());
}

#[tokio::test]
async fn get_cost_summary_has_zero_initial_spend() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Fresh tracker should have zero spend
    let spend = json["daily_spend_usd"].as_str().unwrap();
    assert_eq!(spend, "0");
}

#[tokio::test]
async fn get_cost_summary_includes_agents_array() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["per_agent"].is_array(), "per_agent field should be an array");
    assert_eq!(
        json["per_agent"].as_array().unwrap().len(),
        0,
        "fresh tracker has no per-agent data"
    );
}

#[tokio::test]
async fn get_cost_summary_includes_limit_fields() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Default test tracker has no limits configured, so these should be null
    assert!(json["daily_limit_usd"].is_null());
    assert!(json["monthly_limit_usd"].is_null());
}

#[tokio::test]
async fn get_cost_summary_includes_per_team_array() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/costs").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["per_team"].is_array(),
        "per_team field should be present and an array"
    );
    assert_eq!(
        json["per_team"].as_array().unwrap().len(),
        0,
        "fresh tracker has no per-team data"
    );
}
