//! Integration test for the health endpoint.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_200_with_ok_status() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_returns_uptime_secs() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["uptime_secs"].is_u64(), "uptime_secs should be a u64");
}

#[tokio::test]
async fn health_returns_active_connections() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active_connections"], 0);
}

#[tokio::test]
async fn health_returns_pipeline_lag_ms() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["pipeline_lag_ms"], 0);
}

#[tokio::test]
async fn health_returns_version() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let version = json["version"].as_str().expect("version should be a string");
    assert!(!version.is_empty(), "version should not be empty");
}

#[tokio::test]
async fn health_returns_api_version() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["api_version"], "v1");
}

#[tokio::test]
async fn health_returns_subsystem_checks_map() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let checks = json["checks"].as_object().expect("checks should be a JSON object");
    for subsystem in ["policy_engine", "registry", "audit", "alerts"] {
        assert!(
            checks.contains_key(subsystem),
            "checks should include subsystem: {subsystem}"
        );
        assert_eq!(checks[subsystem], "ok", "subsystem {subsystem} should report ok");
    }
}
