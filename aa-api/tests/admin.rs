//! Integration tests for the admin retention-policy REST routes
//! (AAASM-1592 S-K — AAASM-1861).
//!
//! Each handler under `/api/v1/admin/retention-policy*` is exercised
//! against a real Axum router via `tower::ServiceExt::oneshot`. The
//! happy-path cases populate `AppState.retention_engine` with a
//! `RetentionEngine` backed by a fresh on-disk SQLite database; the
//! unavailable / validation cases reuse `common::test_app` whose
//! AppState defaults `retention_engine` to `None`.

mod common;

use std::sync::Arc;

use aa_api::server::build_app;
use aa_gateway::storage::backend::StorageBackend;
use aa_gateway::storage::{RetentionConfig, RetentionEngine, SqliteBackend, SqliteConfig};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

async fn build_engine() -> (Arc<RetentionEngine>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: tmp.path().join("retention-it.db"),
    })
    .await
    .expect("sqlite open");
    backend.migrate().await.expect("sqlite migrate");
    let engine = Arc::new(RetentionEngine::new(
        Arc::new(backend) as Arc<dyn StorageBackend>,
        RetentionConfig::default(),
    ));
    (engine, tmp)
}

async fn json_body(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("body is not JSON: {e}; bytes={bytes:?}"))
}

#[tokio::test]
async fn get_returns_503_when_retention_engine_is_unconfigured() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/retention-policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(resp).await;
    assert_eq!(body["status"].as_u64(), Some(503));
    assert_eq!(body["error_code"].as_str(), Some("retention_engine_unavailable"));
}

#[tokio::test]
async fn get_returns_current_config_with_no_last_run_initially() {
    let (engine, _tmp) = build_engine().await;
    let app = build_app(common::test_state_with_retention_engine(engine));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/retention-policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["hot_days"].as_u64(), Some(30), "default hot_days");
    assert_eq!(body["warm_days"].as_u64(), Some(90), "default warm_days");
    assert_eq!(body["cold_action"].as_str(), Some("drop"));
    assert_eq!(body["dry_run"].as_bool(), Some(false));
    assert!(body["last_run"].is_null(), "no run yet");
}

#[tokio::test]
async fn put_hot_reloads_config_and_returns_updated_document() {
    let (engine, _tmp) = build_engine().await;
    let app = build_app(common::test_state_with_retention_engine(Arc::clone(&engine)));

    let req_body = serde_json::json!({
        "hot_days": 15,
        "warm_days": 45,
        "cold_action": "drop",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["hot_days"].as_u64(), Some(15));
    assert_eq!(body["warm_days"].as_u64(), Some(45));
    assert_eq!(body["cold_action"].as_str(), Some("drop"));

    // The live engine reflects the swap.
    let live = engine.current_config();
    assert_eq!(live.hot_days, 15);
    assert_eq!(live.warm_days, 45);
}

#[tokio::test]
async fn put_with_warm_days_le_hot_days_returns_400() {
    let app = common::test_app();
    let req_body = serde_json::json!({
        "hot_days": 30,
        "warm_days": 30,
        "cold_action": "drop",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(body["error_code"].as_str(), Some("retention_policy_invalid_warm_days"));
}

#[tokio::test]
async fn put_with_archive_action_missing_url_returns_400() {
    let app = common::test_app();
    let req_body = serde_json::json!({
        "hot_days": 30,
        "warm_days": 90,
        "cold_action": "archive",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(
        body["error_code"].as_str(),
        Some("retention_policy_missing_archive_url")
    );
}

#[tokio::test]
async fn put_with_archive_action_bad_url_scheme_returns_400() {
    let app = common::test_app();
    let req_body = serde_json::json!({
        "hot_days": 30,
        "warm_days": 90,
        "cold_action": "archive",
        "archive_url": "https://example.com/bucket",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(
        body["error_code"].as_str(),
        Some("retention_policy_invalid_archive_url")
    );
}

#[tokio::test]
async fn post_run_dry_run_returns_stats_and_restores_dry_run_flag() {
    let (engine, _tmp) = build_engine().await;
    // Pre-condition: engine starts with dry_run=false (the default).
    assert!(!engine.current_config().dry_run);

    let app = build_app(common::test_state_with_retention_engine(Arc::clone(&engine)));
    let req_body = serde_json::json!({ "dry_run": true });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/retention-policy/run")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["dry_run"].as_bool(), Some(true));
    assert!(body["ran_at"].is_string(), "ran_at must be an ISO-8601 string");

    // Operator's pre-existing dry_run setting must be restored.
    assert!(
        !engine.current_config().dry_run,
        "ad-hoc dry-run must not leave a sticky behaviour change"
    );

    // engine.last_run_stats() is now populated.
    assert!(engine.last_run_stats().is_some());
}

#[tokio::test]
async fn post_run_returns_503_when_retention_engine_is_unconfigured() {
    let app = common::test_app();
    let req_body = serde_json::json!({ "dry_run": false });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/retention-policy/run")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn put_with_hot_days_zero_returns_400() {
    let app = common::test_app();
    let req_body = serde_json::json!({
        "hot_days": 0,
        "warm_days": 90,
        "cold_action": "drop",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = json_body(resp).await;
    assert_eq!(body["error_code"].as_str(), Some("retention_policy_invalid_hot_days"));
}

#[tokio::test]
async fn put_with_archive_action_and_valid_s3_url_returns_200() {
    let (engine, _tmp) = build_engine().await;
    let app = build_app(common::test_state_with_retention_engine(engine));
    let req_body = serde_json::json!({
        "hot_days": 5,
        "warm_days": 30,
        "cold_action": "archive",
        "archive_url": "s3://my-bucket/retention/",
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/v1/admin/retention-policy")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert_eq!(body["cold_action"].as_str(), Some("archive"));
    assert_eq!(body["archive_url"].as_str(), Some("s3://my-bucket/retention/"));
}

#[tokio::test]
async fn post_run_non_dry_run_returns_stats() {
    let (engine, _tmp) = build_engine().await;
    let app = build_app(common::test_state_with_retention_engine(Arc::clone(&engine)));
    let req_body = serde_json::json!({ "dry_run": false });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/retention-policy/run")
                .header("content-type", "application/json")
                .body(Body::from(req_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = json_body(resp).await;
    assert!(body["ran_at"].is_string());
    assert_eq!(body["dry_run"].as_bool(), Some(false));
}
