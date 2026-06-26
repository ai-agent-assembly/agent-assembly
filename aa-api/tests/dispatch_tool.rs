//! Integration tests for `POST /api/v1/dispatch_tool` (AAASM-3805).
//!
//! Covers the native secret-injection branch of the dispatch handler: passthrough
//! of placeholder-free args, resolution of registered `${NAME}` placeholders, and
//! the fail-closed 422 when an unknown placeholder is referenced. The WASM-sandbox
//! branch is exercised by the sandbox crate's own tests (it needs a real wasm
//! module registered as `ToolKind::Wasm`), so it is intentionally out of scope here.

mod common;

use aa_api::server::build_app;
use aa_gateway::secrets::Secret;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

/// POST a dispatch request and return (status, parsed-JSON-body).
async fn post_dispatch(app: axum::Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/dispatch_tool")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn dispatch_passes_through_args_without_placeholders() {
    let app = common::test_app_no_auth();
    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "query": "SELECT 1", "limit": 10 } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // No `${...}` tokens → args are returned unchanged and nothing was substituted.
    assert_eq!(body["resolved_args"]["query"], "SELECT 1");
    assert_eq!(body["resolved_args"]["limit"], 10);
    assert!(body["names_substituted"].as_array().unwrap().is_empty());
    // Native path leaves the sandbox verdict absent.
    assert!(body.get("sandbox").is_none() || body["sandbox"].is_null());
}

#[tokio::test]
async fn dispatch_resolves_registered_placeholder() {
    // Seed a secret, then reference it via a `${DB_PASSWORD}` placeholder.
    let state = common::test_state();
    state
        .secrets_store
        .register(Secret {
            name: "DB_PASSWORD".to_string(),
            value: "s3cr3t-value".to_string(),
        })
        .expect("register secret");
    let app = build_app(state);

    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "password": "${DB_PASSWORD}" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resolved_args"]["password"], "s3cr3t-value");
    assert_eq!(
        body["names_substituted"].as_array().unwrap(),
        &vec![serde_json::Value::String("DB_PASSWORD".to_string())]
    );
}

#[tokio::test]
async fn dispatch_unknown_placeholder_returns_422() {
    let app = common::test_app_no_auth();
    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "token": "${MISSING_SECRET}" } }),
    )
    .await;

    // The resolver refuses to silently forward an unresolved `${...}` token.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("MISSING_SECRET"),
        "422 detail should name the unknown placeholder, got: {detail}"
    );
}
