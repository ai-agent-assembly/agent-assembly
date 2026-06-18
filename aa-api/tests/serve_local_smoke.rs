//! Smoke test for the AAASM-3360 in-memory serving entrypoint.
//!
//! Verifies that an app built from `AppState::local_in_memory()` serves the
//! full `/api/v1/*` REST surface — both the public liveness probe and the
//! protected data routes (reachable because local mode disables auth) — with
//! real JSON bodies instead of 404s.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Build the production local-mode app the shipped `aa-api-server` binary
/// serves: an in-memory `AppState` wired through `build_app`.
fn local_app() -> axum::Router {
    let state = aa_api::AppState::local_in_memory().expect("local_in_memory must construct");
    aa_api::build_app(state)
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("build request"))
        .await
        .expect("router.oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
    (status, body)
}

#[tokio::test]
async fn local_in_memory_serves_health() {
    let (status, body) = get_json(local_app(), "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["api_version"], "v1");
}

#[tokio::test]
async fn local_in_memory_serves_agents_list() {
    // Protected route — reachable because local mode disables auth.
    let (status, body) = get_json(local_app(), "/api/v1/agents").await;
    assert_eq!(status, StatusCode::OK, "agents list must be reachable (auth off)");
    assert!(body.get("items").is_some(), "agents list must return a paginated body");
}

#[tokio::test]
async fn local_in_memory_serves_policies_list() {
    let (status, body) = get_json(local_app(), "/api/v1/policies").await;
    assert_eq!(status, StatusCode::OK, "policies list must be reachable (auth off)");
    assert!(
        body.get("items").is_some(),
        "policies list must return a paginated body"
    );
}

#[tokio::test]
async fn local_in_memory_serves_active_policy() {
    let (status, body) = get_json(local_app(), "/api/v1/policies/active").await;
    assert_eq!(status, StatusCode::OK);
    // The bootstrap policy carries the documented local-policy name.
    assert_eq!(body["name"], "local-policy");
}

#[tokio::test]
async fn local_in_memory_unknown_route_is_json_404_not_html() {
    let (status, body) = get_json(local_app(), "/api/v1/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // ProblemDetail JSON, not an SPA/HTML fallback.
    assert_eq!(body["status"], 404);
}
