//! Tests for the single-process SPA + REST wiring (AAASM-3382).
//!
//! `build_app_with_spa(state, Some(dist))` lets the shipped `aa-api-server`
//! binary serve the dashboard SPA at `/` *and* the full `/api/v1/*` REST
//! surface from one process and port, while keeping unknown `/api/v1/*` routes
//! as RFC 7807 JSON 404s (not the HTML SPA fallback).

use std::fs;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tempfile::TempDir;
use tower::ServiceExt;

/// Create a throwaway `dashboard/dist/` with an `index.html` so the SPA
/// fallback has something to serve.
fn fake_dist() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::write(
        dir.path().join("index.html"),
        "<!doctype html><html><body><div id=\"root\"></div></body></html>",
    )
    .expect("write index.html");
    dir
}

fn local_app_with_spa(dist: &std::path::Path) -> axum::Router {
    let state = aa_api::AppState::local_in_memory().expect("local_in_memory must construct");
    aa_api::build_app_with_spa(state, Some(dist))
}

async fn response_to(app: axum::Router, uri: &str) -> (StatusCode, Vec<u8>) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("build request"))
        .await
        .expect("router.oneshot");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("read body");
    (status, bytes.to_vec())
}

async fn response_with_content_type(app: axum::Router, uri: &str) -> (StatusCode, String, Vec<u8>) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).expect("build request"))
        .await
        .expect("router.oneshot");
    let status = response.status();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("read body");
    (status, content_type, bytes.to_vec())
}

#[tokio::test]
async fn healthz_is_served_alongside_spa() {
    let dist = fake_dist();
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/healthz").await;
    assert_eq!(status, StatusCode::OK, "/healthz must be served by aa-api-server");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("healthz returns JSON");
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_alias_serves_json_not_spa_html() {
    // AAASM-4666: `/health` (no `/api/v1` prefix, no trailing `z`) must return
    // the health JSON, not fall through to the SPA catch-all and return HTML.
    let dist = fake_dist();
    let (status, content_type, body) = response_with_content_type(local_app_with_spa(dist.path()), "/health").await;
    assert_eq!(status, StatusCode::OK, "/health alias must return 200");
    assert!(
        content_type.starts_with("application/json"),
        "/health must serve JSON, not SPA HTML; got content-type {content_type:?}"
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("/health returns JSON");
    assert_eq!(json["status"], "ok");
    assert_eq!(json["api_version"], "v1");
}

#[tokio::test]
async fn api_health_is_served_alongside_spa() {
    let dist = fake_dist();
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK, "full REST surface must coexist with the SPA");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("health returns JSON");
    assert_eq!(json["api_version"], "v1");
}

#[tokio::test]
async fn api_data_route_is_served_alongside_spa() {
    let dist = fake_dist();
    // Protected data route — reachable because in-memory mode disables auth.
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/api/v1/agents").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "data route must be reachable with the SPA mounted"
    );
    let json: serde_json::Value = serde_json::from_slice(&body).expect("agents returns JSON");
    assert!(json.get("items").is_some(), "agents list must return a paginated body");
}

#[tokio::test]
async fn spa_root_serves_index_html_not_json() {
    let dist = fake_dist();
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/").await;
    assert_eq!(status, StatusCode::OK, "SPA root must be served");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("<div id=\"root\">"),
        "GET / must serve the SPA index.html"
    );
}

#[tokio::test]
async fn unknown_client_route_falls_back_to_spa() {
    let dist = fake_dist();
    // A client-side React Router path: the SPA fallback serves index.html so
    // deep links resolve instead of 404ing.
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/dashboard/agents").await;
    assert_eq!(status, StatusCode::OK, "client-side routes must fall back to the SPA");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("<div id=\"root\">"),
        "client route must serve the SPA shell"
    );
}

#[tokio::test]
async fn unknown_api_route_is_json_404_not_spa_html() {
    let dist = fake_dist();
    let (status, body) = response_to(local_app_with_spa(dist.path()), "/api/v1/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unknown API routes must 404");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("unknown /api/v1/* must stay JSON, not HTML SPA");
    assert_eq!(json["status"], 404);
}
