//! AAASM-1486 / F122 ST-E — Live-gateway HTTP integration tests for `/api/v1/health`.
//!
//! ## Discovered response shape (aa-api/src/routes/health.rs)
//!
//! ```text
//! GET /api/v1/health → 200 application/json
//! {
//!   "status":             "ok",    // always "ok" when alive
//!   "version":            "0.0.1", // CARGO_PKG_VERSION
//!   "api_version":        "v1",
//!   "uptime_secs":        u64,     // seconds since server startup
//!   "active_connections": i64,     // live WebSocket/SSE count
//!   "pipeline_lag_ms":    u64,     // placeholder, always 0
//! }
//! ```
//!
//! No `dependencies` / `checks` object is present in the current implementation.
//! `health_reflects_policy_engine_state` is `#[ignore]`'d pending AAASM-TODO
//! to add downstream subsystem health reporting.
//!
//! Health is always unauthenticated: the handler carries no `AuthenticatedCaller`
//! extractor and therefore bypasses auth entirely regardless of the configured
//! `AuthMode`. `AuthMode::On` coverage for this endpoint is deferred to a
//! follow-up subtask pending `TopologyTestEnv::start_with_auth()` (ST-D / ST-R).

mod common;

use std::time::Duration;

use common::TopologyTestEnv;

#[tokio::test(flavor = "multi_thread")]
async fn health_returns_200_immediately_after_startup() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("response body should parse as JSON");
    assert_eq!(body["status"], "ok", "status field should be \"ok\"");
}

#[tokio::test(flavor = "multi_thread")]
async fn health_returns_correct_content_type() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed");

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "content-type should be application/json, got: {content_type}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_does_not_require_auth() {
    // Harness default: AuthMode::Off — health returns 200 without credentials.
    // Code inspection of aa-api/src/routes/health.rs confirms the handler
    // carries no `AuthenticatedCaller` extractor, so auth is bypassed entirely
    // regardless of mode.
    //
    // AuthMode::On coverage is deferred to a follow-up subtask pending
    // `TopologyTestEnv::start_with_auth()` (ST-D / ST-R).
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed without credentials under AuthMode::Off");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn health_response_includes_version_field() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed");

    let body: serde_json::Value = resp.json().await.expect("response body should parse as JSON");
    let version = body["version"].as_str().expect("version field should be a string");
    assert!(!version.is_empty(), "version should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn health_response_includes_uptime_or_started_at() {
    // The handler surfaces server uptime via the `uptime_secs` field (u64
    // seconds elapsed since `AppState::startup_time`).
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed");

    let body: serde_json::Value = resp.json().await.expect("response body should parse as JSON");
    assert!(
        body["uptime_secs"].is_u64(),
        "uptime_secs should be present as a u64, got: {:?}",
        body["uptime_secs"]
    );
}

/// Dependency propagation test — `#[ignore]`'d because the current health
/// handler is minimal: no `dependencies` or `checks` object is present.
/// Filed as AAASM-TODO to add downstream subsystem health reporting
/// (policy engine, registry, audit, alerts).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "health handler is minimal; no dependencies/checks object present (AAASM-TODO)"]
async fn health_reflects_policy_engine_state() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/health", env.base_url()))
        .await
        .expect("GET /api/v1/health should succeed");

    let body: serde_json::Value = resp.json().await.expect("response body should parse as JSON");
    let deps = body
        .get("dependencies")
        .or_else(|| body.get("checks"))
        .expect("health response should include a dependencies or checks object");
    assert!(deps.is_object(), "dependencies/checks should be a JSON object");
    for subsystem in ["policy_engine", "registry", "audit", "alerts"] {
        assert!(
            deps.get(subsystem).is_some(),
            "dependencies object should include subsystem: {subsystem}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn health_under_load_still_returns_200() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/health", env.base_url());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client should build");

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let c = client.clone();
        let u = url.clone();
        set.spawn(async move { c.get(&u).send().await });
    }

    // 5 s total budget for all 50 concurrent requests to complete.
    let deadline = tokio::time::timeout(Duration::from_secs(5), async {
        let mut i = 0usize;
        while let Some(result) = set.join_next().await {
            let resp = result
                .expect("spawn should not panic")
                .expect("GET /api/v1/health should succeed under load");
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::OK,
                "concurrent request {i} should return 200"
            );
            i += 1;
        }
        i
    });

    let completed = deadline
        .await
        .expect("all 50 concurrent requests should complete within 5s");
    assert_eq!(completed, 50, "all 50 requests should have returned 200");
}
