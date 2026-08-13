//! Tests for the hardened local entrypoint (AAASM-3369).
//!
//! `AppState::local_hardened` upgrades the AAASM-3360 in-memory entrypoint so
//! that the shipped `aa-api-server` binary (a) requires an API key on the
//! protected `/api/v1/*` surface by default, leaving `/api/v1/health` public,
//! and (b) backs audit / retention with a local SQLite store so those handlers
//! return real data instead of 503.

use std::sync::Mutex;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const TEST_KEY: &str = "aa_00112233445566778899aabbccddeeff";

/// Serializes the env-var-dependent rate-limit tests so a concurrent test does
/// not observe a half-set `AA_RATE_LIMIT_RPM`.
static RATE_LIMIT_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Build the hardened app with API-key auth seeded from a fixed key.
async fn hardened_app_with_key() -> axum::Router {
    let state = aa_api::AppState::local_hardened(aa_api::LocalAuth::ApiKey {
        key: TEST_KEY.to_string(),
    })
    .await
    .expect("local_hardened must construct");
    aa_api::build_app(state)
}

/// Build the hardened app with auth explicitly disabled.
async fn hardened_app_auth_off() -> axum::Router {
    let state = aa_api::AppState::local_hardened(aa_api::LocalAuth::Off)
        .await
        .expect("local_hardened must construct");
    aa_api::build_app(state)
}

async fn status_of(app: axum::Router, uri: &str, bearer: Option<&str>) -> StatusCode {
    let mut builder = Request::builder().uri(uri);
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("build request"))
        .await
        .expect("router.oneshot");
    response.status()
}

#[tokio::test]
async fn protected_route_rejected_without_key() {
    let status = status_of(hardened_app_with_key().await, "/api/v1/agents", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "protected route must be 401 without an API key"
    );
}

#[tokio::test]
async fn protected_route_rejected_with_bad_key() {
    let bad = "aa_ffffffffffffffffffffffffffffffff";
    let status = status_of(hardened_app_with_key().await, "/api/v1/agents", Some(bad)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "protected route must be 401 with an unknown API key"
    );
}

#[tokio::test]
async fn protected_route_allowed_with_key() {
    let status = status_of(hardened_app_with_key().await, "/api/v1/agents", Some(TEST_KEY)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "protected route must be 200 with the seeded API key"
    );
}

#[tokio::test]
async fn health_is_public_without_key() {
    let status = status_of(hardened_app_with_key().await, "/api/v1/health", None).await;
    assert_eq!(status, StatusCode::OK, "health probe must stay public");
}

#[tokio::test]
async fn auth_off_leaves_protected_route_open() {
    let status = status_of(hardened_app_auth_off().await, "/api/v1/agents", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "AASM_API_AUTH=off must leave protected routes reachable"
    );
}

#[tokio::test]
async fn retention_policy_returns_real_data_not_503() {
    let app = hardened_app_with_key().await;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/admin/retention-policy")
                .header("authorization", format!("Bearer {TEST_KEY}"))
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router.oneshot");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "retention engine must be wired (real data, not 503)"
    );
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("parse json");
    // Default policy: hot=30d, warm=90d, 6-field daily-3am schedule.
    assert_eq!(body["hot_days"], 30);
    assert_eq!(body["schedule"], "0 0 3 * * *");
}

// These two tests are plain `#[test]`s (not `#[tokio::test]`): they mutate the
// process-global `AA_RATE_LIMIT_RPM` under a std `Mutex` and drive the async
// `local_hardened` on a private current-thread runtime, so the lock is never
// held across an `.await` (clippy `await_holding_lock`).
#[test]
fn rate_limit_rpm_env_is_honoured_in_live_limiter() {
    // AAASM-3441: the shipped `serve_local`/`local_hardened` path must build the
    // live limiter from AA_RATE_LIMIT_RPM, not a hard-coded 1000.
    let _guard = RATE_LIMIT_ENV_LOCK.lock().unwrap();
    std::env::set_var("AA_RATE_LIMIT_RPM", "7");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let state = rt
        .block_on(aa_api::AppState::local_hardened(aa_api::LocalAuth::ApiKey {
            key: TEST_KEY.to_string(),
        }))
        .expect("local_hardened must construct");
    std::env::remove_var("AA_RATE_LIMIT_RPM");

    assert_eq!(
        state.auth_config.rate_limit_rpm, 7,
        "auth_config must reflect AA_RATE_LIMIT_RPM"
    );
    // The live limiter must enforce the same value: 7 ok, 8th rejected.
    for i in 0..7 {
        assert!(
            state.rate_limiter.check("local-admin").is_ok(),
            "request {i} should be allowed under rpm=7"
        );
    }
    assert!(
        state.rate_limiter.check("local-admin").is_err(),
        "8th request must be rate-limited when rpm=7"
    );
}

#[test]
fn rate_limit_rpm_defaults_to_1000_when_unset() {
    // With the env unset the live limiter keeps the documented default.
    let _guard = RATE_LIMIT_ENV_LOCK.lock().unwrap();
    std::env::remove_var("AA_RATE_LIMIT_RPM");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build runtime");
    let state = rt
        .block_on(aa_api::AppState::local_hardened(aa_api::LocalAuth::Off))
        .expect("local_hardened must construct");
    assert_eq!(
        state.auth_config.rate_limit_rpm, 1000,
        "default rpm must be 1000 when AA_RATE_LIMIT_RPM is unset"
    );
}

#[tokio::test]
async fn logs_endpoint_returns_real_data_not_503() {
    let app = hardened_app_with_key().await;
    let status = status_of(app, "/api/v1/logs", Some(TEST_KEY)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "logs endpoint must serve real (empty) data, not 503"
    );
}
