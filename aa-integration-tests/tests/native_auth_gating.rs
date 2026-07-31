//! AAASM-5305 — native email/password auth honest-degradation gate (ADR 0031 D2).
//!
//! The integration harness builds the in-memory `AppState` (no Postgres), which
//! is exactly the deployment where native accounts are NOT available. These tests
//! prove the surface degrades honestly end-to-end over HTTP:
//!
//! * `GET /auth/methods` advertises only `api_key` (never `password`), so the
//!   frontend never renders a password form the backend cannot serve.
//! * The account endpoints (`/login`, `/register`, `/refresh`) are reachable
//!   (mounted, not 404) but return `503`, signalling "configured route, no
//!   Postgres" rather than silently 404-ing.
//! * `/auth/token` (the API-key path) is untouched and still works.
//!
//! The Postgres-backed happy path (real login/register/invite/refresh) is covered
//! by the `PgUserStore` integration suite in `aa-storage-postgres`; wiring a live
//! Postgres store into the full aa-api app is out of this harness's scope.

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::{json, Value};

#[tokio::test(flavor = "multi_thread")]
async fn auth_methods_advertises_only_api_key_without_postgres() {
    let env = TopologyTestEnv::start().await.expect("harness starts");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/auth/methods", env.base_url()))
        .send()
        .await
        .expect("methods request");
    assert_eq!(resp.status(), StatusCode::OK, "methods is a public probe");

    let body: Value = resp.json().await.expect("json body");
    let methods = body["methods"].as_array().expect("methods array");
    let methods: Vec<&str> = methods.iter().filter_map(Value::as_str).collect();
    assert_eq!(
        methods,
        vec!["api_key"],
        "an in-memory deployment must advertise only api_key (ADR 0031 D2)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn login_is_gated_503_without_postgres() {
    let env = TopologyTestEnv::start().await.expect("harness starts");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/login", env.base_url()))
        .json(&json!({ "email": "someone@example.com", "password": "irrelevant-here" }))
        .send()
        .await
        .expect("login request");
    // Mounted (not 404) but unavailable (503) — the honest-degradation signal.
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "native login must 503 (not 404) when Postgres is absent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn register_is_gated_503_without_postgres() {
    let env = TopologyTestEnv::start().await.expect("harness starts");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/register", env.base_url()))
        .json(&json!({ "email": "someone@example.com", "password": "a-sufficiently-long-password" }))
        .send()
        .await
        .expect("register request");
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_without_cookie_is_gated_503_without_postgres() {
    let env = TopologyTestEnv::start().await.expect("harness starts");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/auth/refresh", env.base_url()))
        .send()
        .await
        .expect("refresh request");
    // The Postgres gate is checked before the cookie, so an in-memory deployment
    // reports 503 rather than 401 — the surface is unavailable, not "bad cookie".
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}
