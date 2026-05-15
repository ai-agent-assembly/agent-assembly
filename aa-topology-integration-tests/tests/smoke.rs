//! Smoke test for the [`TopologyTestEnv`] harness (AAASM-1066 ST-1 AC).
//!
//! Note: the parent Story's AC text says "GET /healthz". The real endpoint
//! exposed by `aa-api` is `GET /api/v1/health`. Treating the AC text as a
//! minor mismatch and asserting against the real endpoint here; documented
//! in the ST-1 PR description.

mod common;

use common::TopologyTestEnv;

#[tokio::test(flavor = "multi_thread")]
async fn harness_starts_and_returns_200_on_health() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/health", env.base_url()))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("health body json");
    assert_eq!(body["status"], "ok");
}
