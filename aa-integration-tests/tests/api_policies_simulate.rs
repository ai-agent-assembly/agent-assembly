//! Live-gateway integration tests for `POST /api/v1/policies/simulate`
//! (AAASM-5037).
//!
//! The simulate endpoint dry-runs a hypothetical `(agent, tool, target)`
//! request against the active policy and returns the verdict — allow / narrow /
//! deny — plus the matched rule/reason, with **no** state mutation. These tests
//! run against a real in-process Axum server (no mocking): they install a
//! policy that allows one tool and denies another, then assert each verdict
//! and, critically, that repeated simulation never denies a rate-limited tool
//! (proving the dry-run consumes no live rate-limit token).

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::Value;

/// Policy that allows `gmail_send`, denies `shell`, and rate-limits
/// `daily_digest` to a single call per hour. No `data` section, so the
/// credential action defaults to `RedactOnly` — a built-in-detected secret in
/// the payload is redacted (never blocked), yielding a `narrow` verdict.
const SIMULATE_IT_YAML: &str = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: simulate-it-policy
  version: "1.0.0"
spec:
  tools:
    gmail_send:
      allow: true
    daily_digest:
      allow: true
      limit_per_hour: 1
    shell:
      allow: false
"#;

async fn post_policy(client: &reqwest::Client, base_url: &str, yaml: &str) {
    let resp = client
        .post(format!("{base_url}/api/v1/policies"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "policy_yaml": yaml }))
        .send()
        .await
        .expect("POST /api/v1/policies");
    assert_eq!(resp.status(), StatusCode::CREATED, "expected 201 from POST /policies");
}

async fn simulate(client: &reqwest::Client, base_url: &str, body: Value) -> Value {
    let resp = client
        .post(format!("{base_url}/api/v1/policies/simulate"))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("POST /api/v1/policies/simulate");
    assert_eq!(resp.status(), StatusCode::OK, "expected 200 from simulate");
    resp.json::<Value>().await.expect("200 body json")
}

#[tokio::test(flavor = "multi_thread")]
async fn simulate_allows_permitted_tool() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();
    post_policy(&client, &env.base_url(), SIMULATE_IT_YAML).await;

    let out = simulate(
        &client,
        &env.base_url(),
        serde_json::json!({ "agent_id": "research-bot-04", "tool": "gmail_send" }),
    )
    .await;

    assert_eq!(out["verdict"], "allow");
    assert_eq!(out["redacted"], false);
    assert!(out["matched_rule"].is_null(), "a clean allow carries no matched rule");
}

#[tokio::test(flavor = "multi_thread")]
async fn simulate_denies_denied_tool() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();
    post_policy(&client, &env.base_url(), SIMULATE_IT_YAML).await;

    let out = simulate(
        &client,
        &env.base_url(),
        serde_json::json!({ "agent_id": "research-bot-04", "tool": "shell" }),
    )
    .await;

    assert_eq!(out["verdict"], "deny");
    let rule = out["matched_rule"].as_str().expect("deny carries a matched rule");
    assert!(rule.contains("tool denied"), "unexpected matched_rule: {rule}");
    assert!(out["reason"].as_str().is_some_and(|r| r.contains("tool denied")));
}

#[tokio::test(flavor = "multi_thread")]
async fn simulate_narrows_on_detected_secret() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();
    post_policy(&client, &env.base_url(), SIMULATE_IT_YAML).await;

    // `ghp_` is a built-in-scanned GitHub PAT prefix; the always-on credential
    // scanner detects it and (under the default RedactOnly action) redacts
    // rather than blocks — an allowed-but-narrowed verdict.
    let out = simulate(
        &client,
        &env.base_url(),
        serde_json::json!({
            "agent_id": "research-bot-04",
            "tool": "gmail_send",
            "target": "ghp_ABCdef0123456789ghijklmnopqrstuvwxyz12"
        }),
    )
    .await;

    assert_eq!(out["verdict"], "narrow");
    assert_eq!(out["redacted"], true);
}

/// The core dry-run invariant end-to-end: simulating a rate-limited tool any
/// number of times must consume no live token, so every call still returns
/// `allow` (never `deny: rate limit exceeded`).
#[tokio::test(flavor = "multi_thread")]
async fn simulate_never_exhausts_rate_limit() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();
    post_policy(&client, &env.base_url(), SIMULATE_IT_YAML).await;

    for _ in 0..5 {
        let out = simulate(
            &client,
            &env.base_url(),
            serde_json::json!({ "agent_id": "research-bot-04", "tool": "daily_digest" }),
        )
        .await;
        assert_eq!(out["verdict"], "allow", "dry-run must never consume the rate token");
    }
}
