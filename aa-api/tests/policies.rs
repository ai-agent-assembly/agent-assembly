//! Integration tests for the policy endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const VALID_POLICY_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: test-policy
  version: "1.0.0"
spec:
  rules: []
"#;

const ENVELOPE_POLICY_WITH_TOOLS: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: production-policy
  version: "2.0.0"
spec:
  tools:
    shell_exec:
      allow: false
    web_search:
      allow: true
      limit_per_hour: 50
"#;

const INVALID_POLICY_YAML: &str = "this is not valid yaml: [";

#[tokio::test]
async fn create_policy_returns_201_for_valid_yaml() {
    let app = common::test_app();

    let body = serde_json::json!({ "policy_yaml": VALID_POLICY_YAML });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], true);
    assert!(json["version"].as_str().is_some());
    // policy_yaml round-trips the request body back to the caller.
    assert_eq!(json["policy_yaml"], VALID_POLICY_YAML);
}

#[tokio::test]
async fn create_policy_returns_400_for_invalid_yaml() {
    let app = common::test_app();

    let body = serde_json::json!({ "policy_yaml": INVALID_POLICY_YAML });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_policies_returns_200() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["items"].as_array().is_some());
}

#[tokio::test]
async fn list_policies_returns_created_versions() {
    let state = common::test_state();

    // Create a policy via the engine so history gets a record.
    state
        .policy_engine
        .apply_yaml(VALID_POLICY_YAML, Some("test"), state.policy_history.as_ref())
        .await
        .unwrap();

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 1);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["active"], true);
    assert!(items[0]["version"].as_str().is_some());
    // policy_yaml is loaded from the history store snapshot.
    assert_eq!(items[0]["policy_yaml"], VALID_POLICY_YAML);
}

// ── GET /api/v1/policies/active ─────────────────────────────────────────

#[tokio::test]
async fn get_active_policy_returns_200() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies/active")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_active_policy_returns_metadata_from_envelope() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies/active")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // The test_state() loads an envelope policy with name=test-policy, version=0.1.0.
    assert_eq!(json["name"], "test-policy");
    assert_eq!(json["version"], "0.1.0");
    assert_eq!(json["active"], true);
    assert_eq!(json["rule_count"], 0);
}

#[tokio::test]
async fn get_active_policy_reflects_applied_policy() {
    let state = common::test_state();

    // Apply a policy with tool rules so rule_count > 0.
    state
        .policy_engine
        .apply_yaml(ENVELOPE_POLICY_WITH_TOOLS, Some("test"), state.policy_history.as_ref())
        .await
        .unwrap();

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/policies/active")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["name"], "production-policy");
    assert_eq!(json["version"], "2.0.0");
    assert_eq!(json["active"], true);
    assert_eq!(json["rule_count"], 2);
    // policy_yaml is fetched from history (most-recent entry == active).
    assert_eq!(json["policy_yaml"], ENVELOPE_POLICY_WITH_TOOLS);
}
