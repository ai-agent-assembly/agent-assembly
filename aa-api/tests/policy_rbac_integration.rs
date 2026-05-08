//! Integration tests for RBAC role enforcement on policy mutation endpoints.
//!
//! Covers AAASM-979: role × scope × mutation matrix, both allow and deny paths.
//! Uses rstest parametrized cases to walk all combinations.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rstest::rstest;
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

const VALID_POLICY_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: rbac-test-policy
  version: "1.0.0"
spec:
  rules: []
"#;

/// Build an authenticated POST /api/v1/policies request.
fn post_policy_request(token: &str, scope: Option<&str>) -> Request<Body> {
    let mut body = serde_json::json!({ "policy_yaml": VALID_POLICY_YAML });
    if let Some(s) = scope {
        body["scope"] = serde_json::Value::String(s.to_string());
    }
    Request::builder()
        .method("POST")
        .uri("/api/v1/policies")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

// ── Admin scope (→ OrgAdmin) — allowed at every scope level ─────────────────

#[rstest]
#[case(None)] // global (default)
#[case(Some("global"))]
#[case(Some("org:acme"))]
#[case(Some("team:platform"))]
#[case(Some("tool:slack-mcp"))]
#[tokio::test]
async fn admin_scope_allowed_at_all_policy_scopes(#[case] scope: Option<&str>) {
    let (token, entry) = common::generate_test_api_key("admin-key", vec![Scope::Read, Scope::Write, Scope::Admin]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "OrgAdmin should be allowed for scope={scope:?}"
    );
}

// ── Write scope (→ Developer) — allowed only at agent/tool scopes ────────────

#[rstest]
#[case(Some("tool:slack-mcp"))]
#[tokio::test]
async fn write_scope_allowed_at_tool_scope(#[case] scope: Option<&str>) {
    let (token, entry) = common::generate_test_api_key("dev-key", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "Developer should be allowed for scope={scope:?}"
    );
}

#[rstest]
#[case(None)] // global (default)
#[case(Some("global"))]
#[case(Some("org:acme"))]
#[case(Some("team:platform"))]
#[tokio::test]
async fn write_scope_denied_at_global_org_team_scopes(#[case] scope: Option<&str>) {
    let (token, entry) = common::generate_test_api_key("dev-key", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Developer should be denied for scope={scope:?}"
    );
}

// ── Read scope (→ Viewer) — denied at all scopes ────────────────────────────

#[rstest]
#[case(None)]
#[case(Some("global"))]
#[case(Some("org:acme"))]
#[case(Some("team:platform"))]
#[case(Some("tool:slack-mcp"))]
#[tokio::test]
async fn read_scope_denied_at_all_policy_scopes(#[case] scope: Option<&str>) {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Viewer should be denied for scope={scope:?}"
    );
}

// ── No auth — unauthenticated request returns 401 ───────────────────────────

#[tokio::test]
async fn unauthenticated_create_policy_returns_401() {
    let app = common::test_app_with_auth(&[], 1000);

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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Deny response body contains human-readable detail ───────────────────────

#[tokio::test]
async fn forbidden_response_contains_deny_detail() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, Some("global"))).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail = json["detail"].as_str().unwrap_or("");
    assert!(detail.contains("policy mutation denied"), "detail was: {detail}");
}

// ── Invalid scope string returns 400 ────────────────────────────────────────

#[tokio::test]
async fn invalid_scope_string_returns_400() {
    let (token, entry) = common::generate_test_api_key("admin-key", vec![Scope::Read, Scope::Write, Scope::Admin]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let body = serde_json::json!({
        "policy_yaml": VALID_POLICY_YAML,
        "scope": "notascope"
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── GET endpoints remain accessible without auth ────────────────────────────

#[tokio::test]
async fn list_policies_requires_no_auth() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
