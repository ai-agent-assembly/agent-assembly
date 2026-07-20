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
  budget:
    daily_limit_usd: 1000.0
"#;

/// A policy YAML that declares a non-global (`tool:`) scope in its `spec`.
/// The create endpoint installs the single global primary policy slot, so it
/// cannot honor a scoped document and must reject it (AAASM-4933).
const TOOL_SCOPED_POLICY_YAML: &str = r#"
apiVersion: agent-assembly.dev/v1alpha1
kind: GovernancePolicy
metadata:
  name: rbac-test-scoped-policy
  version: "1.0.0"
spec:
  scope: tool:slack-mcp
  budget:
    daily_limit_usd: 1000.0
"#;

/// Build an authenticated POST /api/v1/policies request with `VALID_POLICY_YAML`
/// (a scope-less, i.e. global, document) and an optional advisory `body.scope`.
fn post_policy_request(token: &str, scope: Option<&str>) -> Request<Body> {
    post_policy_request_yaml(token, scope, VALID_POLICY_YAML)
}

/// Variant that lets the caller supply the policy YAML body.
fn post_policy_request_yaml(token: &str, scope: Option<&str>, yaml: &str) -> Request<Body> {
    let mut body = serde_json::json!({ "policy_yaml": yaml });
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

// The endpoint installs the single GLOBAL primary policy, so authorization is
// derived from the policy document's own scope (global here), NOT the advisory
// `body.scope`. Contract (AAASM-4933):
//   - body.scope omitted or "global"  → gated by role (OrgAdmin installs; lower
//     roles are 403).
//   - body.scope a non-global scope   → 400, because it disagrees with the
//     global document (the old privilege-escalation claim vector).

// ── Admin (→ OrgAdmin) — installs the global policy; scope mismatch is 400 ──

#[rstest]
#[case(None, StatusCode::CREATED)] // global (default)
#[case(Some("global"), StatusCode::CREATED)]
#[case(Some("org:acme"), StatusCode::BAD_REQUEST)]
#[case(Some("team:platform"), StatusCode::BAD_REQUEST)]
#[case(Some("tool:slack-mcp"), StatusCode::BAD_REQUEST)]
#[tokio::test]
async fn admin_installs_global_and_rejects_scope_mismatch(#[case] scope: Option<&str>, #[case] expected: StatusCode) {
    let (token, entry) = common::generate_test_api_key("admin-key", vec![Scope::Read, Scope::Write, Scope::Admin]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_eq!(response.status(), expected, "admin scope={scope:?}");
}

// ── Write (→ Developer) — may NEVER install the global policy ────────────────
// A global body (None / "global") is a role denial (403); a scoped body is a
// document mismatch (400). Either way the developer cannot create the policy —
// this is the AAASM-4933 privilege-escalation fix.

#[rstest]
#[case(None, StatusCode::FORBIDDEN)] // global (default) → role denied
#[case(Some("global"), StatusCode::FORBIDDEN)]
#[case(Some("org:acme"), StatusCode::BAD_REQUEST)] // mismatch vs global document
#[case(Some("team:platform"), StatusCode::BAD_REQUEST)]
#[case(Some("tool:slack-mcp"), StatusCode::BAD_REQUEST)]
#[tokio::test]
async fn developer_cannot_install_global_policy(#[case] scope: Option<&str>, #[case] expected: StatusCode) {
    let (token, entry) = common::generate_test_api_key("dev-key", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::CREATED,
        "Developer must never install a global-effect policy (scope={scope:?})"
    );
    assert_eq!(response.status(), expected, "developer scope={scope:?}");
}

/// AAASM-4933 regression (the exact exploit): a Write/Developer caller submits a
/// scope-less (global) policy but claims `body.scope: tool:slack-mcp` to satisfy
/// the Developer role. Pre-fix this returned 201 and installed a global policy;
/// it must now be rejected.
#[tokio::test]
async fn developer_cannot_launder_global_policy_via_tool_scope_claim() {
    let (token, entry) = common::generate_test_api_key("dev-key", vec![Scope::Read, Scope::Write]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(post_policy_request(&token, Some("tool:slack-mcp")))
        .await
        .unwrap();
    assert_ne!(
        response.status(),
        StatusCode::CREATED,
        "privilege escalation must be closed"
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// A document that itself declares a non-global scope cannot be installed via
/// this endpoint (it would be silently globalised). Even an OrgAdmin is rejected
/// with 400 until scoped installation is wired into the cascade.
#[tokio::test]
async fn scoped_document_yaml_is_rejected() {
    let (token, entry) = common::generate_test_api_key("admin-key", vec![Scope::Read, Scope::Write, Scope::Admin]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(post_policy_request_yaml(
            &token,
            Some("tool:slack-mcp"),
            TOOL_SCOPED_POLICY_YAML,
        ))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "scoped install must be rejected"
    );
}

// ── Read scope (→ Viewer) — denied everywhere ───────────────────────────────
// Global body → role denial (403); scoped body → document mismatch (400).

#[rstest]
#[case(None, StatusCode::FORBIDDEN)]
#[case(Some("global"), StatusCode::FORBIDDEN)]
#[case(Some("org:acme"), StatusCode::BAD_REQUEST)]
#[case(Some("team:platform"), StatusCode::BAD_REQUEST)]
#[case(Some("tool:slack-mcp"), StatusCode::BAD_REQUEST)]
#[tokio::test]
async fn read_scope_never_creates_a_policy(#[case] scope: Option<&str>, #[case] expected: StatusCode) {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app.oneshot(post_policy_request(&token, scope)).await.unwrap();
    assert_ne!(
        response.status(),
        StatusCode::CREATED,
        "Viewer must never create (scope={scope:?})"
    );
    assert_eq!(response.status(), expected, "viewer scope={scope:?}");
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

// ── GET endpoints are gated by the deny-by-default auth layer ───────────────

/// Regression for AAASM-3125: prior to the router-level auth gate, read
/// endpoints such as `GET /policies` were reachable without any credential.
/// They now reject unauthenticated callers with 401.
#[tokio::test]
async fn list_policies_requires_auth() {
    let app = common::test_app_with_auth(&[], 1000);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/policies").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
