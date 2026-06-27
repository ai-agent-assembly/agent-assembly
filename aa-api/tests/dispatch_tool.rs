//! Integration tests for `POST /api/v1/dispatch_tool` (AAASM-3805).
//!
//! Covers the native secret-injection branch of the dispatch handler: passthrough
//! of placeholder-free args, resolution of registered `${NAME}` placeholders, and
//! the fail-closed 422 when an unknown placeholder is referenced. The WASM-sandbox
//! branch is exercised by the sandbox crate's own tests (it needs a real wasm
//! module registered as `ToolKind::Wasm`), so it is intentionally out of scope here.

mod common;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_api::server::build_app;
use aa_gateway::secrets::{Secret, SecretsStore, TenantScopedStore};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

/// POST a dispatch request (no auth header) and return (status, parsed-JSON-body).
async fn post_dispatch(app: axum::Router, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    post_dispatch_opt_auth(app, None, body).await
}

/// POST a dispatch request, optionally carrying a `Bearer <token>` header, and
/// return (status, parsed-JSON-body).
async fn post_dispatch_opt_auth(
    app: axum::Router,
    token: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/dispatch_tool")
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .oneshot(builder.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
async fn dispatch_passes_through_args_without_placeholders() {
    let app = common::test_app_no_auth();
    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "query": "SELECT 1", "limit": 10 } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // No `${...}` tokens → args are returned unchanged and nothing was substituted.
    assert_eq!(body["resolved_args"]["query"], "SELECT 1");
    assert_eq!(body["resolved_args"]["limit"], 10);
    assert!(body["names_substituted"].as_array().unwrap().is_empty());
    // Native path leaves the sandbox verdict absent.
    assert!(body.get("sandbox").is_none() || body["sandbox"].is_null());
}

#[tokio::test]
async fn dispatch_resolves_registered_placeholder() {
    // Seed a secret, then reference it via a `${DB_PASSWORD}` placeholder.
    // `test_state()` is bypass mode (admin, untenanted), so the secret must be
    // registered under the untenanted namespace for the scoped resolver to find
    // it (AAASM-3845).
    let state = common::test_state();
    TenantScopedStore::for_tenant(state.secrets_store.as_ref(), None, None)
        .register(Secret {
            name: "DB_PASSWORD".to_string(),
            value: "s3cr3t-value".to_string(),
        })
        .expect("register secret");
    let app = build_app(state);

    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "password": "${DB_PASSWORD}" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resolved_args"]["password"], "s3cr3t-value");
    assert_eq!(
        body["names_substituted"].as_array().unwrap(),
        &vec![serde_json::Value::String("DB_PASSWORD".to_string())]
    );
}

#[tokio::test]
async fn dispatch_unknown_placeholder_returns_422() {
    let app = common::test_app_no_auth();
    let (status, body) = post_dispatch(
        app,
        json!({ "tool": "call_database", "args": { "token": "${MISSING_SECRET}" } }),
    )
    .await;

    // The resolver refuses to silently forward an unresolved `${...}` token.
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("MISSING_SECRET"),
        "422 detail should name the unknown placeholder, got: {detail}"
    );
}

// ── AAASM-3845 regression: authorization + tenant scoping ───────────────

/// An unauthenticated dispatch (auth enabled, no credential) is rejected before
/// any secret resolution can occur.
#[tokio::test]
async fn dispatch_unauthenticated_is_rejected() {
    let app = common::test_app_with_auth(&[], 1000);
    let (status, _body) = post_dispatch_opt_auth(
        app,
        None,
        json!({ "tool": "call_database", "args": { "password": "${DB_PASSWORD}" } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A caller with only the read scope cannot dispatch (write scope required).
#[tokio::test]
async fn dispatch_requires_write_scope() {
    let app = common::test_app_with_auth(&[], 1000);
    let read_only = common::generate_test_jwt("reader", &[Scope::Read]);
    let (status, _body) = post_dispatch_opt_auth(
        app,
        Some(&read_only),
        json!({ "tool": "call_database", "args": { "query": "SELECT 1" } }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A secret registered by one tenant is invisible to another tenant: the
/// cross-tenant reference fails closed as an unknown placeholder (422), while
/// the owning tenant resolves it (200).
#[tokio::test]
async fn dispatch_does_not_resolve_another_tenants_secret() {
    // Auth enabled; seed DB_PASSWORD under org-a's namespace.
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    TenantScopedStore::for_tenant(state.secrets_store.as_ref(), Some("org-a"), None)
        .register(Secret {
            name: "DB_PASSWORD".to_string(),
            value: "org-a-secret".to_string(),
        })
        .expect("register secret");
    let app = build_app(state);

    // The owning tenant (org-a, write) resolves its secret.
    let org_a = common::generate_test_jwt_for_tenant("owner", &[Scope::Write], None, Some("org-a"));
    let (status, body) = post_dispatch_opt_auth(
        app.clone(),
        Some(&org_a),
        json!({ "tool": "call_database", "args": { "password": "${DB_PASSWORD}" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["resolved_args"]["password"], "org-a-secret");

    // A different tenant (org-b, write) references the same bare name and must
    // not resolve it — no cross-tenant credential disclosure.
    let org_b = common::generate_test_jwt_for_tenant("intruder", &[Scope::Write], None, Some("org-b"));
    let (status, body) = post_dispatch_opt_auth(
        app,
        Some(&org_b),
        json!({ "tool": "call_database", "args": { "password": "${DB_PASSWORD}" } }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("DB_PASSWORD"),
        "cross-tenant ref must fail closed as unknown placeholder, got: {detail}"
    );
}
