//! Integration tests for `GET /api/v1/audit/sandbox-summary` (AAASM-1911).
//!
//! Drives the live router so the route registration, query parsing,
//! payload parsing, and JSON response shape are exercised end-to-end. The
//! pure aggregator logic is covered by unit tests in `routes::audit`.

mod common;

use std::sync::Arc;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_core::audit::{AuditEntry, AuditEventType, Lineage};
use aa_core::{AgentId, SessionId};
use aa_gateway::AuditReader;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Build a dry-run shadow `deny` audit entry tagged with an org tenant.
fn dry_run_deny_entry(agent_byte: u8, org: &str) -> AuditEntry {
    AuditEntry::new_with_lineage(
        0,
        1_900_000_000_000_000_000,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([agent_byte; 16]),
        SessionId::from_bytes([0xEE; 16]),
        r#"{"dry_run":true,"shadow_decision":"deny"}"#.to_string(),
        [0u8; 32],
        Lineage {
            org_id: Some(org.to_string()),
            ..Lineage::default()
        },
    )
}

fn audit_dir_with(entries: &[AuditEntry]) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("aa-sandbox-test-{}-{id}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut contents = String::new();
    for e in entries {
        contents.push_str(&serde_json::to_string(e).unwrap());
        contents.push('\n');
    }
    std::fs::write(dir.join("audit.jsonl"), contents).unwrap();
    dir
}

fn app_with_auth_and_audit(dir: &std::path::Path) -> axum::Router {
    let mut state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.audit_reader = Arc::new(AuditReader::new(dir.to_path_buf()));
    aa_api::build_app(state)
}

fn bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn sandbox_summary_returns_zero_counts_when_no_audit_entries() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["counts"]["would_be_denies"], 0);
    assert_eq!(json["counts"]["would_be_redactions"], 0);
    assert_eq!(json["counts"]["would_be_pending_approvals"], 0);
    assert!(json["top_rule"].is_null());
    assert_eq!(json["window_secs"], 86_400);
    assert!(json["generated_at"].is_string());
}

#[tokio::test]
async fn sandbox_summary_respects_window_query_param() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary?window=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["window_secs"], 3_600);
}

#[tokio::test]
async fn sandbox_summary_falls_back_to_24h_for_invalid_window() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary?window=garbage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Default is 24h = 86_400 seconds — invalid input degrades to default,
    // matching the violations-by-lineage handler's behaviour.
    assert_eq!(json["window_secs"], 86_400);
}

// ── AAASM-3846 — function-level/tenant authz on the sandbox summary ──────────

/// The endpoint previously took no caller; it must now reject an unauthenticated
/// request rather than serving every tenant's shadow-mode aggregate.
#[tokio::test]
async fn sandbox_summary_unauthenticated_is_401() {
    let app = aa_api::build_app(common::test_state_with_auth(AuthMode::On, &[], 1000));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/sandbox-summary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// A tenant-scoped caller's aggregate counts only its own org's shadow events,
/// never another org's.
#[tokio::test]
async fn sandbox_summary_tenant_caller_counts_only_own_org() {
    let dir = audit_dir_with(&[
        dry_run_deny_entry(0x11, "acme"),
        dry_run_deny_entry(0x22, "globex"),
        dry_run_deny_entry(0x23, "globex"),
    ]);
    let app = app_with_auth_and_audit(&dir);

    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let response = app
        .oneshot(bearer("/api/v1/audit/sandbox-summary", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["counts"]["would_be_denies"], 1,
        "an acme-scoped caller must count only acme's one shadow deny, not globex's two"
    );
}

/// An admin caller still aggregates every org's shadow events.
#[tokio::test]
async fn sandbox_summary_admin_counts_all_orgs() {
    let dir = audit_dir_with(&[
        dry_run_deny_entry(0x11, "acme"),
        dry_run_deny_entry(0x22, "globex"),
        dry_run_deny_entry(0x23, "globex"),
    ]);
    let app = app_with_auth_and_audit(&dir);

    let token = common::generate_test_jwt("admin", &[Scope::Admin]);
    let response = app
        .oneshot(bearer("/api/v1/audit/sandbox-summary", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["counts"]["would_be_denies"], 3,
        "admin counts every org's shadow denies"
    );
}
