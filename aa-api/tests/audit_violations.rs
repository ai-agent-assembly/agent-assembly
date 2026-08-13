//! Integration tests for `GET /api/v1/audit/violations-by-lineage` (AAASM-3805).

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

/// Build a `PolicyViolation` audit entry tagged with an org tenant.
fn violation_entry(agent_byte: u8, org: &str) -> AuditEntry {
    AuditEntry::new_with_lineage(
        0,
        1_900_000_000_000_000_000,
        AuditEventType::PolicyViolation,
        AgentId::from_bytes([agent_byte; 16]),
        SessionId::from_bytes([0xEE; 16]),
        r#"{"policy_rule":"rule-x"}"#.to_string(),
        [0u8; 32],
        Lineage {
            org_id: Some(org.to_string()),
            ..Lineage::default()
        },
    )
}

/// Write JSONL entries to a fresh temp dir and return its path.
fn audit_dir_with(entries: &[AuditEntry]) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("aa-violations-test-{}-{id}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut contents = String::new();
    for e in entries {
        contents.push_str(&serde_json::to_string(e).unwrap());
        contents.push('\n');
    }
    std::fs::write(dir.join("audit.jsonl"), contents).unwrap();
    dir
}

/// Build an auth-enabled app whose audit reader is backed by `dir`.
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
async fn violations_by_lineage_returns_200_with_empty_set() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/violations-by-lineage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["nodes"].is_array());
    assert!(json["window_secs"].is_number());
    assert!(json["generated_at"].is_string());
}

#[tokio::test]
async fn violations_by_lineage_accepts_window_param() {
    let app = common::test_app();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/violations-by-lineage?window=1h")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["window_secs"], 3600);
}

// ── AAASM-3846 — function-level/tenant authz on the audit heatmap ────────────

/// The endpoint previously took no caller; it must now reject an unauthenticated
/// request rather than serving every tenant's violation heatmap.
#[tokio::test]
async fn violations_by_lineage_unauthenticated_is_401() {
    let app = aa_api::build_app(common::test_state_with_auth(AuthMode::On, &[], 1000));
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit/violations-by-lineage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// A tenant-scoped caller's heatmap is pinned to its own org: a `globex`
/// violation must never appear for an `acme`-scoped caller.
#[tokio::test]
async fn violations_by_lineage_tenant_caller_sees_only_own_org() {
    let dir = audit_dir_with(&[violation_entry(0x11, "acme"), violation_entry(0x22, "globex")]);
    let app = app_with_auth_and_audit(&dir);

    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let resp = app
        .oneshot(bearer("/api/v1/audit/violations-by-lineage", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let nodes = json["nodes"].as_array().unwrap();
    assert_eq!(
        nodes.len(),
        1,
        "an acme-scoped caller must see only acme's violation node"
    );
    assert_eq!(nodes[0]["agent_id"], hex::encode([0x11; 16]));
}

/// An admin caller still sees every org's violations.
#[tokio::test]
async fn violations_by_lineage_admin_sees_all_orgs() {
    let dir = audit_dir_with(&[violation_entry(0x11, "acme"), violation_entry(0x22, "globex")]);
    let app = app_with_auth_and_audit(&dir);

    let token = common::generate_test_jwt("admin", &[Scope::Admin]);
    let resp = app
        .oneshot(bearer("/api/v1/audit/violations-by-lineage", &token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["nodes"].as_array().unwrap().len(), 2, "admin sees every org");
}
