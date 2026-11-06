//! AAASM-6444 review (MEDIUM 2) — an org-bound caller is pinned to its own org on
//! `GET /api/v1/logs`, admin scope included. Only an *unbound* admin (the local
//! single-process admin key, an operator) may choose the org, which is the control
//! the J59 two-org row uses.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};
use aa_gateway::AuditReader;

fn entry(seq: u64, org: &str) -> AuditEntry {
    AuditEntry::new_with_lineage(
        seq,
        1_000 + seq,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([seq as u8 + 1; 16]),
        SessionId::from_bytes([0xEE; 16]),
        "{}".to_string(),
        [0u8; 32],
        Lineage {
            org_id: Some(org.to_string()),
            ..Lineage::default()
        },
    )
}

fn app() -> axum::Router {
    let dir = std::env::temp_dir().join(format!("aa-6444-pin-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let body: String = [entry(0, "acme"), entry(1, "globex")]
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect();
    std::fs::write(dir.join("audit.jsonl"), body).unwrap();
    let mut state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.audit_reader = Arc::new(AuditReader::new(dir));
    aa_api::build_app(state)
}

async fn orgs_seen(token: &str, query: &str) -> (StatusCode, Vec<u64>) {
    let response = app()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/logs?per_page=100{query}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let mut seqs: Vec<u64> = json["items"]
        .as_array()
        .map(|a| a.iter().map(|e| e["seq"].as_u64().unwrap()).collect())
        .unwrap_or_default();
    seqs.sort_unstable();
    (status, seqs)
}

/// An admin bound to acme asking for globex gets acme's entries only (seq 0), and
/// asking for nothing gets acme's entries only — never globex's (seq 1).
#[tokio::test]
async fn an_org_bound_admin_cannot_read_another_org() {
    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Admin], None, Some("acme"));
    let (status, cross) = orgs_seen(&token, "&org_id=globex").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !cross.contains(&1),
        "an acme-bound admin read globex's entry: {cross:?}"
    );
    let (_, all) = orgs_seen(&token, "").await;
    assert_eq!(all, vec![0], "an acme-bound admin with no filter must see only acme");
}

/// Negative control: an admin with no org binding still chooses the org, so the
/// empty answer above is the pin and not missing data.
#[tokio::test]
async fn an_unbound_admin_still_chooses_the_org() {
    let token = common::generate_test_jwt("u", &[Scope::Admin]);
    let (_, globex) = orgs_seen(&token, "&org_id=globex").await;
    assert_eq!(globex, vec![1]);
    let (_, everything) = orgs_seen(&token, "").await;
    assert_eq!(everything, vec![0, 1]);
}
