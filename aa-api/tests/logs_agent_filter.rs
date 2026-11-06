//! AAASM-6446 — `GET /api/v1/logs?agent_id=` never widens the result.
//!
//! The filter used to parse only a 32-hex audit id; `zz`, `deadbeef` and an agent
//! name parsed to "no filter" and every agent's entries came back, so
//! `aasm audit export --agent <name>` exported all of them.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};
use aa_gateway::registry::{AgentRecord, AgentStatus};
use aa_gateway::service::convert::hash_to_16;
use aa_gateway::AuditReader;

const ALPHA: &str = "alpha-agent";
const BETA: &str = "beta-agent";
const ALPHA_DID: &str = "did:key:z6MkAlphaAlphaAlphaAlphaAlphaAlphaAlphaAlpha";
const ALPHA_KEY: [u8; 16] = [0xA1; 16];

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn entry(seq: u64, ty: AuditEventType, agent_key: [u8; 16], root: Option<[u8; 16]>, claimed: &str) -> AuditEntry {
    AuditEntry::new_with_lineage(
        seq,
        1_000 + seq,
        ty,
        AgentId::from_bytes(agent_key),
        SessionId::from_bytes([0xEE; 16]),
        serde_json::json!({ "agent_id_claimed": claimed }).to_string(),
        [0u8; 32],
        Lineage {
            root_agent_id: root.map(AgentId::from_bytes),
            ..Lineage::default()
        },
    )
}

fn record(name: &str, key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: key,
        name: name.to_string(),
        framework: "test".into(),
        version: "0".into(),
        risk_tier: 1,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(key),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

/// alpha: a deny keyed by its claimed *name*, and an allow keyed by its did:key
/// with the registry key as root (how the SDK path records them). beta: a deny.
fn app() -> axum::Router {
    let dir = std::env::temp_dir().join(format!("aa-6446-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let entries = [
        entry(0, AuditEventType::PolicyViolation, hash_to_16(ALPHA), None, ALPHA),
        entry(
            1,
            AuditEventType::ToolCallIntercepted,
            hash_to_16(ALPHA_DID),
            Some(ALPHA_KEY),
            ALPHA_DID,
        ),
        entry(2, AuditEventType::PolicyViolation, hash_to_16(BETA), None, BETA),
    ];
    let body: String = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap() + "\n")
        .collect();
    std::fs::write(dir.join("audit.jsonl"), body).unwrap();

    let mut state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.audit_reader = Arc::new(AuditReader::new(dir));
    state.agent_registry.register(record(ALPHA, ALPHA_KEY)).unwrap();
    aa_api::build_app(state)
}

async fn get(query: &str) -> (StatusCode, serde_json::Value) {
    let token = common::generate_test_jwt("u", &[Scope::Admin]);
    let response = app()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/api/v1/logs?{query}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn seqs(body: &serde_json::Value) -> Vec<u64> {
    let mut v: Vec<u64> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect();
    v.sort_unstable();
    v
}

/// Negative control: with no filter every entry is returned, so the empty
/// results below are the filter's doing and not an empty fixture.
#[tokio::test]
async fn no_filter_returns_every_entry() {
    let (status, body) = get("per_page=100").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seqs(&body), vec![0, 1, 2]);
}

#[tokio::test]
async fn unparseable_agent_id_returns_nothing_not_everything() {
    for bogus in ["zz", "deadbeef", "no-such-agent", "00000000000000000000000000000000"] {
        let (status, body) = get(&format!("agent_id={bogus}&per_page=100")).await;
        assert_eq!(status, StatusCode::OK, "{bogus}");
        assert_eq!(body["total"], 0, "agent_id={bogus} must select nothing");
        assert!(seqs(&body).is_empty(), "agent_id={bogus}");
    }
}

#[tokio::test]
async fn agent_name_selects_only_that_agents_entries_including_registry_bound_allows() {
    let (_, body) = get(&format!("agent_id={ALPHA}&per_page=100")).await;
    assert_eq!(
        seqs(&body),
        vec![0, 1],
        "alpha's deny (claimed name) and its did:key allow (via the registry)"
    );
    let (_, body) = get(&format!("agent_id={BETA}&per_page=100")).await;
    assert_eq!(seqs(&body), vec![2]);
}

#[tokio::test]
async fn did_key_and_hex_audit_id_still_select_their_agent() {
    let (_, by_did) = get(&format!("agent_id={ALPHA_DID}&per_page=100")).await;
    assert_eq!(seqs(&by_did), vec![1]);
    let (_, by_hex) = get(&format!("agent_id={}&per_page=100", hex16(hash_to_16(BETA)))).await;
    assert_eq!(seqs(&by_hex), vec![2]);
}

#[tokio::test]
async fn blank_agent_id_is_a_400_not_an_unfiltered_dump() {
    let (status, _) = get("agent_id=&per_page=100").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_event_type_returns_nothing_not_everything() {
    let (status, body) = get("event_type=NotAnEventType&per_page=100").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 0);
}
