//! Integration tests for the agent detail endpoints — capabilities, budget
//! rollup, and subtree-burn — plus the resume-conflict guard (AAASM-3805).
//!
//! These handlers carry tenant-authz, existence (404), and id-validation (400)
//! branches that the core agents test suite did not exercise. Auth is left off
//! (the bypass caller is admin) so these focus on the handler bodies and their
//! 400/404/409 error paths; tenant-403 paths are covered by tenant_scope.rs.

mod common;

use std::collections::BTreeMap;

use aa_gateway::registry::{AgentRecord, AgentStatus};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Build a test `AgentRecord` with a known 16-byte id and the given status.
fn test_agent(id_byte: u8, status: AgentStatus) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: format!("test-agent-{id_byte}"),
        framework: "langgraph".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: vec!["read_file".to_string()],
        public_key: "test-pubkey".to_string(),
        credential_token: "test-token".to_string(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: std::collections::VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        org_id: None,
    }
}

fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, value)
}

// ── capabilities ────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_capabilities_returns_200_for_registered_agent() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x11, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);

    let (status, body) = get(app, &format!("/api/v1/agents/{}/capabilities", hex_id(0x11))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["allow"].is_array());
    assert!(body["deny"].is_array());
    assert!(body["sources"].is_array());
}

#[tokio::test]
async fn get_capabilities_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let (status, _) = get(app, &format!("/api/v1/agents/{}/capabilities", hex_id(0x99))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_capabilities_returns_400_for_invalid_id() {
    let app = common::test_app();
    let (status, _) = get(app, "/api/v1/agents/not-hex/capabilities").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── budget rollup ────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_budget_returns_200_for_registered_agent() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x22, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);

    let (status, body) = get(app, &format!("/api/v1/agents/{}/budget", hex_id(0x22))).await;
    assert_eq!(status, StatusCode::OK);
    // The rollup always carries at least the agent + global rows.
    assert!(!body["rows"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_budget_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let (status, _) = get(app, &format!("/api/v1/agents/{}/budget", hex_id(0x98))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_budget_returns_400_for_invalid_id() {
    let app = common::test_app();
    let (status, _) = get(app, "/api/v1/agents/zz/budget").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── subtree-burn ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_subtree_burn_returns_200_with_default_and_30d_period() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x33, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);

    // Default period (7d) — one dense point per day, even with no recorded spend.
    let (status, body) = get(app, &format!("/api/v1/agents/{}/subtree-burn", hex_id(0x33))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["period"], "7d");
    assert_eq!(body["points"].as_array().unwrap().len(), 7);

    // Opt-in 30d period.
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x33, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);
    let (status, body) = get(app, &format!("/api/v1/agents/{}/subtree-burn?period=30d", hex_id(0x33))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["period"], "30d");
    assert_eq!(body["points"].as_array().unwrap().len(), 30);
}

#[tokio::test]
async fn get_subtree_burn_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let (status, _) = get(app, &format!("/api/v1/agents/{}/subtree-burn", hex_id(0x97))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_subtree_burn_returns_400_for_invalid_id() {
    let app = common::test_app();
    let (status, _) = get(app, "/api/v1/agents/xyz/subtree-burn").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── resume conflict + id validation ──────────────────────────────────────────

#[tokio::test]
async fn resume_active_agent_returns_409() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x44, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agents/{}/resume", hex_id(0x44)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // Only suspended agents can be resumed; an already-active one is a conflict.
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn resume_invalid_id_returns_400() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/agents/nothex/resume")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
