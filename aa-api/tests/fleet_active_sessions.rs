//! Integration tests for `GET /api/v1/fleet/active-sessions` (AAASM-5038).
//!
//! The endpoint is a read-only, tenant-scoped aggregation of the
//! `active_sessions` the registry already tracks per agent. These tests cover
//! the empty case, the fleet-wide flatten + newest-first ordering, the shape of
//! each row (agent identity attached), and the same cross-tenant isolation the
//! sibling `list_agents` enforces.

mod common;

use std::collections::{BTreeMap, VecDeque};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_gateway::registry::{ActiveSession, AgentRecord, AgentStatus};

/// Build a test `AgentRecord` tagged with an optional team and the given
/// active sessions.
fn agent_with_sessions(id_byte: u8, team: Option<&str>, sessions: Vec<ActiveSession>) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: format!("agent-{id_byte}"),
        framework: "langgraph".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: Vec::new(),
        public_key: String::new(),
        credential_token: String::new(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: sessions.len() as u32,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: sessions,
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: team.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some([id_byte; 16]),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        org_id: None,
    }
}

fn session(id: &str, offset_secs: i64, status: &str) -> ActiveSession {
    ActiveSession {
        session_id: id.to_string(),
        started_at: chrono::Utc::now() - chrono::Duration::seconds(offset_secs),
        status: status.to_string(),
    }
}

fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

fn bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn active_sessions_returns_empty_array_when_no_sessions() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fleet/active-sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn active_sessions_flattens_all_agents_newest_first() {
    let state = common::test_state();
    // Two agents, three sessions total, deliberately out of chronological order.
    state
        .agent_registry
        .register(agent_with_sessions(
            0xAA,
            None,
            vec![session("sess-old", 300, "idle"), session("sess-new", 5, "running")],
        ))
        .unwrap();
    state
        .agent_registry
        .register(agent_with_sessions(
            0xBB,
            None,
            vec![session("sess-mid", 60, "running")],
        ))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fleet/active-sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 3, "all three sessions are flattened into one list");

    // Newest-first ordering by started_at.
    let order: Vec<&str> = rows.iter().map(|r| r["session_id"].as_str().unwrap()).collect();
    assert_eq!(order, vec!["sess-new", "sess-mid", "sess-old"]);

    // Each row carries the owning agent's identity plus the session fields.
    let first = &rows[0];
    assert_eq!(first["session_id"], "sess-new");
    assert_eq!(first["status"], "running");
    assert_eq!(first["agent_id"], hex_id(0xAA));
    assert_eq!(first["agent_name"], "agent-170");
    assert!(first["started_at"].as_str().is_some());
}

#[tokio::test]
async fn active_sessions_are_scoped_to_caller_team() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state
        .agent_registry
        .register(agent_with_sessions(
            0xAA,
            Some("alpha"),
            vec![session("alpha-sess", 10, "running")],
        ))
        .unwrap();
    state
        .agent_registry
        .register(agent_with_sessions(
            0xBB,
            Some("beta"),
            vec![session("beta-sess", 10, "running")],
        ))
        .unwrap();
    let app = aa_api::build_app(state);

    // A caller scoped to team "alpha" must only see alpha's sessions.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let response = app
        .oneshot(bearer("/api/v1/fleet/active-sessions", &token))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rows = json.as_array().unwrap();
    assert_eq!(rows.len(), 1, "a team-scoped caller sees only its own team's sessions");
    assert_eq!(rows[0]["session_id"], "alpha-sess");
    assert_eq!(rows[0]["team_id"], "alpha");
}

#[tokio::test]
async fn active_sessions_requires_authentication() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);

    // No bearer credential — deny-by-default like every other protected route.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/fleet/active-sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
