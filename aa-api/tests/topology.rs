//! Integration tests for the topology endpoints.

mod common;

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_gateway::registry::{AgentRecord, AgentStatus, SuspendReason};

fn make_agent(id_byte: u8, name: &str, depth: u32, team_id: Option<&str>, parent_id: Option<[u8; 16]>) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: name.to_string(),
        framework: "langgraph".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: vec![],
        public_key: "test-pubkey".to_string(),
        credential_token: "test-token".to_string(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: std::collections::VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: parent_id.map(|b| format!("{}", b[0])),
        team_id: team_id.map(str::to_string),
        depth,
        delegation_reason: if depth > 0 { Some("subtask".to_string()) } else { None },
        spawned_by_tool: None,
        root_agent_id: if depth == 0 { Some([id_byte; 16]) } else { parent_id },
        children: Vec::new(),
        parent_key: None,
    }
}

fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_overview_empty_registry_returns_200() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/topology/overview").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["team_count"], 0);
    assert_eq!(json["total_agent_count"], 0);
    assert_eq!(json["root_agent_count"], 0);
    assert!(json["teams"].as_array().unwrap().is_empty());
    assert!(json["standalone_root_agents"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn topology_overview_with_agents_returns_correct_counts() {
    let state = common::test_state();
    // root in team-a, child in team-a, standalone root
    state.agent_registry.register(make_agent(0x01, "root-a", 0, Some("team-a"), None)).unwrap();
    state.agent_registry.register(make_agent(0x02, "child-a", 1, Some("team-a"), Some([0x01; 16]))).unwrap();
    state.agent_registry.register(make_agent(0x03, "standalone", 0, None, None)).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/topology/overview").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["team_count"], 1);
    assert_eq!(json["total_agent_count"], 3);
    assert_eq!(json["root_agent_count"], 2);
    assert_eq!(json["teams"].as_array().unwrap().len(), 1);
    assert_eq!(json["teams"][0]["team_id"], "team-a");
    assert_eq!(json["teams"][0]["agent_count"], 2);
    assert_eq!(json["standalone_root_agents"].as_array().unwrap().len(), 1);
    assert_eq!(json["standalone_root_agents"][0]["name"], "standalone");
}

#[tokio::test]
async fn topology_overview_status_filter_works() {
    let state = common::test_state();
    state.agent_registry.register(make_agent(0x01, "active-agent", 0, None, None)).unwrap();
    let mut suspended = make_agent(0x02, "suspended-agent", 0, None, None);
    suspended.status = AgentStatus::Suspended(SuspendReason::Manual);
    state.agent_registry.register(suspended).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview?status=active")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_agent_count"], 1);
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_tree_returns_400_for_invalid_id() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/tree/not-a-valid-hex-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn topology_tree_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let id = hex_id(0xAA);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/topology/tree/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn topology_tree_returns_subtree_for_known_agent() {
    let state = common::test_state();
    state.agent_registry.register(make_agent(0x01, "root", 0, None, None)).unwrap();
    state.agent_registry.register(make_agent(0x02, "child", 1, None, Some([0x01; 16]))).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0x01);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/topology/tree/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "root");
    assert_eq!(json["depth"], 0);
    assert_eq!(json["status"], "active");
}

// ---------------------------------------------------------------------------
// Team
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_team_returns_404_for_unknown_team() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/team/nonexistent-team")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn topology_team_returns_members_for_known_team() {
    let state = common::test_state();
    state.agent_registry.register(make_agent(0x01, "root-a", 0, Some("team-x"), None)).unwrap();
    state.agent_registry.register(make_agent(0x02, "child-a", 1, Some("team-x"), Some([0x01; 16]))).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/team/team-x")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["team_id"], "team-x");
    assert_eq!(json["agent_count"], 2);
    let members = json["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    // members are sorted by depth; depth-0 first
    assert_eq!(members[0]["depth"], 0);
    assert_eq!(members[1]["depth"], 1);
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_lineage_returns_400_for_invalid_id() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/lineage/not-hex")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn topology_lineage_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let id = hex_id(0xCC);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/topology/lineage/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn topology_lineage_root_agent_has_no_ancestors() {
    let state = common::test_state();
    state.agent_registry.register(make_agent(0x01, "root", 0, None, None)).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0x01);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/topology/lineage/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ancestor_count"], 0);
    assert!(json["ancestors"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_stats_empty_registry_returns_zeros() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/topology/stats").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_agents"], 0);
    assert_eq!(json["root_agent_count"], 0);
    assert_eq!(json["active_count"], 0);
    assert_eq!(json["team_count"], 0);
}

#[tokio::test]
async fn topology_stats_with_agents_returns_correct_counts() {
    let state = common::test_state();
    state.agent_registry.register(make_agent(0x01, "root", 0, Some("team-a"), None)).unwrap();
    state.agent_registry.register(make_agent(0x02, "child", 1, Some("team-a"), Some([0x01; 16]))).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/topology/stats").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total_agents"], 2);
    assert_eq!(json["root_agent_count"], 1);
    assert_eq!(json["active_count"], 2);
    assert_eq!(json["max_depth"], 1);
    assert_eq!(json["team_count"], 1);
    assert_eq!(json["team_sizes"]["team-a"], 2);
}
