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
        parent_key: parent_id,
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
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview")
                .body(Body::empty())
                .unwrap(),
        )
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
    state
        .agent_registry
        .register(make_agent(0x01, "root-a", 0, Some("team-a"), None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child-a", 1, Some("team-a"), Some([0x01; 16])))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x03, "standalone", 0, None, None))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview")
                .body(Body::empty())
                .unwrap(),
        )
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
    state
        .agent_registry
        .register(make_agent(0x01, "active-agent", 0, None, None))
        .unwrap();
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

#[tokio::test]
async fn topology_overview_min_depth_filter_excludes_shallow_agents() {
    let state = common::test_state();
    // depth 0 root + depth 1 child in the same team
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, Some("team-a"), None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child", 1, Some("team-a"), Some([0x01; 16])))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview?min_depth=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Only the depth-1 child passes the filter; the depth-0 root is excluded.
    assert_eq!(json["total_agent_count"], 1);
}

#[tokio::test]
async fn topology_team_min_depth_filter_excludes_root_member() {
    let state = common::test_state();
    // root (depth 0) + two children (depth 1) all in "team-x"
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, Some("team-x"), None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child-a", 1, Some("team-x"), Some([0x01; 16])))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x03, "child-b", 1, Some("team-x"), Some([0x01; 16])))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/team/team-x?min_depth=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Only the two depth-1 children pass; the depth-0 root is excluded.
    assert_eq!(json["agent_count"], 2);
    let members = json["members"].as_array().unwrap();
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|m| m["depth"].as_u64().unwrap() >= 1));
}

#[tokio::test]
async fn topology_overview_show_budget_populates_governance_level() {
    // Use a standalone root (no team) so it appears in standalone_root_agents,
    // which is where get_overview conditionally sets governance_level.
    let state = common::test_state();
    state
        .agent_registry
        .register(make_agent(0x01, "standalone-root", 0, None, None))
        .unwrap();

    let app = aa_api::server::build_app(state);

    // Without show_budget: governance_level is skipped by serde (None → omitted).
    let resp_no_budget = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp_no_budget.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_no_budget = &json["standalone_root_agents"][0];
    assert!(
        agent_no_budget["governance_level"].is_null(),
        "governance_level should be absent without ?show_budget=true"
    );

    // With show_budget=true: governance_level must be a non-null string.
    let resp_with_budget = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview?show_budget=true")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(resp_with_budget.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let agent_with_budget = &json["standalone_root_agents"][0];
    assert!(
        agent_with_budget["governance_level"].is_string(),
        "governance_level should be a string with ?show_budget=true"
    );
}

/// Build a state pre-populated with a realistic fixture:
/// - 2 teams (alpha, beta), 1 standalone root
/// - alpha: root-a (depth 0), a1..a4 (depth 1), a5..a6 (depth 2)  → 7 agents
/// - beta:  root-b (depth 0), b1..b3 (depth 1)                     → 4 agents
/// - root-s: standalone root (no team)                              → 1 agent
///
/// Total: 12 agents, 3 roots
fn large_fixture_state() -> aa_api::state::AppState {
    let state = common::test_state();
    let reg = &state.agent_registry;

    // alpha team
    reg.register(make_agent(0xA0, "root-a", 0, Some("alpha"), None))
        .unwrap();
    for (byte, name) in [(0xA1, "a1"), (0xA2, "a2"), (0xA3, "a3"), (0xA4, "a4")] {
        reg.register(make_agent(byte, name, 1, Some("alpha"), Some([0xA0; 16])))
            .unwrap();
    }
    reg.register(make_agent(0xA5, "a5", 2, Some("alpha"), Some([0xA1; 16])))
        .unwrap();
    reg.register(make_agent(0xA6, "a6", 2, Some("alpha"), Some([0xA1; 16])))
        .unwrap();

    // beta team
    reg.register(make_agent(0xB0, "root-b", 0, Some("beta"), None)).unwrap();
    for (byte, name) in [(0xB1, "b1"), (0xB2, "b2"), (0xB3, "b3")] {
        reg.register(make_agent(byte, name, 1, Some("beta"), Some([0xB0; 16])))
            .unwrap();
    }

    // standalone root
    reg.register(make_agent(0xC0, "root-s", 0, None, None)).unwrap();

    state
}

#[tokio::test]
async fn topology_overview_large_fixture_counts_correctly() {
    let state = large_fixture_state();
    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/overview")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_agent_count"], 12);
    assert_eq!(json["root_agent_count"], 3);
    assert_eq!(json["team_count"], 2);

    let teams = json["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 2);
    // teams are sorted alphabetically: alpha first, beta second
    assert_eq!(teams[0]["team_id"], "alpha");
    assert_eq!(teams[0]["agent_count"], 7);
    assert_eq!(teams[1]["team_id"], "beta");
    assert_eq!(teams[1]["agent_count"], 4);

    let standalone = json["standalone_root_agents"].as_array().unwrap();
    assert_eq!(standalone.len(), 1);
    assert_eq!(standalone[0]["name"], "root-s");
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
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, None, None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child", 1, None, Some([0x01; 16])))
        .unwrap();

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

#[tokio::test]
async fn topology_tree_returns_422_for_non_root_agent() {
    let state = common::test_state();
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, None, None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child", 1, None, Some([0x01; 16])))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0x02); // child at depth 1 — not a root
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/topology/tree/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
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
    state
        .agent_registry
        .register(make_agent(0x01, "root-a", 0, Some("team-x"), None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child-a", 1, Some("team-x"), Some([0x01; 16])))
        .unwrap();

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
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, None, None))
        .unwrap();

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
    // A root agent's lineage contains only itself as the single element (root-first ordering).
    assert_eq!(json["ancestor_count"], 1);
    let ancestors = json["ancestors"].as_array().unwrap();
    assert_eq!(ancestors.len(), 1);
    assert_eq!(ancestors[0]["depth"], 0);
}

#[tokio::test]
async fn topology_lineage_multi_hop_returns_root_first_ordering() {
    let state = common::test_state();
    let reg = &state.agent_registry;
    // root → child → grandchild
    reg.register(make_agent(0x01, "root", 0, None, None)).unwrap();
    reg.register(make_agent(0x02, "child", 1, None, Some([0x01; 16])))
        .unwrap();
    reg.register(make_agent(0x03, "grandchild", 2, None, Some([0x02; 16])))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0x03);
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

    assert_eq!(json["ancestor_count"], 3);
    let ancestors = json["ancestors"].as_array().unwrap();
    assert_eq!(ancestors.len(), 3);
    // root-first ordering: depth 0, 1, 2
    assert_eq!(ancestors[0]["depth"], 0);
    assert_eq!(ancestors[0]["name"], "root");
    assert_eq!(ancestors[1]["depth"], 1);
    assert_eq!(ancestors[1]["name"], "child");
    assert_eq!(ancestors[2]["depth"], 2);
    assert_eq!(ancestors[2]["name"], "grandchild");
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

#[tokio::test]
async fn topology_stats_empty_registry_returns_zeros() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/stats")
                .body(Body::empty())
                .unwrap(),
        )
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
    state
        .agent_registry
        .register(make_agent(0x01, "root", 0, Some("team-a"), None))
        .unwrap();
    state
        .agent_registry
        .register(make_agent(0x02, "child", 1, Some("team-a"), Some([0x01; 16])))
        .unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/stats")
                .body(Body::empty())
                .unwrap(),
        )
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
    // histogram fields must be present
    assert!(json["depth_histogram"].is_object());
    assert!(json["team_size_histogram"].is_object());
    assert!(json["spawn_count_histogram"].is_object());
    assert!(json["orphan_count"].is_number());
    assert!(json["avg_children_per_parent"].is_number());
}

#[tokio::test]
async fn topology_stats_large_fixture_histograms_are_correct() {
    // large_fixture_state: alpha(7) + beta(4) + standalone root-s(1) = 12 agents
    // alpha: root-a(0), a1..a4(1), a5(2), a6(2)
    // beta:  root-b(0), b1..b3(1)
    // standalone: root-s(0)
    // orphans (depth>0, no team): none — all non-roots belong to a team
    let state = large_fixture_state();
    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/topology/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_agents"], 12);
    assert_eq!(json["max_depth"], 2);
    assert_eq!(json["orphan_count"], 0);

    // depth histogram: depth 0 → 3 roots, depth 1 → 7 (a1-a4 + b1-b3), depth 2 → 2 (a5, a6)
    assert_eq!(json["depth_histogram"]["0"], 3);
    assert_eq!(json["depth_histogram"]["1"], 7);
    assert_eq!(json["depth_histogram"]["2"], 2);

    // team_size_histogram: alpha has 7 members → bucket 7; beta has 4 → bucket 4
    assert_eq!(json["team_size_histogram"]["7"], 1);
    assert_eq!(json["team_size_histogram"]["4"], 1);

    // avg_children_per_parent > 0 (root-a has 4 children, a1 has 2, root-b has 3)
    assert!(json["avg_children_per_parent"].as_f64().unwrap() > 0.0);
}
