//! Integration tests for the cost-observability read surfaces (AAASM-5032):
//! `GET /api/v1/costs/history` (trailing daily spend series) and
//! `GET /api/v1/costs/budget-tree` (org → team → agent inheritance tree).
//!
//! Each endpoint is covered by a happy path against the auth-disabled app
//! (asserting the shape the dashboard consumes) and a deny-by-default 401 case.

mod common;

use std::collections::{BTreeMap, VecDeque};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use aa_api::auth::scope::Scope;
use aa_api::server::build_app;
use aa_core::AgentId;
use aa_gateway::registry::{AgentRecord, AgentStatus};
use rust_decimal::Decimal;

/// Minimal registered agent for tree/history seeding.
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
        recent_events: VecDeque::new(),
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
        enforcement_mode: None,
        org_id: None,
    }
}

async fn get_json(app: axum::Router, uri: &str) -> serde_json::Value {
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "expected 200 for {uri}");
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn assert_requires_auth(uri: &str) {
    let (_plaintext, entry) = common::generate_test_api_key("costs-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);
    let res = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "expected 401 for {uri}");
}

// --- costs/history --------------------------------------------------------

#[tokio::test]
async fn cost_history_returns_dense_seven_day_series_with_todays_spend() {
    let state = common::test_state();
    state
        .agent_registry
        .register(make_agent(0x01, "spender", 0, Some("team-a"), None))
        .unwrap();
    // Two same-day charges accrue onto today's bucket.
    state.budget_tracker.record_raw_spend(
        AgentId::from_bytes([0x01; 16]),
        Some("team-a"),
        None,
        Decimal::new(250, 2),
    );
    state.budget_tracker.record_raw_spend(
        AgentId::from_bytes([0x01; 16]),
        Some("team-a"),
        None,
        Decimal::new(150, 2),
    );

    let json = get_json(build_app(state), "/api/v1/costs/history").await;
    assert_eq!(json["days"], 7, "default window is 7 days");
    let points = json["points"].as_array().expect("points must be an array");
    assert_eq!(points.len(), 7, "series is dense (one point per day)");
    for p in points {
        assert!(p["date"].as_str().is_some(), "each point carries a date");
        assert!(p["spend_usd"].as_str().is_some(), "spend is a decimal string");
    }
    // Only today (the last bucket) has spend; the sum of both charges appears.
    assert_eq!(points[6]["spend_usd"], "4.00", "today sums both same-day charges");
    assert_eq!(points[0]["spend_usd"], "0", "earlier days are zero-filled");
}

#[tokio::test]
async fn cost_history_days_param_is_honoured_and_clamped() {
    let json = get_json(common::test_app(), "/api/v1/costs/history?days=3").await;
    assert_eq!(json["days"], 3);
    assert_eq!(json["points"].as_array().unwrap().len(), 3);

    // Beyond the 90-day ceiling the window clamps rather than returning an
    // unbounded series.
    let clamped = get_json(common::test_app(), "/api/v1/costs/history?days=999").await;
    assert_eq!(clamped["days"], 90);
    assert_eq!(clamped["points"].as_array().unwrap().len(), 90);
}

#[tokio::test]
async fn cost_history_requires_authentication() {
    assert_requires_auth("/api/v1/costs/history").await;
}

// --- costs/budget-tree ----------------------------------------------------

#[tokio::test]
async fn budget_tree_nests_org_team_and_agents() {
    let state = common::test_state();
    // team-a: a root agent that spawned one sub-agent; team-b: a lone root.
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
        .register(make_agent(0x03, "root-b", 0, Some("team-b"), None))
        .unwrap();
    state.budget_tracker.record_raw_spend(
        AgentId::from_bytes([0x01; 16]),
        Some("team-a"),
        None,
        Decimal::new(500, 2),
    );
    state.budget_tracker.record_raw_spend(
        AgentId::from_bytes([0x02; 16]),
        Some("team-a"),
        None,
        Decimal::new(300, 2),
    );
    state.budget_tracker.record_raw_spend(
        AgentId::from_bytes([0x03; 16]),
        Some("team-b"),
        None,
        Decimal::new(200, 2),
    );

    let json = get_json(build_app(state), "/api/v1/costs/budget-tree").await;
    let root = &json["root"];
    assert_eq!(root["kind"], "org");
    assert_eq!(root["depth"], 0);
    // Org subtree = every team's subtree = 5.00 + 3.00 + 2.00.
    assert_eq!(root["subtree_spend_usd"], "10.00");

    let teams = root["children"].as_array().expect("org has team children");
    assert_eq!(teams.len(), 2, "two teams");
    // Teams are sorted by id, so team-a is first.
    let team_a = &teams[0];
    assert_eq!(team_a["kind"], "team");
    assert_eq!(team_a["label"], "team-a");
    assert_eq!(team_a["depth"], 1);
    // team-a subtree = root-a own (5.00) + spawned child-a (3.00).
    assert_eq!(team_a["subtree_spend_usd"], "8.00");

    let root_a = &team_a["children"][0];
    assert_eq!(root_a["kind"], "agent");
    assert_eq!(root_a["own_spend_usd"], "5.00");
    assert_eq!(
        root_a["subtree_spend_usd"], "8.00",
        "agent subtree rolls in its sub-agent"
    );
    assert!(
        root_a["governance_level"].as_str().is_some(),
        "agent nodes carry a governance level"
    );
    // child-a nests under root-a (not as a second team-a root).
    let child_a = &root_a["children"][0];
    assert_eq!(child_a["kind"], "agent");
    assert_eq!(child_a["label"], "child-a");
    assert_eq!(child_a["own_spend_usd"], "3.00");
}

#[tokio::test]
async fn budget_tree_root_is_null_when_no_agents_visible() {
    // A fresh registry has no agents, so an (admin) caller sees an empty tree.
    let json = get_json(common::test_app(), "/api/v1/costs/budget-tree").await;
    assert!(
        json["root"].is_null(),
        "no visible agents → null root for an empty-state client"
    );
}

#[tokio::test]
async fn budget_tree_requires_authentication() {
    assert_requires_auth("/api/v1/costs/budget-tree").await;
}
