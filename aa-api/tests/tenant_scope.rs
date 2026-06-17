//! Integration tests for per-tenant authorization of the cost / budget
//! surfaces (AAASM-3139), which complete the per-tenant filtering that
//! AAASM-3126 (#1089) deferred to an admin gate.

mod common;

use std::collections::{BTreeMap, VecDeque};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rust_decimal::Decimal;
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_gateway::registry::{AgentRecord, AgentStatus};

fn bearer(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

fn agent_with_team(id_byte: u8, team: &str) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: format!("agent-{id_byte}"),
        framework: "test".to_string(),
        version: "0".to_string(),
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
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(team.to_string()),
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

fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

#[tokio::test]
async fn costs_tenant_caller_sees_only_its_own_team() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    // Seed spend for two distinct teams.
    state.budget_tracker.record_raw_spend(
        aa_core::identity::AgentId::from_bytes([1; 16]),
        Some("alpha"),
        None,
        Decimal::new(5, 0),
    );
    state.budget_tracker.record_raw_spend(
        aa_core::identity::AgentId::from_bytes([2; 16]),
        Some("beta"),
        None,
        Decimal::new(7, 0),
    );
    let app = aa_api::build_app(state);

    // A read-only caller scoped to team "alpha" must see only the alpha row.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let response = app.oneshot(bearer("/api/v1/costs", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let teams = json["per_team"].as_array().unwrap();
    assert_eq!(teams.len(), 1, "tenant caller must see only its own team");
    assert_eq!(teams[0]["team_id"], "alpha");
    // No per-agent breakdown leaks to a non-admin tenant caller.
    assert!(json["per_agent"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn costs_admin_sees_all_teams() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.budget_tracker.record_raw_spend(
        aa_core::identity::AgentId::from_bytes([1; 16]),
        Some("alpha"),
        None,
        Decimal::new(5, 0),
    );
    state.budget_tracker.record_raw_spend(
        aa_core::identity::AgentId::from_bytes([2; 16]),
        Some("beta"),
        None,
        Decimal::new(7, 0),
    );
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt("admin", &[Scope::Admin]);
    let response = app.oneshot(bearer("/api/v1/costs", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["per_team"].as_array().unwrap().len(), 2, "admin sees every team");
}

#[tokio::test]
async fn agent_budget_tenant_caller_can_read_own_team_agent() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xAA, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}/budget", hex_id(0xAA));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "a team-scoped caller may read its own team's agent budget"
    );
}

#[tokio::test]
async fn agent_budget_cross_tenant_read_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xBB, "beta")).unwrap();
    let app = aa_api::build_app(state);

    // Caller scoped to "alpha" must not read a "beta" agent's budget.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}/budget", hex_id(0xBB));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "cross-tenant budget read is denied"
    );
}
