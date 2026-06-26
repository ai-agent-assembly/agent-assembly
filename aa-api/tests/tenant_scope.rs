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
    agent_with_tenant(id_byte, Some(team), None)
}

/// Build a request with an explicit method, URI, bearer token, and JSON body.
fn json_bearer(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Build a root `AgentRecord` tagged with an optional team and org (AAASM-3483).
fn agent_with_tenant(id_byte: u8, team: Option<&str>, org: Option<&str>) -> AgentRecord {
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
        team_id: team.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some([id_byte; 16]),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        org_id: org.map(str::to_string),
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

// AAASM-3790 — the `GET /agents/{id}` read path was missing the
// `authorize_agent_access` gate its delete/suspend siblings already had.
#[tokio::test]
async fn get_agent_cross_tenant_read_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xC1, "beta")).unwrap();
    let app = aa_api::build_app(state);

    // Caller scoped to "alpha" must not read a "beta" agent's record.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}", hex_id(0xC1));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "cross-tenant agent record read is denied"
    );
}

// ---------------------------------------------------------------------------
// AAASM-3483 — topology & audit-log cross-tenant isolation (security
// regression). Reproduces the four leaks the QA harness flagged on base SHA
// ebc4d7dc (verification-reports/base-branch-2026-06/AAASM-3463-org-isolation.md
// + verification-reports/qa3463/): an `acme`/`alpha`-scoped caller must not read
// `globex`/`beta` topology or audit, and a missing filter must not become an
// all-tenant dump.
// ---------------------------------------------------------------------------

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// TC1 — a tenant-scoped caller cannot read another org's topology overview
/// even with an explicit `?org_id` selector for that org.
#[tokio::test]
async fn topology_overview_cross_org_explicit_filter_is_empty() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state
        .agent_registry
        .register(agent_with_tenant(0x11, Some("research"), Some("globex")))
        .unwrap();
    let app = aa_api::build_app(state);

    // Caller scoped to org "acme" asks for globex's overview.
    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let response = app
        .oneshot(bearer("/api/v1/topology/overview?org_id=globex", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["total_agent_count"], 0,
        "an acme-scoped caller must not see globex's agents via ?org_id=globex"
    );
    assert!(json["teams"].as_array().unwrap().is_empty());
}

/// TC1b — omitting the org filter must not dump every tenant's topology.
#[tokio::test]
async fn topology_overview_no_filter_does_not_dump_all_orgs() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state
        .agent_registry
        .register(agent_with_tenant(0x21, Some("eng"), Some("acme")))
        .unwrap();
    state
        .agent_registry
        .register(agent_with_tenant(0x22, Some("research"), Some("globex")))
        .unwrap();
    let app = aa_api::build_app(state);

    // No ?org_id — an acme-scoped caller must still see only acme's one agent.
    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let response = app.oneshot(bearer("/api/v1/topology/overview", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["total_agent_count"], 1,
        "a tenant-scoped caller must see only its own org, not every org"
    );
    let teams = json["teams"].as_array().unwrap();
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0]["team_id"], "eng");
}

/// A non-admin caller with no tenant scope at all gets an empty overview, never
/// a cross-tenant dump.
#[tokio::test]
async fn topology_overview_unscoped_caller_sees_nothing() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state
        .agent_registry
        .register(agent_with_tenant(0x31, Some("eng"), Some("acme")))
        .unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt("u", &[Scope::Read]);
    let response = app.oneshot(bearer("/api/v1/topology/overview", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["total_agent_count"], 0);
}

/// TC3 — a team-scoped caller cannot read another team's topology.
#[tokio::test]
async fn topology_team_cross_team_read_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0x41, "beta")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let response = app.oneshot(bearer("/api/v1/topology/team/beta", &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "an alpha-scoped caller must not read team beta's membership"
    );
}

/// A team-scoped caller may still read its own team's topology.
#[tokio::test]
async fn topology_team_own_team_read_is_ok() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0x51, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let response = app
        .oneshot(bearer("/api/v1/topology/team/alpha", &token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["agent_count"], 1);
}

/// TC4 — a team-scoped caller cannot read another team's agent lineage; the
/// out-of-tenant agent is reported as not found (no existence oracle).
#[tokio::test]
async fn topology_lineage_cross_tenant_read_is_404() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0x61, "beta")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/topology/lineage/{}", hex_id(0x61));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a beta agent's lineage must not leak to an alpha caller"
    );
}

/// The tree endpoint reports another tenant's root as not found.
#[tokio::test]
async fn topology_tree_cross_tenant_read_is_404() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0x71, "beta")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/topology/tree/{}", hex_id(0x71));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Stats aggregate only the caller's own tenant, never every tenant's counts.
#[tokio::test]
async fn topology_stats_are_scoped_to_caller_tenant() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state
        .agent_registry
        .register(agent_with_tenant(0x81, Some("eng"), Some("acme")))
        .unwrap();
    state
        .agent_registry
        .register(agent_with_tenant(0x82, Some("research"), Some("globex")))
        .unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let response = app.oneshot(bearer("/api/v1/topology/stats", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["total_agents"], 1,
        "stats must count only the caller's own org, not every org"
    );
}

/// The audit-log endpoint requires authentication (it previously had none).
#[tokio::test]
async fn logs_endpoint_requires_authentication() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/logs")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "the audit-log endpoint must reject an unauthenticated caller"
    );
}

/// A tenant-scoped caller's audit query is pinned to its own org: an explicit
/// `?org_id` for another org returns an empty page, not that org's audit.
#[tokio::test]
async fn logs_cross_org_explicit_filter_is_empty() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_tenant("u", &[Scope::Read], None, Some("acme"));
    let response = app.oneshot(bearer("/api/v1/logs?org_id=globex", &token)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(
        json["total"], 0,
        "an acme-scoped caller must not read globex's audit via ?org_id=globex"
    );
    assert!(json["items"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// AAASM-3726 — agent lifecycle (delete/suspend/resume) require write-scope +
// tenant ownership. AAASM-3687 — subtree-burn requires read-scope + tenant
// ownership. A read-only token and a cross-tenant token must each be denied.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_agent_read_only_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xA1, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    // Read-only token scoped to the agent's own team — still denied (no write).
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}", hex_id(0xA1));
    let response = app.oneshot(json_bearer("DELETE", &uri, &token, "")).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "a read-only caller must not delete an agent"
    );
}

#[tokio::test]
async fn delete_agent_cross_tenant_write_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xB1, "beta")).unwrap();
    let app = aa_api::build_app(state);

    // Write token scoped to "alpha" must not delete a "beta" agent.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Write], "alpha");
    let uri = format!("/api/v1/agents/{}", hex_id(0xB1));
    let response = app.oneshot(json_bearer("DELETE", &uri, &token, "")).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "cross-tenant agent delete is denied"
    );
}

#[tokio::test]
async fn suspend_agent_read_only_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xA2, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}/suspend", hex_id(0xA2));
    let response = app
        .oneshot(json_bearer("POST", &uri, &token, r#"{"reason":"x"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn suspend_agent_cross_tenant_write_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xB2, "beta")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Write], "alpha");
    let uri = format!("/api/v1/agents/{}/suspend", hex_id(0xB2));
    let response = app
        .oneshot(json_bearer("POST", &uri, &token, r#"{"reason":"x"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn resume_agent_read_only_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xA3, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}/resume", hex_id(0xA3));
    let response = app.oneshot(json_bearer("POST", &uri, &token, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn resume_agent_cross_tenant_write_token_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xB3, "beta")).unwrap();
    let app = aa_api::build_app(state);

    let token = common::generate_test_jwt_for_team("u", &[Scope::Write], "alpha");
    let uri = format!("/api/v1/agents/{}/resume", hex_id(0xB3));
    let response = app.oneshot(json_bearer("POST", &uri, &token, "")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_agent_own_team_write_token_is_allowed() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xA4, "alpha")).unwrap();
    let app = aa_api::build_app(state);

    // A write token scoped to the agent's own team may delete it.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Write], "alpha");
    let uri = format!("/api/v1/agents/{}", hex_id(0xA4));
    let response = app.oneshot(json_bearer("DELETE", &uri, &token, "")).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "an own-team write caller may delete its agent"
    );
}

#[tokio::test]
async fn subtree_burn_cross_tenant_read_is_403() {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    state.agent_registry.register(agent_with_team(0xC1, "beta")).unwrap();
    let app = aa_api::build_app(state);

    // An alpha-scoped read caller must not read a beta agent's subtree burn.
    let token = common::generate_test_jwt_for_team("u", &[Scope::Read], "alpha");
    let uri = format!("/api/v1/agents/{}/subtree-burn", hex_id(0xC1));
    let response = app.oneshot(bearer(&uri, &token)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "cross-tenant subtree-burn read is denied"
    );
}
