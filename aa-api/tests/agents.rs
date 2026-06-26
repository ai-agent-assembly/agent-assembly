//! Integration tests for the agent endpoints.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::collections::BTreeMap;
use tower::ServiceExt;

use aa_gateway::registry::{AgentRecord, AgentStatus};

/// Build a test `AgentRecord` with a known 16-byte ID.
fn test_agent(id_byte: u8) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: format!("test-agent-{id_byte}"),
        framework: "langgraph".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: vec!["read_file".to_string(), "write_file".to_string()],
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

/// Convert a single-byte ID to the 32-char hex string the API expects.
fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

#[tokio::test]
async fn list_agents_returns_200_empty() {
    let app = common::test_app();

    let response = app
        .oneshot(Request::builder().uri("/api/v1/agents").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_agents_returns_registered_agents() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xAA)).unwrap();
    state.agent_registry.register(test_agent(0xBB)).unwrap();

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(Request::builder().uri("/api/v1/agents").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 2);

    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    // Each agent should have expected fields
    for item in items {
        assert!(item["id"].as_str().is_some());
        assert!(item["name"].as_str().is_some());
        assert_eq!(item["framework"], "langgraph");
        assert_eq!(item["status"], "Active");
    }
}

#[tokio::test]
async fn get_agent_returns_200_for_registered_agent() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xAA)).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xAA);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["id"], id);
    assert_eq!(json["name"], "test-agent-170");
    assert_eq!(json["framework"], "langgraph");
    assert_eq!(json["version"], "0.1.0");
    assert_eq!(json["status"], "Active");
    assert_eq!(json["tool_names"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn get_agent_returns_404_for_unknown_id() {
    let app = common::test_app();
    let id = hex_id(0xFF);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_agent_returns_400_for_invalid_id() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/not-a-hex-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_agent_returns_204_for_registered_agent() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xCC)).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xCC);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_agent_returns_404_for_unknown_id() {
    let app = common::test_app();
    let id = hex_id(0xFF);

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_agent_returns_400_for_invalid_id() {
    let app = common::test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/agents/bad-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_agents_pagination_works() {
    let state = common::test_state();
    for i in 0u8..5 {
        state.agent_registry.register(test_agent(i)).unwrap();
    }

    let app = aa_api::server::build_app(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents?page=1&per_page=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["total"], 5);
    assert_eq!(json["page"], 1);
    assert_eq!(json["per_page"], 2);
    assert_eq!(json["items"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn get_agent_response_includes_new_fields() {
    let state = common::test_state();
    let mut agent = test_agent(0xDD);
    agent.pid = Some(9876);
    agent.session_count = 7;
    agent.last_event = Some(chrono::Utc::now());
    agent.policy_violations_count = 2;
    state.agent_registry.register(agent).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xDD);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["pid"], 9876);
    assert_eq!(json["session_count"], 7);
    assert!(json["last_event"].as_str().is_some());
    assert_eq!(json["policy_violations_count"], 2);
}

#[tokio::test]
async fn get_agent_response_null_optional_fields() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xEE)).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xEE);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["pid"].is_null());
    assert_eq!(json["session_count"], 0);
    assert!(json["last_event"].is_null());
    assert_eq!(json["policy_violations_count"], 0);
    assert!(json["active_sessions"].as_array().unwrap().is_empty());
    assert!(json["recent_events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_agent_response_includes_active_sessions_and_recent_events() {
    use aa_gateway::registry::{ActiveSession, RecentEvent};

    let state = common::test_state();
    let mut agent = test_agent(0xCC);
    agent.active_sessions = vec![ActiveSession {
        session_id: "sess-001".into(),
        started_at: chrono::Utc::now(),
        status: "running".into(),
    }];
    agent.recent_events.push_back(RecentEvent {
        event_type: "violation".into(),
        summary: "blocked tool call".into(),
        timestamp: chrono::Utc::now(),
    });
    state.agent_registry.register(agent).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xCC);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let sessions = json["active_sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["session_id"], "sess-001");
    assert_eq!(sessions[0]["status"], "running");
    assert!(sessions[0]["started_at"].as_str().is_some());

    let events = json["recent_events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event_type"], "violation");
    assert_eq!(events[0]["summary"], "blocked tool call");
    assert!(events[0]["timestamp"].as_str().is_some());
}

#[tokio::test]
async fn suspend_agent_returns_200() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xCC)).unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xCC);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agents/{id}/suspend"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"anomaly spike"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["agent_id"], id);
    assert_eq!(json["previous_status"], "Active");
    assert_eq!(json["new_status"], "Suspended(Manual)");
}

#[tokio::test]
async fn suspend_agent_returns_404_for_unknown_id() {
    let app = common::test_app();
    let id = hex_id(0xFF);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agents/{id}/suspend"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"reason":"test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn resume_agent_returns_200() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0xDD)).unwrap();
    // Suspend first so we can resume
    state
        .agent_registry
        .suspend_agent(&[0xDD; 16], aa_gateway::registry::SuspendReason::Manual)
        .unwrap();

    let app = aa_api::server::build_app(state);
    let id = hex_id(0xDD);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agents/{id}/resume"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["agent_id"], id);
    assert_eq!(json["previous_status"], "Suspended(Manual)");
    assert_eq!(json["new_status"], "Active");
}

#[tokio::test]
async fn resume_agent_returns_404_for_unknown_id() {
    let app = common::test_app();
    let id = hex_id(0xFF);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/agents/{id}/resume"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Additional coverage tests (AAASM-3805) ────────────────────────────────────

/// A valid hex string whose byte length ≠ 16 triggers the "wrong length" error
/// branch in `parse_agent_id` (lines 69–72 of agents.rs).
#[tokio::test]
async fn get_agent_with_short_hex_id_returns_400() {
    let app = common::test_app();
    // "aabb" is valid hex but decodes to 2 bytes, not 16.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents/aabb")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("32 hex characters"),
        "detail should mention 32-char requirement"
    );
}

/// An agent registered with non-empty `recent_traces` must include those traces
/// in the GET /agents/{id} response (tests lines 99–106 of agents.rs).
#[tokio::test]
async fn get_agent_includes_recent_traces_in_response() {
    let state = common::test_state();
    let mut rec = test_agent(0x77);
    rec.recent_traces = vec![aa_gateway::registry::store::RecentTrace {
        session_id: "test-session-abc".to_string(),
        timestamp: chrono::Utc::now(),
    }];
    state.agent_registry.register(rec).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}", hex_id(0x77)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let traces = json["recent_traces"].as_array().unwrap();
    assert_eq!(traces.len(), 1);
    assert_eq!(traces[0]["session_id"], "test-session-abc");
    assert!(traces[0]["timestamp"].is_string());
}

/// A registered agent's effective-permissions endpoint returns the merged
/// allow/deny sets plus per-scope provenance (covers the happy path of
/// get_agent_capabilities).
#[tokio::test]
async fn get_agent_capabilities_returns_200_for_registered_agent() {
    let state = common::test_state();
    state.agent_registry.register(test_agent(0x42)).unwrap();

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/capabilities", hex_id(0x42)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["allow"].is_array());
    assert!(json["deny"].is_array());
    assert!(json["sources"].is_array());
}

#[tokio::test]
async fn get_agent_capabilities_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/capabilities", hex_id(0x99)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// Subtree-burn over an agent with recorded spend (self) and a child with
/// recorded spend emits a dense per-day point series with per-child rows.
#[tokio::test]
async fn get_agent_subtree_burn_includes_self_and_child_spend() {
    use rust_decimal::Decimal;

    let state = common::test_state();

    // Parent agent declares one child; both are registered.
    let mut parent = test_agent(0x10);
    let child_bytes = [0x20u8; 16];
    parent.children = vec![child_bytes];
    state.agent_registry.register(parent).unwrap();

    let mut child = test_agent(0x20);
    child.parent_agent_id = Some(hex_id(0x10));
    state.agent_registry.register(child).unwrap();

    // Record spend so both the "(self)" and child rows are emitted.
    let parent_id = aa_core::identity::AgentId::from_bytes([0x10u8; 16]);
    let child_id = aa_core::identity::AgentId::from_bytes(child_bytes);
    state
        .budget_tracker
        .record_raw_spend(parent_id, None, None, Decimal::new(150, 2));
    state
        .budget_tracker
        .record_raw_spend(child_id, None, None, Decimal::new(75, 2));

    let app = aa_api::server::build_app(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/agents/{}/subtree-burn?period=7d", hex_id(0x10)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let points = json["points"].as_array().unwrap();
    assert!(!points.is_empty());
    // The most recent day should carry per-child rows including the "(self)" row.
    let last = points.last().unwrap();
    let per_child = last["per_child"].as_array().unwrap();
    let names: Vec<&str> = per_child
        .iter()
        .map(|c| c["child_name"].as_str().unwrap_or_default())
        .collect();
    assert!(names.contains(&"(self)"), "self row must be present; got {names:?}");
}
