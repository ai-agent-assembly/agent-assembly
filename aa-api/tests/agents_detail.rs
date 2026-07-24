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

// ── decisions (recent per-agent decision stream, AAASM-5058) ─────────────────

/// Seed the app's audit reader with the given JSONL-encoded entries and return
/// the wired app (keeps the temp dir alive for the test's duration).
fn app_with_audit(
    state: aa_api::state::AppState,
    entries: &[aa_core::AuditEntry],
) -> (axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut contents = String::new();
    for e in entries {
        contents.push_str(&serde_json::to_string(e).unwrap());
        contents.push('\n');
    }
    std::fs::write(dir.path().join("audit.jsonl"), contents).unwrap();
    let mut state = state;
    state.audit_reader = std::sync::Arc::new(aa_gateway::AuditReader::new(dir.path().to_path_buf()));
    (aa_api::server::build_app(state), dir)
}

/// Build a decision audit entry for `id_byte`'s agent at sequence `seq`.
fn decision_entry(id_byte: u8, seq: u64, ts_ns: u64, payload: &str) -> aa_core::AuditEntry {
    aa_core::AuditEntry::new(
        seq,
        ts_ns,
        aa_core::AuditEventType::ToolCallIntercepted,
        aa_core::identity::AgentId::from_bytes([id_byte; 16]),
        aa_core::identity::SessionId::from_bytes([0xEE; 16]),
        payload.to_string(),
        [0u8; 32],
    )
}

#[tokio::test]
async fn get_decisions_returns_400_for_invalid_id() {
    let app = common::test_app();
    let (status, _) = get(app, "/api/v1/agents/not-hex/decisions").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_decisions_returns_404_for_unknown_agent() {
    let app = common::test_app();
    let (status, _) = get(app, &format!("/api/v1/agents/{}/decisions", hex_id(0x96))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_decisions_returns_empty_for_agent_with_no_audit() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x55, AgentStatus::Active))
        .unwrap();
    let app = aa_api::server::build_app(state);

    let (status, body) = get(app, &format!("/api/v1/agents/{}/decisions", hex_id(0x55))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decisions"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn get_decisions_projects_rows_newest_first_and_skips_non_decisions() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x56, AgentStatus::Active))
        .unwrap();

    let entries = [
        decision_entry(
            0x56,
            0,
            1_700_000_000_000_000_000,
            r#"{"action_type":"TOOL_CALL","decision":1,"detail":{"kind":"tool_call","tool_name":"pg.users"}}"#,
        ),
        // Newer, and a deny with a matched policy under `detail`.
        decision_entry(
            0x56,
            1,
            1_700_000_100_000_000_000,
            r#"{"action_type":"TOOL_CALL","decision":2,"detail":{"kind":"policy_violation","policy_rule":"P-066","blocked_action":"gmail.send"}}"#,
        ),
        // No `decision` → not a governance decision, must be skipped.
        decision_entry(
            0x56,
            2,
            1_700_000_050_000_000_000,
            r#"{"action_type":"AGENT_SPAWN","detail":{"kind":"spawn"}}"#,
        ),
    ];
    let (app, _dir) = app_with_audit(state, &entries);

    let (status, body) = get(app, &format!("/api/v1/agents/{}/decisions", hex_id(0x56))).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["decisions"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "the non-decision spawn entry is filtered out");

    // Newest first: the deny (ts +100s) precedes the allow.
    assert_eq!(rows[0]["decision"], 2);
    assert_eq!(rows[0]["decisionLabel"], "deny");
    assert_eq!(rows[0]["matchedPolicy"], "P-066");
    assert_eq!(rows[0]["resource"], "gmail.send");
    assert_eq!(rows[0]["verb"], "TOOL_CALL");
    // No latency source exists — the column is surfaced null, never fabricated.
    assert!(rows[0]["latencyMs"].is_null());

    assert_eq!(rows[1]["decision"], 1);
    assert_eq!(rows[1]["decisionLabel"], "allow");
    assert_eq!(rows[1]["resource"], "pg.users");
    assert!(rows[1]["matchedPolicy"].is_null());
}

#[tokio::test]
async fn get_decisions_honours_limit() {
    let state = common::test_state();
    state
        .agent_registry
        .register(test_agent(0x57, AgentStatus::Active))
        .unwrap();

    let entries: Vec<aa_core::AuditEntry> = (0..5)
        .map(|i| {
            decision_entry(
                0x57,
                i,
                1_700_000_000_000_000_000 + i * 1_000_000_000,
                r#"{"action_type":"TOOL_CALL","decision":1,"detail":{"kind":"tool_call","tool_name":"pg.users"}}"#,
            )
        })
        .collect();
    let (app, _dir) = app_with_audit(state, &entries);

    let (status, body) = get(app, &format!("/api/v1/agents/{}/decisions?limit=2", hex_id(0x57))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["decisions"].as_array().unwrap().len(),
        2,
        "limit caps the row count"
    );
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
