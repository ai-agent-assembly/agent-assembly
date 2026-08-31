//! Integration tests for the actor-aware governance-mutation audit path
//! (AAASM-5287 / ADR 0021 prerequisite 1/3).
//!
//! These assert the security-critical contract: when an operator performs an
//! enforcement-/authorization-relevant mutation (here, agent suspend), the
//! emitted audit record's actor and tenant come from the *authenticated
//! identity* and can NOT be spoofed via the request body, the reason is
//! required, and the before/after governance values are recorded.

mod common;

use std::collections::{BTreeMap, VecDeque};

use aa_core::audit::{AuditEntry, AuditEventType};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::mpsc;
use tower::ServiceExt;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use aa_api::state::AppState;
use aa_gateway::registry::{AgentRecord, AgentStatus};

const VERIFIED_KEY_ID: &str = "operator-verified";
const VERIFIED_TEAM: &str = "team-alpha";
const VERIFIED_ORG: &str = "org-alpha";

fn hex_id(id_byte: u8) -> String {
    format!("{id_byte:02x}").repeat(16)
}

fn json_bearer(method: &str, uri: &str, token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A root agent record tagged with a team + org tenant, so a matching
/// tenant-scoped caller passes `authorize_agent_access`.
fn agent_with_tenant(id_byte: u8, team: &str, org: &str) -> AgentRecord {
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
        enforcement_mode_expires_at: None,
        org_id: Some(org.to_string()),
    }
}

/// Build an auth-enabled state with the audit pipeline wired to a channel the
/// test drains, plus one agent owned by the verified tenant registered under
/// `id_byte`. Returns the state and the receiving end of the audit channel.
fn state_with_audit_channel(id_byte: u8) -> (AppState, mpsc::Receiver<AuditEntry>) {
    let mut state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let (tx, rx) = mpsc::channel::<AuditEntry>(16);
    state.set_audit_chain_from_sender(tx);
    state
        .agent_registry
        .register(agent_with_tenant(id_byte, VERIFIED_TEAM, VERIFIED_ORG))
        .unwrap();
    (state, rx)
}

/// A JWT for the verified operator: Write scope, confined to the verified
/// (team, org). This is the authenticated identity the audit record must
/// attribute the action to.
fn verified_operator_token() -> String {
    common::generate_test_jwt_for_tenant(
        VERIFIED_KEY_ID,
        &[Scope::Write],
        Some(VERIFIED_TEAM),
        Some(VERIFIED_ORG),
    )
}

fn payload_of(entry: &AuditEntry) -> serde_json::Value {
    serde_json::from_str(entry.payload()).expect("governance-mutation payload is JSON")
}

// ── The headline security test ────────────────────────────────────────────
//
// A caller stuffs actor/org/team into the request body. The audit record must
// ignore all of it and record the values from the authenticated identity.

#[tokio::test]
async fn actor_and_tenant_are_taken_from_identity_not_the_request_body() {
    let (state, mut rx) = state_with_audit_channel(0xC1);
    let app = aa_api::build_app(state);
    let token = verified_operator_token();

    // The body tries to spoof actor + tenant. SuspendRequest only reads
    // `reason`; the spoofed fields are ignored, but even if they were parsed
    // the handler sources actor/tenant solely from the authenticated caller.
    let spoof_body = r#"{
        "reason": "incident-4821 mitigation",
        "actor": "attacker-key",
        "org": "evil-org",
        "team": "evil-team",
        "key_id": "attacker-key"
    }"#;
    let uri = format!("/api/v1/agents/{}/suspend", hex_id(0xC1));
    let response = app
        .oneshot(json_bearer("POST", &uri, &token, spoof_body))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the suspend itself must still succeed"
    );

    let entry = rx
        .try_recv()
        .expect("a governance-mutation audit entry must have been emitted");
    assert_eq!(entry.event_type(), AuditEventType::GovernanceMutation);

    let payload = payload_of(&entry);
    // Actor is the verified JWT subject, NOT the body-supplied "attacker-key".
    assert_eq!(
        payload["actor"], VERIFIED_KEY_ID,
        "actor must be the authenticated identity, never the request body"
    );
    assert_ne!(payload["actor"], "attacker-key");
    // Tenant is the verified caller tenant, NOT the body-supplied "evil-*".
    assert_eq!(payload["org"], VERIFIED_ORG, "org must be the verified tenant org");
    assert_eq!(payload["team"], VERIFIED_TEAM, "team must be the verified tenant team");
    assert_ne!(payload["org"], "evil-org");
    assert_ne!(payload["team"], "evil-team");

    // The verified tenant also flows into the entry's lineage, so audit-log
    // tenant scoping applies to operator actions too.
    assert_eq!(entry.org_id(), Some(VERIFIED_ORG));
    assert_eq!(entry.team_id(), Some(VERIFIED_TEAM));
}

// ── Reason is required ──────────────────────────────────────────────────────

#[tokio::test]
async fn suspend_with_empty_reason_is_422_and_emits_no_audit() {
    let (state, mut rx) = state_with_audit_channel(0xC2);
    let app = aa_api::build_app(state);
    let token = verified_operator_token();

    let uri = format!("/api/v1/agents/{}/suspend", hex_id(0xC2));
    let response = app
        .oneshot(json_bearer("POST", &uri, &token, r#"{"reason":"   "}"#))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a blank reason must be rejected before any mutation"
    );
    assert!(
        rx.try_recv().is_err(),
        "no governance-mutation audit entry may be emitted when the reason is rejected"
    );
}

// ── Happy path records reason + before/after ────────────────────────────────

#[tokio::test]
async fn suspend_records_reason_and_before_after_status() {
    let (state, mut rx) = state_with_audit_channel(0xC3);
    let app = aa_api::build_app(state);
    let token = verified_operator_token();

    let uri = format!("/api/v1/agents/{}/suspend", hex_id(0xC3));
    let response = app
        .oneshot(json_bearer(
            "POST",
            &uri,
            &token,
            r#"{"reason":"scheduled maintenance"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let entry = rx
        .try_recv()
        .expect("a governance-mutation audit entry must have been emitted");
    let payload = payload_of(&entry);
    assert_eq!(payload["action"], "suspend");
    assert_eq!(payload["reason"], "scheduled maintenance");
    assert_eq!(payload["before"], "Active");
    assert_eq!(payload["after"], "Suspended(Manual)");
    // The mutated agent, not the operator, is the entry's agent_id.
    assert_eq!(
        entry.agent_id(),
        aa_core::AgentId::from_bytes([0xC3; 16]),
        "the audit entry identifies the mutated agent"
    );
    // Defence in depth: no credential-shaped bytes in the payload.
    assert!(!entry.payload().contains("Bearer"));
    assert!(!entry.payload().contains("aa_"));
}
