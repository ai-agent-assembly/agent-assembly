//! Integration tests for the dashboard Capability Matrix endpoint (AAASM-1366).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use aa_api::auth::scope::Scope;

/// Build a POST /capability/override request with the given body and an
/// optional Bearer token.
fn post_override_request(body: serde_json::Value, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/capability/override")
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

/// Stable ids of the agents these tests register and target.
const TARGET_ID: &str = "01010101010101010101010101010101";
const OTHER_ID: &str = "02020202020202020202020202020202";

/// A registered agent for the capability projection to return. The matrix is
/// projected from the registry now, so a test that overrides a cell has to
/// register the agent whose cell it is overriding.
fn registered_agent(id_byte: u8, name: &str) -> aa_gateway::registry::AgentRecord {
    aa_gateway::registry::AgentRecord {
        agent_id: [id_byte; 16],
        name: name.to_string(),
        framework: "crewai".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: vec!["pg".to_string()],
        public_key: "pk".to_string(),
        credential_token: "tok".to_string(),
        metadata: std::collections::BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: aa_gateway::registry::AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: Vec::new(),
        recent_events: std::collections::VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some("cx-tools".to_string()),
        org_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some([id_byte; 16]),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
    }
}

/// App with the target agent registered, so the matrix projects one row.
fn app_with_target() -> axum::Router {
    common::test_app_with_agents(vec![registered_agent(0x01, "support-triage")])
}

/// App with two registered agents, for tests that need to tell rows apart.
fn app_with_two_agents() -> axum::Router {
    common::test_app_with_agents(vec![
        registered_agent(0x01, "support-triage"),
        registered_agent(0x02, "research-bot-04"),
    ])
}

// ── AAASM-3846 — function-level authz on the read + revoke gates ─────────────

/// `GET /capability/matrix` previously served sensitive policy state with no
/// auth; it must now reject an unauthenticated caller.
#[tokio::test]
async fn get_matrix_unauthenticated_is_401() {
    let app = common::test_app_with_auth(&[], 1000);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/matrix")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `GET /capability/override` previously disclosed the override log with no
/// auth; it must now reject an unauthenticated caller.
#[tokio::test]
async fn list_overrides_unauthenticated_is_401() {
    let app = common::test_app_with_auth(&[], 1000);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/override")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// `DELETE /capability/override/{id}` mutates capability state, so a viewer
/// (read-only) caller must be denied with 403 — matching `apply_override`.
#[tokio::test]
async fn revoke_override_rejects_viewer_scope_with_403() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/capability/override/some-id")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a read-only caller must not revoke a capability override"
    );
}

/// `GET /capability/matrix` is global control-plane state with no per-team
/// partition (AAASM-4841), so a mere read-scoped caller must be refused with
/// 403 — mirroring the admin posture of `list_overrides` (AAASM-4829).
#[tokio::test]
async fn get_matrix_rejects_viewer_scope_with_403() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/matrix")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a read-only caller must not read the capability matrix"
    );
}

/// An admin-scoped caller may read the capability matrix.
#[tokio::test]
async fn get_matrix_admin_scope_is_allowed() {
    let (token, entry) = common::generate_test_api_key("admin-key", vec![Scope::Admin]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/matrix")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "an admin caller may read the matrix");
}

#[tokio::test]
async fn get_matrix_returns_200_with_dashboard_shape() {
    let app = app_with_target();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/capability/matrix")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Top-level shape mirrors dashboard's `CapabilityMatrix` interface.
    assert!(json["resources"].is_array(), "resources must be an array");
    assert!(json["agents"].is_array(), "agents must be an array");
    assert!(json["policies"].is_array(), "policies must be an array");
    assert!(
        json["sampleCalls"].is_array(),
        "sampleCalls must be camelCase, not sample_calls"
    );
    assert!(
        json.get("sample_calls").is_none(),
        "snake_case sample_calls must not appear"
    );

    // The three fixed capability families are always columns.
    let resource_ids: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    for expected in ["filesystem", "terminal", "network_outbound"] {
        assert!(resource_ids.contains(&expected), "{expected} must be a column");
    }

    // Every projected agent carries a cell per system family, each with all
    // four verb decisions.
    let agents = json["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1, "the one registered agent is projected");
    let resource_ids = ["filesystem", "terminal", "network_outbound"];
    for agent in agents {
        // CapabilityAgent uses camelCase `lastSeen`.
        assert!(agent["lastSeen"].is_string(), "agent {} missing lastSeen", agent["id"]);
        for rid in resource_ids {
            let cell = &agent["caps"][rid];
            assert!(
                cell.is_object(),
                "agent {} missing cell for resource {rid}",
                agent["id"]
            );
            for verb in ["read", "write", "delete", "exec"] {
                assert!(
                    cell[verb].is_string(),
                    "agent {} resource {rid} missing decision for {verb}",
                    agent["id"]
                );
            }
        }
    }
}

#[tokio::test]
async fn apply_override_returns_only_updated_rows() {
    let app = app_with_target(); // auth off → caller is OrgAdmin, RBAC pass

    let response = app
        .oneshot(post_override_request(
            json!({
                "agentIds": [TARGET_ID],
                "resourceId": "pg",
                "verb": "write",
                "decision": "deny"
            }),
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let updated = json["updated"].as_array().unwrap();
    assert_eq!(updated.len(), 1, "only one row should change");
    assert_eq!(updated[0]["id"], TARGET_ID);
    assert_eq!(
        updated[0]["caps"]["pg"]["write"], "deny",
        "the targeted cell must reflect the new decision"
    );
}

#[tokio::test]
async fn apply_override_rejects_viewer_scope_with_403() {
    let (token, entry) = common::generate_test_api_key("viewer-key", vec![Scope::Read]);
    let app = common::test_app_with_auth(&[entry], 1000);

    let response = app
        .oneshot(post_override_request(
            json!({
                "agentIds": [TARGET_ID],
                "resourceId": "pg",
                "verb": "write",
                "decision": "deny"
            }),
            Some(&token),
        ))
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Viewer (Read-only scope) must be denied"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail = json["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("policy mutation denied"),
        "ProblemDetail body should describe the deny; got: {detail}"
    );
}

#[tokio::test]
async fn apply_override_rejects_unknown_agent_with_400() {
    let app = common::test_app(); // auth off → RBAC pass; failure must be from validation

    let response = app
        .oneshot(post_override_request(
            json!({
                "agentIds": ["does-not-exist"],
                "resourceId": "pg",
                "verb": "write",
                "decision": "deny"
            }),
            None,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let detail = json["detail"].as_str().unwrap_or("");
    assert!(
        detail.contains("does-not-exist"),
        "ProblemDetail should name the offending agent id; got: {detail}"
    );
}

// ── Additional coverage tests (AAASM-3805) ────────────────────────────────────

async fn oneshot_get(app: axum::Router, uri: &str) -> (axum::http::StatusCode, serde_json::Value) {
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

async fn oneshot_delete(app: axum::Router, uri: &str) -> axum::http::StatusCode {
    app.oneshot(
        axum::http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

// ── list_overrides ──────────────────────────────────────────────────────────

#[tokio::test]
async fn list_overrides_returns_200_with_empty_list_initially() {
    let app = common::test_app();
    let (status, body) = oneshot_get(app, "/api/v1/capability/override").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_overrides_reflects_applied_override() {
    let app = app_with_target();
    // Apply one override first.
    app.clone()
        .oneshot(post_override_request(
            json!({
                "agentIds": [TARGET_ID],
                "resourceId": "pg",
                "verb": "read",
                "decision": "deny"
            }),
            None,
        ))
        .await
        .unwrap();

    let (status, body) = oneshot_get(app, "/api/v1/capability/override").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["resourceId"], "pg");
    assert_eq!(items[0]["verb"], "read");
}

#[tokio::test]
async fn list_overrides_with_agent_id_filter_returns_matching_entries() {
    let app = app_with_two_agents();
    // Apply overrides for two different agents.
    app.clone()
        .oneshot(post_override_request(
            json!({"agentIds": [TARGET_ID], "resourceId": "pg", "verb": "read", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(post_override_request(
            json!({"agentIds": [OTHER_ID], "resourceId": "pg", "verb": "write", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();

    let (status, body) = oneshot_get(app, &format!("/api/v1/capability/override?agent_id={TARGET_ID}")).await;
    assert_eq!(status, StatusCode::OK);
    let items = body.as_array().unwrap();
    // Only the override naming the target agent should be visible.
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["agentIds"].as_array().unwrap()[0], TARGET_ID);
}

// ── revoke_override ──────────────────────────────────────────────────────────

#[tokio::test]
async fn revoke_override_returns_204_and_removes_entry() {
    let app = app_with_target();

    // Apply an override and grab its id.
    let apply_resp = app
        .clone()
        .oneshot(post_override_request(
            json!({"agentIds": [TARGET_ID], "resourceId": "pg", "verb": "write", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(apply_resp.into_body(), usize::MAX).await.unwrap();
    let apply_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let override_id = apply_json["overrideId"].as_str().unwrap().to_string();

    // Delete it.
    let status = oneshot_delete(app.clone(), &format!("/api/v1/capability/override/{override_id}")).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn revoke_override_returns_404_for_unknown_id() {
    let app = common::test_app();
    let status = oneshot_delete(app, "/api/v1/capability/override/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── apply_override with different verbs ─────────────────────────────────────

#[tokio::test]
async fn apply_override_with_verb_delete() {
    let app = app_with_target();
    let resp = app
        .oneshot(post_override_request(
            json!({"agentIds": [TARGET_ID], "resourceId": "pg", "verb": "delete", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["updated"][0]["caps"]["pg"]["delete"], "deny");
}

#[tokio::test]
async fn apply_override_with_verb_exec() {
    let app = app_with_target();
    let resp = app
        .oneshot(post_override_request(
            json!({"agentIds": [TARGET_ID], "resourceId": "pg", "verb": "exec", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["updated"][0]["caps"]["pg"]["exec"], "deny");
}

#[tokio::test]
async fn apply_override_with_ttl_returns_201() {
    let app = app_with_target();
    let resp = app
        .oneshot(post_override_request(
            json!({
                "agentIds": [TARGET_ID],
                "resourceId": "pg",
                "verb": "write",
                "decision": "deny",
                "ttlSeconds": 3600
            }),
            None,
        ))
        .await
        .unwrap();
    // TTL present → 201 Created (not 200 OK).
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ── get_matrix filters ───────────────────────────────────────────────────────

#[tokio::test]
async fn get_matrix_with_team_id_filter_returns_matching_agent_only() {
    let (status, body) = oneshot_get(
        app_with_target(),
        &format!("/api/v1/capability/matrix?team_id={TARGET_ID}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let agents = body["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["id"], TARGET_ID);
}

#[tokio::test]
async fn get_matrix_with_tool_filter_returns_single_resource_column() {
    let (status, body) = oneshot_get(app_with_target(), "/api/v1/capability/matrix?tool=filesystem").await;
    assert_eq!(status, StatusCode::OK);
    let resources = body["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], "filesystem");
}

#[tokio::test]
async fn get_matrix_with_effective_only_excludes_all_na_cells() {
    let (status, body) = oneshot_get(app_with_target(), "/api/v1/capability/matrix?effective_only=true").await;
    assert_eq!(status, StatusCode::OK);
    // Every remaining cell must have at least one non-"na" decision.
    let agents = body["agents"].as_array().unwrap();
    for agent in agents {
        let caps = agent["caps"].as_object().unwrap();
        for (_rid, cell) in caps {
            let all_na = ["read", "write", "delete", "exec"].iter().all(|v| cell[v] == "na");
            assert!(
                !all_na,
                "effective_only=true must remove all-na cells; found one in agent {}",
                agent["id"]
            );
        }
    }
}

// ── TTL auto-expiry (covers the spawned deactivation task) ───────────────────

#[tokio::test]
async fn override_with_short_ttl_deactivates_itself() {
    use aa_api::models::capability::{Decision, Verb};
    use aa_api::routes::capability::CapabilityStore;
    use std::sync::Arc;

    let store = CapabilityStore::new();
    let id = Arc::clone(&store)
        .record_override(&aa_api::models::capability::CapabilityOverrideRequest {
            agent_ids: vec!["agent-a".to_string()],
            resource_id: "filesystem".to_string(),
            verb: Verb::Write,
            decision: Decision::Deny,
            ttl_seconds: Some(1),
        })
        .await;

    let during = store.list_overrides(None).await;
    assert_eq!(during.len(), 1);
    assert!(during[0].active, "the override is live before its TTL elapses");
    assert_eq!(during[0].id, id);

    // After the TTL the spawned task deactivates the entry, so it stops being
    // replayed over the projection and the base decision resurfaces.
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;
    let after = store.list_overrides(None).await;
    assert!(
        !after[0].active,
        "TTL expiry must deactivate the override so the projected value wins again"
    );
}
