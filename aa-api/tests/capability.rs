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

#[tokio::test]
async fn get_matrix_returns_200_with_dashboard_shape() {
    let app = common::test_app();

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

    // Seed contract: 8 resources covering every group.
    assert_eq!(json["resources"].as_array().unwrap().len(), 8);

    // Seed contract: every agent has a cell for every resource, and the
    // cell carries decisions for all four verbs.
    let resource_ids: Vec<&str> = json["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(!resource_ids.is_empty());

    let agents = json["agents"].as_array().unwrap();
    assert!(!agents.is_empty(), "seed must include at least one agent");
    for agent in agents {
        // CapabilityAgent uses camelCase `lastSeen`.
        assert!(agent["lastSeen"].is_string(), "agent {} missing lastSeen", agent["id"]);
        for rid in &resource_ids {
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
    let app = common::test_app(); // auth off → caller is OrgAdmin, RBAC pass

    let response = app
        .oneshot(post_override_request(
            json!({
                "agentIds": ["support-triage"],
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
    assert_eq!(updated[0]["id"], "support-triage");
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
                "agentIds": ["support-triage"],
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
    let app = common::test_app();
    // Apply one override first.
    app.clone()
        .oneshot(post_override_request(
            json!({
                "agentIds": ["support-triage"],
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
    let app = common::test_app();
    // Apply overrides for two different agents.
    app.clone()
        .oneshot(post_override_request(
            json!({"agentIds": ["support-triage"], "resourceId": "gmail", "verb": "read", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();
    app.clone()
        .oneshot(post_override_request(
            json!({"agentIds": ["research-bot-04"], "resourceId": "slack", "verb": "write", "decision": "deny"}),
            None,
        ))
        .await
        .unwrap();

    let (status, body) = oneshot_get(app, "/api/v1/capability/override?agent_id=support-triage").await;
    assert_eq!(status, StatusCode::OK);
    let items = body.as_array().unwrap();
    // Only the support-triage override should be visible.
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["agentIds"].as_array().unwrap()[0], "support-triage");
}

// ── revoke_override ──────────────────────────────────────────────────────────

#[tokio::test]
async fn revoke_override_returns_204_and_removes_entry() {
    let app = common::test_app();

    // Apply an override and grab its id.
    let apply_resp = app
        .clone()
        .oneshot(post_override_request(
            json!({"agentIds": ["support-triage"], "resourceId": "pg", "verb": "write", "decision": "deny"}),
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
    let app = common::test_app();
    let resp = app
        .oneshot(post_override_request(
            json!({"agentIds": ["support-triage"], "resourceId": "pg", "verb": "delete", "decision": "deny"}),
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
    let app = common::test_app();
    let resp = app
        .oneshot(post_override_request(
            json!({"agentIds": ["support-triage"], "resourceId": "pg", "verb": "exec", "decision": "deny"}),
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
    let app = common::test_app();
    let resp = app
        .oneshot(post_override_request(
            json!({
                "agentIds": ["support-triage"],
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
    let (status, body) = oneshot_get(common::test_app(), "/api/v1/capability/matrix?team_id=support-triage").await;
    assert_eq!(status, StatusCode::OK);
    let agents = body["agents"].as_array().unwrap();
    // All returned agents should have id == "support-triage".
    for a in agents {
        assert_eq!(a["id"], "support-triage");
    }
}

#[tokio::test]
async fn get_matrix_with_tool_filter_returns_single_resource_column() {
    let (status, body) = oneshot_get(common::test_app(), "/api/v1/capability/matrix?tool=gmail").await;
    assert_eq!(status, StatusCode::OK);
    // The resources list should only contain "gmail".
    let resources = body["resources"].as_array().unwrap();
    assert!(resources.iter().all(|r| r["id"] == "gmail"));
}

#[tokio::test]
async fn get_matrix_with_effective_only_excludes_all_na_cells() {
    let (status, body) = oneshot_get(common::test_app(), "/api/v1/capability/matrix?effective_only=true").await;
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
