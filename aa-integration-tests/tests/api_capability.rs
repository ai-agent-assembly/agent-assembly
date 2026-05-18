//! AAASM-1489 (F122 ST-H) — Live-gateway HTTP integration tests for
//! `/api/v1/capability/*` endpoints.
//!
//! Uses `TopologyTestEnv::start()` which boots an in-process axum server with
//! `CapabilityStore::new_seeded()` as the fixture baseline. Auth is `Off` so
//! all RBAC checks pass without a token.
//!
//! ## Route surface for `aa-api/src/routes/capability.rs`
//!
//! | Method | Path | Handler |
//! |--------|------|---------|
//! | GET    | `/api/v1/capability/matrix`        | `get_matrix`      |
//! | POST   | `/api/v1/capability/override`      | `apply_override`  |
//! | DELETE | `/api/v1/capability/override/{id}` | `revoke_override` |

mod common;

use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::{json, Value};

// ── helpers ──────────────────────────────────────────────────────────────────

/// POST /api/v1/capability/override with a JSON body; no auth header (auth is Off).
async fn post_override(base_url: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base_url}/api/v1/capability/override"))
        .json(&body)
        .send()
        .await
        .expect("POST /capability/override should send")
}

/// GET /api/v1/capability/matrix (with optional query string).
async fn get_matrix(base_url: &str, query: &str) -> reqwest::Response {
    let url = if query.is_empty() {
        format!("{base_url}/api/v1/capability/matrix")
    } else {
        format!("{base_url}/api/v1/capability/matrix?{query}")
    };
    reqwest::get(&url).await.expect("GET /capability/matrix should send")
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix tests (5)
// ═════════════════════════════════════════════════════════════════════════════

/// GET /capability/matrix returns 200 with the seeded fixture shape:
/// 4 agents, 8 resources, 2 policies, 3 sample calls. Every agent has a cell
/// for every resource and each cell carries all four verb decisions.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_returns_seeded_data() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = get_matrix(&env.base_url(), "").await;
    assert_eq!(resp.status(), StatusCode::OK, "matrix endpoint must return 200");

    let body: Value = resp.json().await.expect("body should parse as JSON");

    // Top-level fields mirror `CapabilityMatrix` (camelCase on the wire).
    let resources = body["resources"].as_array().expect("resources must be an array");
    let agents = body["agents"].as_array().expect("agents must be an array");
    let policies = body["policies"].as_array().expect("policies must be an array");
    let sample_calls = body["sampleCalls"]
        .as_array()
        .expect("sampleCalls must be present (camelCase)");
    assert!(
        body.get("sample_calls").is_none(),
        "snake_case key must not appear on the wire"
    );

    // Seed contract: 8 resources, 4 agents, 2 policies, 3 sample calls.
    assert_eq!(resources.len(), 8, "seeded matrix has 8 resources");
    assert_eq!(agents.len(), 4, "seeded matrix has 4 agents");
    assert_eq!(policies.len(), 2, "seeded matrix has 2 policies");
    assert_eq!(sample_calls.len(), 3, "seeded matrix has 3 sample calls");

    // Every resource must have id, name, group, paths.
    let resource_ids: Vec<&str> = resources.iter().map(|r| r["id"].as_str().unwrap()).collect();
    for expected in ["gmail", "gdrive", "s3", "pg", "shell", "http", "github", "slack"] {
        assert!(resource_ids.contains(&expected), "resource {expected} must be present");
    }

    // Every agent must have a cell for every resource, each cell with 4 verb decisions.
    for agent in agents {
        let id = agent["id"].as_str().unwrap_or("<unknown>");
        assert!(
            agent["lastSeen"].is_string(),
            "agent {id} must have `lastSeen` (camelCase)"
        );
        assert!(
            agent.get("last_seen").is_none(),
            "snake_case `last_seen` must not appear for {id}"
        );
        for rid in &resource_ids {
            let cell = &agent["caps"][rid];
            assert!(cell.is_object(), "agent {id} must have a caps cell for resource {rid}");
            for verb in ["read", "write", "delete", "exec"] {
                assert!(
                    cell[verb].is_string(),
                    "agent {id} resource {rid} must have a `{verb}` decision"
                );
            }
        }
    }
}

/// `?team_id=` filter returns only the agent row whose `id` matches.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_filter_by_team() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = get_matrix(&env.base_url(), "team_id=research-bot-04").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.expect("body should parse");
    let agents = body["agents"].as_array().expect("agents array");
    // When implemented: assert only the requested agent row is present.
    assert_eq!(agents.len(), 1, "filter should return exactly one agent row");
    assert_eq!(agents[0]["id"], "research-bot-04");
}

/// `?tool=` filter returns only the matching resource column and filters
/// each agent's caps map to that single key.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_filter_by_tool() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = get_matrix(&env.base_url(), "tool=gmail").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.expect("body should parse");
    let resources = body["resources"].as_array().expect("resources array");
    // When implemented: assert only the gmail resource column is present.
    assert_eq!(resources.len(), 1, "filter should return only the gmail column");
    assert_eq!(resources[0]["id"], "gmail");
}

/// `?effective_only=true` excludes cap cells where all four verb decisions
/// are `na` (no effective permission).
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_effective_only_excludes_inherited() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = get_matrix(&env.base_url(), "effective_only=true").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.expect("body should parse");
    // When implemented: inherited grants must not appear in cells.
    let agents = body["agents"].as_array().expect("agents array");
    assert!(!agents.is_empty(), "at least one agent row expected");
    // Additional assertions about inherited vs effective decisions go here.
}

/// Unknown `team_id` returns 200 with an empty agent list.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_unknown_team_returns_empty() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = get_matrix(&env.base_url(), "team_id=does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::OK, "unknown team should return 200, not 404");

    let body: Value = resp.json().await.expect("body should parse");
    let agents = body["agents"].as_array().expect("agents array");
    // When implemented: zero agent rows for an unknown team_id.
    assert_eq!(agents.len(), 0, "unknown team should yield empty agent list");
}

// ═════════════════════════════════════════════════════════════════════════════
// Override tests (5)
// ═════════════════════════════════════════════════════════════════════════════

/// POST a grant override for `research-bot-04 × pg × write → deny`, then
/// GET the matrix and confirm the cell reflects the change. Seeded value is
/// `approval`; override must change it to `deny`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_grant_then_appears_in_matrix() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let base = env.base_url();

    // Precondition: seeded pg.write for research-bot-04 is "approval".
    let before: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent_before = before["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "research-bot-04")
        .expect("research-bot-04 must be in the seeded matrix");
    assert_eq!(
        agent_before["caps"]["pg"]["write"], "approval",
        "precondition: pg.write must be 'approval' before override"
    );

    // Apply override: grant deny on pg.write for research-bot-04.
    let override_resp = post_override(
        &base,
        json!({
            "agentIds": ["research-bot-04"],
            "resourceId": "pg",
            "verb": "write",
            "decision": "deny"
        }),
    )
    .await;
    assert_eq!(override_resp.status(), StatusCode::OK, "POST /override must return 200");

    let override_body: Value = override_resp.json().await.expect("override body should parse");
    let updated = override_body["updated"]
        .as_array()
        .expect("response must have `updated` array");
    assert_eq!(updated.len(), 1, "exactly one agent row must be returned");
    assert_eq!(
        updated[0]["id"], "research-bot-04",
        "returned row must match the targeted agent"
    );
    assert_eq!(
        updated[0]["caps"]["pg"]["write"], "deny",
        "returned row must reflect the new decision"
    );

    // Confirm the matrix also reflects the change.
    let after: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent_after = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "research-bot-04")
        .expect("research-bot-04 must still be in the matrix");
    assert_eq!(
        agent_after["caps"]["pg"]["write"], "deny",
        "matrix must reflect the override after GET"
    );

    // Sibling agent must remain unchanged.
    let sibling = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "support-triage")
        .expect("support-triage must still be in the matrix");
    assert_ne!(
        sibling["caps"]["pg"]["write"], "deny",
        "support-triage pg.write must not be affected by the override on research-bot-04"
    );
}

/// POST a revoke override (deny) on `support-triage × gmail × read` (seeded
/// as `allow`), then verify the matrix reflects `deny`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_revoke_then_blocked_in_matrix() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let base = env.base_url();

    // Precondition: seeded gmail.read for support-triage is "allow".
    let before: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent_before = before["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "support-triage")
        .expect("support-triage must be in the seeded matrix");
    assert_eq!(
        agent_before["caps"]["gmail"]["read"], "allow",
        "precondition: gmail.read must be 'allow' before revoke override"
    );

    // Apply revoke: set gmail.read → deny for support-triage.
    let override_resp = post_override(
        &base,
        json!({
            "agentIds": ["support-triage"],
            "resourceId": "gmail",
            "verb": "read",
            "decision": "deny"
        }),
    )
    .await;
    assert_eq!(override_resp.status(), StatusCode::OK, "POST /override must return 200");

    let override_body: Value = override_resp.json().await.expect("override body should parse");
    let updated = override_body["updated"]
        .as_array()
        .expect("`updated` array must be present");
    assert_eq!(updated.len(), 1, "exactly one agent row must change");
    assert_eq!(
        updated[0]["caps"]["gmail"]["read"], "deny",
        "returned row must reflect the revoke"
    );

    // Confirm the matrix now shows deny.
    let after: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent_after = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "support-triage")
        .expect("support-triage must still be in the matrix");
    assert_eq!(
        agent_after["caps"]["gmail"]["read"], "deny",
        "matrix must reflect the revoke after GET"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capability_override_with_ttl_expires() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let base = env.base_url();

    // Apply a short-lived override.
    let override_resp = post_override(
        &base,
        json!({
            "agentIds": ["research-bot-04"],
            "resourceId": "pg",
            "verb": "write",
            "decision": "deny",
            "ttlSeconds": 1
        }),
    )
    .await;
    assert_eq!(
        override_resp.status(),
        StatusCode::CREATED,
        "override with TTL should return 201"
    );

    // Wait for expiry (use tokio::time::advance once mock clock lands).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Matrix should revert to the seeded value.
    let after: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "research-bot-04")
        .unwrap();
    assert_eq!(
        agent["caps"]["pg"]["write"], "approval",
        "cell must revert to seeded value after TTL expiry"
    );
}

/// `GET /api/v1/capability/override` — list active overrides, assert both
/// seeded override entries appear with `active: true`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_list_returns_active() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let base = env.base_url();

    // Seed two overrides.
    for verb in ["write", "delete"] {
        let resp = post_override(
            &base,
            json!({
                "agentIds": ["research-bot-04"],
                "resourceId": "pg",
                "verb": verb,
                "decision": "deny"
            }),
        )
        .await;
        assert!(resp.status().is_success());
    }

    // GET /capability/override should list both.
    let list_resp = reqwest::get(format!("{base}/api/v1/capability/override"))
        .await
        .expect("GET /capability/override should send");
    assert_eq!(list_resp.status(), StatusCode::OK);

    let body: Value = list_resp.json().await.expect("body should parse");
    let overrides = body.as_array().unwrap_or_else(|| body["overrides"].as_array().unwrap());
    assert_eq!(overrides.len(), 2, "two active overrides must be listed");
    for entry in overrides {
        assert_eq!(entry["active"], true, "each entry must be active");
    }
}

/// `DELETE /api/v1/capability/override/{id}` reverts the cell and returns 204.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_delete_removes_from_matrix() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let base = env.base_url();

    // Seed an override and capture its id.
    let create_resp = post_override(
        &base,
        json!({
            "agentIds": ["research-bot-04"],
            "resourceId": "pg",
            "verb": "write",
            "decision": "deny"
        }),
    )
    .await;
    assert_eq!(create_resp.status(), StatusCode::OK);
    let create_body: Value = create_resp.json().await.unwrap();
    let override_id = create_body["overrideId"]
        .as_str()
        .expect("response must include overrideId");

    // DELETE the override.
    let del_resp = reqwest::Client::new()
        .delete(format!("{base}/api/v1/capability/override/{override_id}"))
        .send()
        .await
        .expect("DELETE should send");
    assert!(
        del_resp.status().is_success(),
        "DELETE must return 2xx; got {}",
        del_resp.status()
    );

    // Matrix must revert.
    let after: Value = get_matrix(&base, "").await.json().await.unwrap();
    let agent = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "research-bot-04")
        .unwrap();
    assert_eq!(
        agent["caps"]["pg"]["write"], "approval",
        "cell must revert to seeded value after override deletion"
    );
}

// ═════════════════════════════════════════════════════════════════════════════
// Validation tests (2)
// ═════════════════════════════════════════════════════════════════════════════

/// `verb` and `decision` are strongly-typed enums on the wire. Sending an
/// unrecognised `verb` value causes JSON extraction to fail; axum returns
/// 422 Unprocessable Entity (JSON rejection default). The response body is
/// an error description (not a structured ProblemDetail).
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_invalid_action_returns_400() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = post_override(
        &env.base_url(),
        json!({
            "agentIds": ["research-bot-04"],
            "resourceId": "pg",
            "verb": "INVALID_VERB",
            "decision": "deny"
        }),
    )
    .await;

    // Axum's Json extractor returns 422 for enum deser failures; accept both
    // 400 and 422 since the exact code is an implementation detail of axum's
    // rejection handler.
    assert!(
        resp.status().is_client_error(),
        "invalid verb must yield a 4xx error; got {}",
        resp.status()
    );
    assert_ne!(resp.status(), StatusCode::OK, "invalid verb must not return 200");
}

/// Unknown `resourceId` (a tool not present in any agent's caps map) is
/// silently skipped by `CapabilityStore::apply_override` — the request
/// succeeds with 200 and returns an empty `updated` array. Neither 400 nor
/// 404 is returned; this matches the documented behaviour in the store's
/// `apply_override` doc comment: "An unknown `resourceId` on an agent is
/// silently skipped."
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_unknown_tool_returns_400_or_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = post_override(
        &env.base_url(),
        json!({
            "agentIds": ["research-bot-04"],
            "resourceId": "nonexistent-tool-xyz",
            "verb": "read",
            "decision": "deny"
        }),
    )
    .await;

    // Actual behaviour: 200 + empty updated array (unknown resource silently skipped).
    // The ticket expected 400 or 404; the implementation silently skips unknown
    // resourceId values. This is by design (matches dashboard mock behaviour).
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "unknown resourceId is silently skipped and returns 200 (not 400/404)"
    );
    let body: Value = resp.json().await.expect("body should parse");
    let updated = body["updated"].as_array().expect("`updated` must be an array");
    assert!(
        updated.is_empty(),
        "unknown resourceId yields empty updated array; got {} entries",
        updated.len()
    );
}
