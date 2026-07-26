//! AAASM-1489 (F122 ST-H) — Live-gateway HTTP integration tests for
//! `/api/v1/capability/*` endpoints.
//!
//! Uses `TopologyTestEnv::start()` which boots an in-process axum server. Auth
//! is `Off` so all RBAC checks pass without a token.
//!
//! As of AAASM-5090 the matrix is a projection of the agent registry and the
//! policy capability cascade rather than a compiled-in fixture, so these tests
//! register the agents they expect to see and assert against that projection.
//!
//! ## Route surface for `aa-api/src/routes/capability.rs`
//!
//! | Method | Path | Handler |
//! |--------|------|---------|
//! | GET    | `/api/v1/capability/matrix`        | `get_matrix`      |
//! | POST   | `/api/v1/capability/override`      | `apply_override`  |
//! | GET    | `/api/v1/capability/override`      | `list_overrides`  |
//! | DELETE | `/api/v1/capability/override/{id}` | `revoke_override` |

mod common;

use aa_gateway::registry::{AgentRecord, AgentStatus};
use common::TopologyTestEnv;
use reqwest::StatusCode;
use serde_json::{json, Value};

// ── helpers ──────────────────────────────────────────────────────────────────

fn hex_id(b: u8) -> String {
    [b; 16].iter().map(|x| format!("{x:02x}")).collect()
}

/// Minimal registered agent; only the fields the projection reads matter.
fn agent(id_byte: u8, name: &str, team: Option<&str>, tools: &[&str]) -> AgentRecord {
    AgentRecord {
        agent_id: [id_byte; 16],
        name: name.to_string(),
        framework: "langgraph".to_string(),
        version: "0.1.0".to_string(),
        risk_tier: 1,
        tool_names: tools.iter().map(|t| (*t).to_string()).collect(),
        public_key: "pk".to_string(),
        credential_token: format!("tok-{id_byte}"),
        metadata: std::collections::BTreeMap::new(),
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
        team_id: team.map(str::to_string),
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

/// Start the harness with two registered agents, one of which declares a tool.
async fn env_with_agents() -> TopologyTestEnv {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(agent(0x01, "checkout-agent", Some("team-alpha"), &["search"]))
        .expect("register a");
    env.agent_registry
        .register(agent(0x02, "refund-agent", Some("team-beta"), &[]))
        .expect("register b");
    env
}

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

async fn matrix_json(base_url: &str, query: &str) -> Value {
    get_matrix(base_url, query)
        .await
        .json()
        .await
        .expect("matrix body should parse as JSON")
}

// ═════════════════════════════════════════════════════════════════════════════
// Matrix projection
// ═════════════════════════════════════════════════════════════════════════════

/// The matrix projects the registered agents, keyed by their real hex ids, with
/// the fixed capability families as columns and camelCase keys on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_projects_registered_agents() {
    let env = env_with_agents().await;
    let resp = get_matrix(&env.base_url(), "").await;
    assert_eq!(resp.status(), StatusCode::OK, "matrix endpoint must return 200");

    let body: Value = resp.json().await.expect("body should parse as JSON");
    let resources = body["resources"].as_array().expect("resources must be an array");
    let agents = body["agents"].as_array().expect("agents must be an array");
    assert!(
        body["sampleCalls"].is_array(),
        "sampleCalls must be present (camelCase)"
    );
    assert!(
        body.get("sample_calls").is_none(),
        "snake_case key must not appear on the wire"
    );

    assert_eq!(agents.len(), 2, "both registered agents are projected");
    let ids: Vec<&str> = agents.iter().map(|a| a["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&hex_id(0x01).as_str()));
    assert!(ids.contains(&hex_id(0x02).as_str()));

    // The three system capability families are always columns; the tool the
    // first agent declared joins them.
    let resource_ids: Vec<&str> = resources.iter().map(|r| r["id"].as_str().unwrap()).collect();
    for expected in ["filesystem", "terminal", "network_outbound", "search"] {
        assert!(resource_ids.contains(&expected), "resource {expected} must be present");
    }

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
        for rid in ["filesystem", "terminal", "network_outbound"] {
            let cell = &agent["caps"][rid];
            assert!(cell.is_object(), "agent {id} must have a caps cell for {rid}");
            for verb in ["read", "write", "delete", "exec"] {
                assert!(
                    cell[verb].is_string(),
                    "agent {id} resource {rid} must have a `{verb}` decision"
                );
            }
        }
    }
}

/// Fields with no source in the gateway never reach the wire as a value, so a
/// consumer can tell "unmeasured" apart from a real zero.
///
/// Most are omitted entirely. `trust` is the exception (AAASM-5104): it is
/// required-but-nullable, so the key is always present carrying an explicit
/// `null` — a missing key is the thing that invites `?? 0`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_never_fakes_a_field_with_no_real_source() {
    let env = env_with_agents().await;
    let body = matrix_json(&env.base_url(), "").await;

    for agent in body["agents"].as_array().unwrap() {
        let id = agent["id"].as_str().unwrap();
        assert!(agent.get("trust").is_some(), "agent {id} must carry the trust key");
        assert!(agent["trust"].is_null(), "agent {id} must carry trust as null");
        assert!(!agent["trust"].is_number(), "agent {id} must not carry a fake trust");
        assert_ne!(agent["trust"], 0, "agent {id} must not fold trust to a scored zero");
        assert!(agent.get("flagged").is_none(), "agent {id} must not carry a fake flag");
        assert!(agent.get("note").is_none(), "agent {id} must not carry a fake note");
        // No enforcement_mode override was registered for either agent.
        assert!(agent.get("mode").is_none(), "agent {id} declared no mode override");
    }
    for policy in body["policies"].as_array().unwrap() {
        assert!(policy.get("hits24h").is_none(), "hit counts have no source here");
    }
    assert!(
        body["sampleCalls"].as_array().unwrap().is_empty(),
        "call samples need a policy diff nothing computes yet"
    );

    // A tool column carries no group; a system family does.
    let resources = body["resources"].as_array().unwrap();
    let search = resources.iter().find(|r| r["id"] == "search").unwrap();
    assert!(search.get("group").is_none(), "an MCP tool has no classification");
    let fs = resources.iter().find(|r| r["id"] == "filesystem").unwrap();
    assert_eq!(fs["group"], "files");
}

/// With nothing registered the matrix is empty rather than falling back to demo
/// rows — the endpoint has no fixture left to serve.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_is_empty_without_registered_agents() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let body = matrix_json(&env.base_url(), "").await;
    assert!(body["agents"].as_array().unwrap().is_empty());
}

/// `?team_id=` filter returns only the agent row whose `id` matches.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_filter_by_team() {
    let env = env_with_agents().await;
    let body = matrix_json(&env.base_url(), &format!("team_id={}", hex_id(0x01))).await;
    let agents = body["agents"].as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["id"], hex_id(0x01));
}

/// `?tool=` narrows both the resource list and each agent's caps map.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_filter_by_tool() {
    let env = env_with_agents().await;
    let body = matrix_json(&env.base_url(), "tool=filesystem").await;

    let resources = body["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["id"], "filesystem");
    for agent in body["agents"].as_array().unwrap() {
        let caps = agent["caps"].as_object().unwrap();
        assert_eq!(caps.len(), 1, "caps narrow to the selected tool");
        assert!(caps.contains_key("filesystem"));
    }
}

/// `?effective_only=true` drops cells whose four verbs are all `na`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_effective_only_excludes_all_na_cells() {
    let env = env_with_agents().await;
    let body = matrix_json(&env.base_url(), "effective_only=true").await;

    for agent in body["agents"].as_array().unwrap() {
        for (rid, cell) in agent["caps"].as_object().unwrap() {
            let all_na = ["read", "write", "delete", "exec"].iter().all(|v| cell[*v] == "na");
            assert!(!all_na, "cell {rid} is entirely n/a and should have been dropped");
        }
    }
}

/// An unknown team id yields an empty agent list, not an error.
#[tokio::test(flavor = "multi_thread")]
async fn capability_matrix_unknown_team_returns_empty() {
    let env = env_with_agents().await;
    let body = matrix_json(&env.base_url(), "team_id=no-such-agent").await;
    assert!(body["agents"].as_array().unwrap().is_empty());
}

// ═════════════════════════════════════════════════════════════════════════════
// Override overlay
// ═════════════════════════════════════════════════════════════════════════════

/// An applied override is replayed over the projection on the next read.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_appears_in_matrix() {
    let env = env_with_agents().await;
    let base = env.base_url();
    let target = hex_id(0x01);

    let before = matrix_json(&base, "").await;
    let agent_before = before["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .expect("target agent is projected")
        .clone();
    assert_ne!(
        agent_before["caps"]["filesystem"]["write"], "deny",
        "precondition: the projected value is not already deny"
    );

    let resp = post_override(
        &base,
        json!({
            "agentIds": [target],
            "resourceId": "filesystem",
            "verb": "write",
            "decision": "deny"
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "POST /override must return 200");

    let body: Value = resp.json().await.expect("override body should parse");
    let updated = body["updated"].as_array().expect("response must have `updated`");
    assert_eq!(updated.len(), 1, "exactly one agent row must be returned");
    assert_eq!(updated[0]["id"], target);
    assert_eq!(updated[0]["caps"]["filesystem"]["write"], "deny");
    assert!(body["overrideId"].is_string(), "the override id must be returned");

    let after = matrix_json(&base, "").await;
    let agent_after = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .unwrap()
        .clone();
    assert_eq!(agent_after["caps"]["filesystem"]["write"], "deny");
    // Only the targeted verb moved.
    assert_eq!(
        agent_after["caps"]["filesystem"]["read"],
        agent_before["caps"]["filesystem"]["read"]
    );
}

/// Deleting an override stops it being replayed, restoring the projected value.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_delete_restores_projected_value() {
    let env = env_with_agents().await;
    let base = env.base_url();
    let target = hex_id(0x01);

    let before = matrix_json(&base, "").await;
    let original = before["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .unwrap()["caps"]["filesystem"]["write"]
        .clone();

    let body: Value = post_override(
        &base,
        json!({ "agentIds": [target], "resourceId": "filesystem", "verb": "write", "decision": "deny" }),
    )
    .await
    .json()
    .await
    .unwrap();
    let override_id = body["overrideId"].as_str().unwrap().to_string();

    let del = reqwest::Client::new()
        .delete(format!("{base}/api/v1/capability/override/{override_id}"))
        .send()
        .await
        .expect("DELETE should send");
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let after = matrix_json(&base, "").await;
    let restored = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .unwrap()["caps"]["filesystem"]["write"]
        .clone();
    assert_eq!(restored, original, "revoking restores the projected decision");
}

/// Deleting an override that never existed is a 404.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_delete_unknown_id_returns_404() {
    let env = env_with_agents().await;
    let resp = reqwest::Client::new()
        .delete(format!("{}/api/v1/capability/override/not-a-real-id", env.base_url()))
        .send()
        .await
        .expect("DELETE should send");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A TTL'd override returns 201 and stops applying once it elapses.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_with_ttl_expires() {
    let env = env_with_agents().await;
    let base = env.base_url();
    let target = hex_id(0x01);

    let before = matrix_json(&base, "").await;
    let original = before["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .unwrap()["caps"]["filesystem"]["write"]
        .clone();

    let resp = post_override(
        &base,
        json!({
            "agentIds": [target],
            "resourceId": "filesystem",
            "verb": "write",
            "decision": "deny",
            "ttlSeconds": 1
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED, "a TTL'd override returns 201");

    tokio::time::sleep(std::time::Duration::from_millis(1400)).await;
    let after = matrix_json(&base, "").await;
    let now = after["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == target)
        .unwrap()["caps"]["filesystem"]["write"]
        .clone();
    assert_eq!(now, original, "TTL expiry restores the projected decision");
}

/// `GET /capability/override` lists what was applied and honours `agent_id`.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_list_returns_active() {
    let env = env_with_agents().await;
    let base = env.base_url();
    let target = hex_id(0x01);

    post_override(
        &base,
        json!({ "agentIds": [target], "resourceId": "filesystem", "verb": "write", "decision": "deny" }),
    )
    .await;

    let all: Value = reqwest::get(format!("{base}/api/v1/capability/override"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 1);

    let filtered: Value = reqwest::get(format!("{base}/api/v1/capability/override?agent_id=nobody"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(filtered.as_array().unwrap().is_empty());
}

/// An override naming an agent the projection does not contain is rejected, and
/// nothing is recorded.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_unknown_agent_returns_400() {
    let env = env_with_agents().await;
    let base = env.base_url();

    let resp = post_override(
        &base,
        json!({ "agentIds": ["not-registered"], "resourceId": "filesystem", "verb": "write", "decision": "deny" }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let all: Value = reqwest::get(format!("{base}/api/v1/capability/override"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(all.as_array().unwrap().is_empty(), "a rejected override is not logged");
}

/// A malformed body (unknown decision) is rejected by deserialization.
#[tokio::test(flavor = "multi_thread")]
async fn capability_override_invalid_decision_returns_4xx() {
    let env = env_with_agents().await;
    let resp = post_override(
        &env.base_url(),
        json!({
            "agentIds": [hex_id(0x01)],
            "resourceId": "filesystem",
            "verb": "write",
            "decision": "not-a-decision"
        }),
    )
    .await;
    assert!(
        resp.status().is_client_error(),
        "an unknown decision must not be accepted, got {}",
        resp.status()
    );
}
