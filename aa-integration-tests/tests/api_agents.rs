//! F122 ST-A: Live-gateway integration tests for `/api/v1/agents/*` (AAASM-1482).
//!
//! 15 tests across 4 groups: happy-path (5), lifecycle (4), graph+edges (3),
//! error paths (3). All tests use `TopologyTestEnv::start()` + `reqwest::Client`.
//! Team scope `f122-agents-it` is used for all seeded state.
//!
//! ## Divergences from ticket description
//!
//! 1. **`agents_subtree_burn_returns_budget_time_series`** replaces the ticket's
//!    `agents_subtree_burn_cascade_deregisters_descendants`: the ticket described
//!    `POST /subtree-burn` as a cascade-terminate operation, but the implemented
//!    endpoint is `GET /api/v1/agents/{id}/subtree-burn` which returns a budget
//!    time series (`SubtreeBurnResponse`). Tested against the actual endpoint.
//!    Follow-up: clarify whether a separate cascade-terminate endpoint is planned.
//!
//! 2. **`agents_resume_when_already_running_returns_409`**: the ticket expected
//!    `{"code":"invalid_state",…}` in the error body. `ProblemDetail` has no
//!    `code` field — only `type`, `title`, `status`, `detail`, `instance`. The
//!    test asserts on HTTP 409 and `body["status"] == 409` only. A 409 guard was
//!    added to `aa-api/src/routes/agents.rs resume_agent` as part of this ST
//!    (previously the route returned 200 for an already-active agent).
//!
//! 3. **`agents_list_invalid_pagination_returns_400`** replaces the ticket's
//!    `agents_list_invalid_filter_returns_400 (GET /agents?status=garbage)`:
//!    `GET /api/v1/agents` accepts only `page`/`per_page` pagination params, not
//!    a `status` filter. The test triggers 400 via an invalid pagination value.

mod common;

use std::collections::{BTreeMap, VecDeque};

use aa_gateway::registry::{AgentRecord, AgentStatus, SuspendReason};
use common::TopologyTestEnv;

const TEAM: &str = "f122-agents-it";

fn make_agent(id: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: format!("f122-{}", &hex_id(&id)[..12]),
        framework: "f122-framework".into(),
        version: "0.1.0".into(),
        risk_tier: 0,
        tool_names: vec!["f122_tool".into()],
        public_key: "f122-pubkey".into(),
        credential_token: "f122-token".into(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(TEAM.into()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn rand_id() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

async fn record_edge(client: &reqwest::Client, base_url: &str, source: &str, target: &str) {
    let resp = client
        .post(format!("{base_url}/api/v1/topology/edges"))
        .json(&serde_json::json!({
            "source_agent_id": source,
            "target_agent_id": target,
            "edge_type": "delegates_to"
        }))
        .send()
        .await
        .expect("record edge request");
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED, "record edge failed");
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agents_list_empty_returns_200_and_empty_array() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/agents", env.base_url()))
        .send()
        .await
        .expect("list agents");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["total"], 0);
    assert!(body["items"].as_array().expect("items array").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_list_returns_seeded_agents() {
    let env = TopologyTestEnv::start().await.expect("harness start");

    let ids = [rand_id(), rand_id(), rand_id()];
    for id in ids {
        env.agent_registry.register(make_agent(id)).expect("register agent");
    }

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents", env.base_url()))
        .send()
        .await
        .expect("list agents");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["total"], 3);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    for item in items {
        assert!(item["id"].as_str().is_some(), "id field missing");
        assert!(item["name"].as_str().is_some(), "name field missing");
        assert!(item["status"].as_str().is_some(), "status field missing");
        assert!(item["framework"].as_str().is_some(), "framework field missing");
        assert!(item["version"].as_str().is_some(), "version field missing");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_inspect_returns_full_record() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}", env.base_url(), agent_hex))
        .send()
        .await
        .expect("inspect agent");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["id"], agent_hex.as_str());
    assert!(body["name"].as_str().is_some());
    assert_eq!(body["framework"], "f122-framework");
    assert_eq!(body["version"], "0.1.0");
    assert_eq!(body["status"], "Active");
    assert!(body["tool_names"].is_array());
    assert!(body["metadata"].is_object());
    assert!(body["active_sessions"].is_array());
    assert!(body["recent_events"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_budget_returns_snapshot() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let agent_core_id = aa_core::identity::AgentId::from_bytes(id);
    env.budget_tracker
        .record_raw_spend(agent_core_id, Some(TEAM), rust_decimal::Decimal::from(5));

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}/budget", env.base_url(), agent_hex))
        .send()
        .await
        .expect("get agent budget");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    let rows = body["rows"].as_array().expect("rows array");
    assert!(!rows.is_empty(), "budget rollup should have at least one row");
    for row in rows {
        assert!(row["scope"].as_str().is_some(), "scope field missing");
        assert!(row["period"].as_str().is_some(), "period field missing");
        assert!(row["spent_usd"].as_str().is_some(), "spent_usd field missing");
    }
    // The agent-scope row should reflect the seeded spend
    let agent_row = rows.iter().find(|r| r["scope"] == "agent");
    assert!(agent_row.is_some(), "agent-scope row should be present");
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_capabilities_returns_effective_set() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}/capabilities", env.base_url(), agent_hex))
        .send()
        .await
        .expect("get capabilities");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(body["allow"].is_array(), "allow must be array");
    assert!(body["deny"].is_array(), "deny must be array");
    assert!(body["sources"].is_array(), "sources must be array");
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agents_suspend_then_status_is_suspended() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let client = reqwest::Client::new();

    // Suspend once
    let resp = client
        .post(format!("{}/api/v1/agents/{}/suspend", env.base_url(), agent_hex))
        .json(&serde_json::json!({"reason": "anomaly spike under investigation"}))
        .send()
        .await
        .expect("suspend agent");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["previous_status"], "Active");
    assert!(
        body["new_status"].as_str().unwrap_or("").contains("Suspended"),
        "new_status should contain 'Suspended', got: {}",
        body["new_status"]
    );

    // Re-suspend is idempotent — still returns 200
    let resp2 = client
        .post(format!("{}/api/v1/agents/{}/suspend", env.base_url(), agent_hex))
        .json(&serde_json::json!({"reason": "re-check suspension"}))
        .send()
        .await
        .expect("re-suspend agent");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);

    // GET confirms suspended status
    let get_resp = client
        .get(format!("{}/api/v1/agents/{}", env.base_url(), agent_hex))
        .send()
        .await
        .expect("inspect agent after suspend");
    let get_body: serde_json::Value = get_resp.json().await.expect("json body");
    assert!(
        get_body["status"].as_str().unwrap_or("").contains("Suspended"),
        "agent status should be Suspended, got: {}",
        get_body["status"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_resume_from_suspended_returns_to_running() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");
    env.agent_registry
        .suspend_agent(&id, SuspendReason::Manual)
        .expect("suspend agent in registry");

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/agents/{}/resume", env.base_url(), agent_hex))
        .send()
        .await
        .expect("resume agent");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["new_status"], "Active");
    assert!(
        body["previous_status"].as_str().unwrap_or("").contains("Suspended"),
        "previous_status should contain 'Suspended'"
    );

    // GET confirms active status
    let get_resp = client
        .get(format!("{}/api/v1/agents/{}", env.base_url(), agent_hex))
        .send()
        .await
        .expect("inspect agent after resume");
    let get_body: serde_json::Value = get_resp.json().await.expect("json body");
    assert_eq!(get_body["status"], "Active");
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_resume_when_already_running_returns_409() {
    // Note: ticket expected {"code":"invalid_state",...} but ProblemDetail has no
    // `code` field. Asserting HTTP 409 and body["status"] == 409 only.
    // The 409 guard was added to resume_agent in aa-api/src/routes/agents.rs.
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");
    // Agent is already Active — do not suspend before resuming

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/agents/{}/resume", env.base_url(), agent_hex))
        .send()
        .await
        .expect("resume already-active agent");

    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], 409);
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_subtree_burn_returns_budget_time_series() {
    // Ticket described POST /subtree-burn for cascade-terminate; actual endpoint
    // is GET /api/v1/agents/{id}/subtree-burn returning a SubtreeBurnResponse.
    // See divergence note in module-level doc.
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}/subtree-burn", env.base_url(), agent_hex))
        .send()
        .await
        .expect("subtree-burn request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["agent_id"], agent_hex.as_str());
    assert!(body["period"].as_str().is_some(), "period field missing");
    assert!(body["points"].is_array(), "points must be an array");
}

// ---------------------------------------------------------------------------
// Graph + edges
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agents_edges_returns_direct_neighbours() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let parent_id = rand_id();
    let child_id = rand_id();
    let parent_hex = hex_id(&parent_id);
    let child_hex = hex_id(&child_id);

    env.agent_registry
        .register(make_agent(parent_id))
        .expect("register parent");
    env.agent_registry
        .register(make_agent(child_id))
        .expect("register child");

    let client = reqwest::Client::new();
    record_edge(&client, &env.base_url(), &parent_hex, &child_hex).await;

    let resp = client
        .get(format!("{}/api/v1/agents/{}/edges", env.base_url(), parent_hex))
        .send()
        .await
        .expect("list edges");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["agent_id"], parent_hex.as_str());
    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 1, "parent should have one outgoing edge");
    assert_eq!(edges[0]["source_agent_id"], parent_hex.as_str());
    assert_eq!(edges[0]["target_agent_id"], child_hex.as_str());
    assert_eq!(edges[0]["edge_type"], "delegates_to");
    assert_eq!(body["count"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_graph_returns_full_subtree() {
    // Seeds a 3-level tree: root → {c1 → [gc1, gc2], c2 → [gc3, gc4]} — 7 nodes, 6 edges.
    // Default graph BFS depth=2 visits all three levels.
    let env = TopologyTestEnv::start().await.expect("harness start");
    let client = reqwest::Client::new();
    let base = env.base_url();

    let (root, c1, c2, gc1, gc2, gc3, gc4) = (
        rand_id(),
        rand_id(),
        rand_id(),
        rand_id(),
        rand_id(),
        rand_id(),
        rand_id(),
    );
    for id in [root, c1, c2, gc1, gc2, gc3, gc4] {
        env.agent_registry.register(make_agent(id)).expect("register agent");
    }

    let (root_hex, c1_hex, c2_hex, gc1_hex, gc2_hex, gc3_hex, gc4_hex) = (
        hex_id(&root),
        hex_id(&c1),
        hex_id(&c2),
        hex_id(&gc1),
        hex_id(&gc2),
        hex_id(&gc3),
        hex_id(&gc4),
    );

    for (src, tgt) in [
        (root_hex.as_str(), c1_hex.as_str()),
        (root_hex.as_str(), c2_hex.as_str()),
        (c1_hex.as_str(), gc1_hex.as_str()),
        (c1_hex.as_str(), gc2_hex.as_str()),
        (c2_hex.as_str(), gc3_hex.as_str()),
        (c2_hex.as_str(), gc4_hex.as_str()),
    ] {
        record_edge(&client, &base, src, tgt).await;
    }

    let resp = client
        .get(format!("{base}/api/v1/agents/{root_hex}/graph"))
        .send()
        .await
        .expect("graph request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["root_agent_id"], root_hex.as_str());
    let nodes = body["nodes"].as_array().expect("nodes array");
    assert_eq!(nodes.len(), 7, "should return all 7 nodes in the subtree");
    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 6, "should return all 6 directed edges");
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_graph_for_leaf_returns_single_node_no_edges() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let id = rand_id();
    let agent_hex = hex_id(&id);

    env.agent_registry.register(make_agent(id)).expect("register agent");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}/graph", env.base_url(), agent_hex))
        .send()
        .await
        .expect("graph request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    let nodes = body["nodes"].as_array().expect("nodes array");
    assert_eq!(nodes.len(), 1, "leaf should have exactly one node");
    assert_eq!(nodes[0]["id"], agent_hex.as_str());
    let edges = body["edges"].as_array().expect("edges array");
    assert!(edges.is_empty(), "leaf should have no edges");
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agents_inspect_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let unknown_hex = "00".repeat(16);

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents/{}", env.base_url(), unknown_hex))
        .send()
        .await
        .expect("inspect unknown agent");

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_suspend_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness start");
    let unknown_hex = "00".repeat(16);

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/agents/{}/suspend", env.base_url(), unknown_hex))
        .json(&serde_json::json!({"reason": "test"}))
        .send()
        .await
        .expect("suspend unknown agent");

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["status"], 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn agents_list_invalid_pagination_returns_400() {
    // Ticket specified GET /agents?status=garbage but list_agents only accepts
    // page/per_page params. An invalid per_page value triggers serde deserialization
    // failure in axum's Query extractor, returning 400.
    let env = TopologyTestEnv::start().await.expect("harness start");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/agents?per_page=not-a-number", env.base_url()))
        .send()
        .await
        .expect("list agents with invalid param");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}
