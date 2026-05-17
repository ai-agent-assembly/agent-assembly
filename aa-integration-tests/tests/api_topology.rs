//! AAASM-1483 / F122 ST-B — Live-gateway HTTP integration tests for
//! all `/api/v1/topology/*` endpoints.
//!
//! 13 tests, team scope `f122-topology-it`. All tests start a fresh
//! `TopologyTestEnv` (in-process axum server on a free port), seed state
//! directly into the shared `Arc<AgentRegistry>`, and drive assertions via
//! `reqwest` against the running server. No gateway mocking.
//!
//! Test groups:
//!  - Overview + stats (3)
//!  - Tree (3)
//!  - Team (2)
//!  - Lineage (2)
//!  - Edges (2)
//!  - Caching (1)
//!
//! Lineage ordering convention: `GET /topology/lineage/{id}` returns ancestors
//! **root-first** — index 0 is the root (depth 0), the last element is the
//! requested agent itself. A root returns a single-element list containing
//! only itself.

mod common;

use std::collections::{BTreeMap, VecDeque};

use aa_core::GovernanceLevel;
use aa_gateway::registry::{AgentRecord, AgentStatus, SuspendReason};
use common::TopologyTestEnv;
use reqwest::Client;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const TEAM: &str = "f122-topology-it";

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_agent(
    id: [u8; 16],
    depth: u32,
    parent_key: Option<[u8; 16]>,
    root_agent_id: Option<[u8; 16]>,
    parent_agent_id: Option<String>,
    team_id: Option<&str>,
    status: AgentStatus,
) -> AgentRecord {
    let hex_id: String = id.iter().map(|b| format!("{b:02x}")).collect();
    AgentRecord {
        agent_id: id,
        name: format!("f122-agent-{}", &hex_id[..8]),
        framework: "f122-test".into(),
        version: "0.0.1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "deadbeef".into(),
        credential_token: "f122-token".into(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: GovernanceLevel::default(),
        parent_agent_id,
        team_id: team_id.map(str::to_string),
        depth,
        delegation_reason: if depth > 0 {
            Some("f122-test-delegation".into())
        } else {
            None
        },
        spawned_by_tool: None,
        root_agent_id,
        children: vec![],
        parent_key,
    }
}

fn root_agent(id: [u8; 16], team_id: Option<&str>) -> AgentRecord {
    make_agent(id, 0, None, Some(id), None, team_id, AgentStatus::Active)
}

fn child_agent(id: [u8; 16], parent: [u8; 16], root: [u8; 16], team_id: Option<&str>) -> AgentRecord {
    make_agent(
        id,
        1,
        Some(parent),
        Some(root),
        Some(hex(&parent)),
        team_id,
        AgentStatus::Active,
    )
}

fn grandchild_agent(id: [u8; 16], parent: [u8; 16], root: [u8; 16], team_id: Option<&str>) -> AgentRecord {
    make_agent(
        id,
        2,
        Some(parent),
        Some(root),
        Some(hex(&parent)),
        team_id,
        AgentStatus::Active,
    )
}

// ---------------------------------------------------------------------------
// Overview + stats
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_empty_returns_zero_counts() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/topology/overview", env.base_url());
    let resp = reqwest::get(&url).await.expect("GET overview should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("body should be JSON");
    assert_eq!(body["team_count"], 0, "empty registry: team_count should be 0");
    assert_eq!(
        body["total_agent_count"], 0,
        "empty registry: total_agent_count should be 0"
    );
    assert_eq!(
        body["root_agent_count"], 0,
        "empty registry: root_agent_count should be 0"
    );
    assert!(body["teams"].as_array().unwrap().is_empty(), "teams should be []");
    assert!(
        body["standalone_root_agents"].as_array().unwrap().is_empty(),
        "standalone_root_agents should be []"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_after_seed_returns_correct_counts() {
    // 3 Active + 1 Suspended agents in the f122-topology-it team.
    const A1: [u8; 16] = [0xA1; 16];
    const A2: [u8; 16] = [0xA2; 16];
    const A3: [u8; 16] = [0xA3; 16];
    const A4: [u8; 16] = [0xA4; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    for id in [A1, A2, A3] {
        env.agent_registry
            .register(root_agent(id, Some(TEAM)))
            .expect("register active agent");
    }
    let mut suspended = root_agent(A4, Some(TEAM));
    suspended.status = AgentStatus::Suspended(SuspendReason::Manual);
    env.agent_registry
        .register(suspended)
        .expect("register suspended agent");

    // Overview: total count.
    let overview_url = format!("{}/api/v1/topology/overview", env.base_url());
    let overview: serde_json::Value = reqwest::get(&overview_url)
        .await
        .expect("GET overview")
        .json()
        .await
        .expect("overview JSON");
    assert_eq!(overview["total_agent_count"], 4, "total_agent_count = 4");
    assert_eq!(overview["root_agent_count"], 4, "all 4 are roots (depth 0)");
    assert_eq!(overview["team_count"], 1, "one team registered");

    // Stats: by-status breakdown.
    let stats_url = format!("{}/api/v1/topology/stats", env.base_url());
    let stats: serde_json::Value = reqwest::get(&stats_url)
        .await
        .expect("GET stats")
        .json()
        .await
        .expect("stats JSON");
    assert_eq!(stats["active_count"], 3, "active_count = 3");
    assert_eq!(stats["suspended_count"], 1, "suspended_count = 1");
    assert_eq!(stats["total_agents"], 4, "total_agents = 4");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_stats_groups_by_team() {
    // 2 teams × 2 agents each.
    const B1: [u8; 16] = [0xB1; 16];
    const B2: [u8; 16] = [0xB2; 16];
    const B3: [u8; 16] = [0xB3; 16];
    const B4: [u8; 16] = [0xB4; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    for id in [B1, B2] {
        env.agent_registry
            .register(root_agent(id, Some("f122-team-alpha")))
            .expect("register alpha agent");
    }
    for id in [B3, B4] {
        env.agent_registry
            .register(root_agent(id, Some("f122-team-beta")))
            .expect("register beta agent");
    }

    let url = format!("{}/api/v1/topology/stats", env.base_url());
    let stats: serde_json::Value = reqwest::get(&url)
        .await
        .expect("GET stats")
        .json()
        .await
        .expect("stats JSON");

    assert_eq!(stats["team_count"], 2, "two teams registered");
    assert_eq!(stats["total_agents"], 4);
    assert_eq!(stats["team_sizes"]["f122-team-alpha"], 2, "alpha has 2 agents");
    assert_eq!(stats["team_sizes"]["f122-team-beta"], 2, "beta has 2 agents");
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_for_orphan_returns_single_node() {
    const C1: [u8; 16] = [0xC1; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(C1, Some(TEAM)))
        .expect("register C1");

    let url = format!("{}/api/v1/topology/tree/{}", env.base_url(), hex(&C1));
    let resp = reqwest::get(&url).await.expect("GET tree");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let tree: serde_json::Value = resp.json().await.expect("tree JSON");

    assert_eq!(tree["id"], hex(&C1), "root id should match");
    assert_eq!(tree["depth"], 0, "root depth should be 0");
    let children = tree["children"].as_array().expect("children array");
    assert!(children.is_empty(), "orphan root should have no children");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_for_3level_subtree_returns_full_hierarchy() {
    // root(D1) → mid(D2) → leaf(D3)
    const D1: [u8; 16] = [0xD1; 16];
    const D2: [u8; 16] = [0xD2; 16];
    const D3: [u8; 16] = [0xD3; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(D1, Some(TEAM)))
        .expect("register root D1");
    env.agent_registry
        .register(child_agent(D2, D1, D1, Some(TEAM)))
        .expect("register mid D2");
    env.agent_registry
        .register(grandchild_agent(D3, D2, D1, Some(TEAM)))
        .expect("register leaf D3");

    let url = format!("{}/api/v1/topology/tree/{}", env.base_url(), hex(&D1));
    let resp = reqwest::get(&url).await.expect("GET tree");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let tree: serde_json::Value = resp.json().await.expect("tree JSON");

    assert_eq!(tree["id"], hex(&D1), "root id");
    assert_eq!(tree["depth"], 0, "root depth = 0");

    let root_children = tree["children"].as_array().expect("root.children array");
    assert_eq!(root_children.len(), 1, "root has exactly one child");

    let mid = &root_children[0];
    assert_eq!(mid["id"], hex(&D2), "mid id");
    assert_eq!(mid["depth"], 1, "mid depth = 1");

    let mid_children = mid["children"].as_array().expect("mid.children array");
    assert_eq!(mid_children.len(), 1, "mid has exactly one child");

    let leaf = &mid_children[0];
    assert_eq!(leaf["id"], hex(&D3), "leaf id");
    assert_eq!(leaf["depth"], 2, "leaf depth = 2");
    assert!(leaf["children"].as_array().unwrap().is_empty(), "leaf has no children");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_tree_unknown_root_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let missing_id = "deadbeefdeadbeefdeadbeefdeadbeef";
    let url = format!("{}/api/v1/topology/tree/{missing_id}", env.base_url());
    let resp = reqwest::get(&url).await.expect("GET tree unknown id");
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND, "unknown root → 404");
}

// ---------------------------------------------------------------------------
// Team
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn topology_team_returns_only_team_members() {
    // E1 and E2 are in TEAM; E3 is in a different team.
    const E1: [u8; 16] = [0xE1; 16];
    const E2: [u8; 16] = [0xE2; 16];
    const E3: [u8; 16] = [0xE3; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(E1, Some(TEAM)))
        .expect("register E1");
    env.agent_registry
        .register(root_agent(E2, Some(TEAM)))
        .expect("register E2");
    env.agent_registry
        .register(root_agent(E3, Some("f122-other-team")))
        .expect("register E3");

    let url = format!("{}/api/v1/topology/team/{TEAM}", env.base_url());
    let resp = reqwest::get(&url).await.expect("GET team");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("team JSON");

    assert_eq!(body["team_id"], TEAM);
    assert_eq!(body["agent_count"], 2, "only 2 agents belong to the target team");

    let members = body["members"].as_array().expect("members array");
    assert_eq!(members.len(), 2);

    let e1_hex = hex(&E1);
    let e2_hex = hex(&E2);
    let e3_hex = hex(&E3);
    let ids: Vec<&str> = members.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&e1_hex.as_str()), "E1 should be in members");
    assert!(ids.contains(&e2_hex.as_str()), "E2 should be in members");
    assert!(!ids.contains(&e3_hex.as_str()), "E3 from other team should not appear");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_team_with_no_members_returns_empty() {
    // Querying a team with no registered agents returns 200 + empty members list
    // rather than 404, distinguishing "team has no agents" from "route not found".
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/topology/team/f122-no-such-team", env.base_url());
    let resp = reqwest::get(&url).await.expect("GET team unknown");
    assert_eq!(resp.status(), reqwest::StatusCode::OK, "empty team → 200 (not 404)");
    let body: serde_json::Value = resp.json().await.expect("team JSON");
    assert_eq!(body["agent_count"], 0, "agent_count should be 0");
    assert!(
        body["members"].as_array().expect("members array").is_empty(),
        "members should be []"
    );
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

/// Ordering convention: `ancestors[0]` is the root (depth 0), `ancestors[last]`
/// is the requested agent. A root agent returns a single-element chain.
#[tokio::test(flavor = "multi_thread")]
async fn topology_lineage_returns_ancestor_chain_root_first() {
    // root(F1) → mid(F2) → leaf(F3)
    const F1: [u8; 16] = [0xF1; 16];
    const F2: [u8; 16] = [0xF2; 16];
    const F3: [u8; 16] = [0xF3; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(F1, Some(TEAM)))
        .expect("register root F1");
    env.agent_registry
        .register(child_agent(F2, F1, F1, Some(TEAM)))
        .expect("register mid F2");
    env.agent_registry
        .register(grandchild_agent(F3, F2, F1, Some(TEAM)))
        .expect("register leaf F3");

    let url = format!("{}/api/v1/topology/lineage/{}", env.base_url(), hex(&F3));
    let resp = reqwest::get(&url).await.expect("GET lineage");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("lineage JSON");

    assert_eq!(body["agent_id"], hex(&F3), "subject agent id");
    assert_eq!(body["ancestor_count"], 3, "chain length = 3 (root + mid + leaf)");

    let ancestors = body["ancestors"].as_array().expect("ancestors array");
    assert_eq!(ancestors.len(), 3);

    // Root-first ordering (see module doc for the ordering convention).
    assert_eq!(ancestors[0]["id"], hex(&F1), "ancestors[0] should be root F1");
    assert_eq!(ancestors[0]["depth"], 0, "root depth = 0");
    assert_eq!(ancestors[1]["id"], hex(&F2), "ancestors[1] should be mid F2");
    assert_eq!(ancestors[1]["depth"], 1, "mid depth = 1");
    assert_eq!(
        ancestors[2]["id"],
        hex(&F3),
        "ancestors[2] should be the requested agent F3"
    );
    assert_eq!(ancestors[2]["depth"], 2, "leaf depth = 2");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_lineage_for_root_returns_self_only() {
    const F4: [u8; 16] = [0xF4; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(F4, Some(TEAM)))
        .expect("register root F4");

    let url = format!("{}/api/v1/topology/lineage/{}", env.base_url(), hex(&F4));
    let resp = reqwest::get(&url).await.expect("GET lineage");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("lineage JSON");

    assert_eq!(body["ancestor_count"], 1, "root's chain contains only itself");
    let ancestors = body["ancestors"].as_array().expect("ancestors array");
    assert_eq!(ancestors.len(), 1);
    assert_eq!(ancestors[0]["id"], hex(&F4), "single entry is the root itself");
    assert_eq!(ancestors[0]["depth"], 0, "root depth = 0");
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn topology_edges_returns_all_relationships() {
    // Source and target agents — registration not required for POST /topology/edges.
    const SRC: [u8; 16] = [0x10; 16];
    const TGT: [u8; 16] = [0x11; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = Client::new();
    let base = env.base_url();

    // Record two edges of different types via POST /topology/edges.
    for edge_type in ["messages", "delegates_to"] {
        let resp = client
            .post(format!("{base}/api/v1/topology/edges"))
            .json(&serde_json::json!({
                "source_agent_id": hex(&SRC),
                "target_agent_id": hex(&TGT),
                "edge_type": edge_type
            }))
            .send()
            .await
            .expect("POST topology/edges");
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::CREATED,
            "edge POST should return 201"
        );
    }

    // GET /topology/edges — list all recorded edges.
    let resp = reqwest::get(format!("{base}/api/v1/topology/edges"))
        .await
        .expect("GET topology/edges");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("edges list JSON");

    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 2, "two edges recorded");
    assert_eq!(body["count"], 2, "count field reflects edge count");

    // Each edge must carry the source/target/type relationship fields.
    for edge in edges {
        assert!(edge["source_agent_id"].is_string(), "edge must have source_agent_id");
        assert!(edge["target_agent_id"].is_string(), "edge must have target_agent_id");
        assert!(edge["edge_type"].is_string(), "edge must have edge_type (relation)");
    }

    // Both recorded edge types must be present.
    let types: Vec<&str> = edges.iter().map(|e| e["edge_type"].as_str().unwrap()).collect();
    assert!(types.contains(&"messages"), "messages edge should be present");
    assert!(types.contains(&"delegates_to"), "delegates_to edge should be present");
}

#[tokio::test(flavor = "multi_thread")]
async fn topology_edges_filter_by_team_only_returns_in_team_edges() {
    // IN1 and IN2 belong to f122-edge-team; OUT belongs to a different team.
    const IN1: [u8; 16] = [0x20; 16];
    const IN2: [u8; 16] = [0x21; 16];
    const OUT: [u8; 16] = [0x22; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    env.agent_registry
        .register(root_agent(IN1, Some("f122-edge-team")))
        .expect("register IN1");
    env.agent_registry
        .register(root_agent(IN2, Some("f122-edge-team")))
        .expect("register IN2");
    env.agent_registry
        .register(root_agent(OUT, Some("f122-other-team")))
        .expect("register OUT");

    let client = Client::new();
    let base = env.base_url();

    // In-team edge: IN1 → IN2.
    client
        .post(format!("{base}/api/v1/topology/edges"))
        .json(&serde_json::json!({
            "source_agent_id": hex(&IN1),
            "target_agent_id": hex(&IN2),
            "edge_type": "messages"
        }))
        .send()
        .await
        .expect("POST in-team edge");

    // Fully out-of-team edge: OUT → OUT (both endpoints outside target team).
    client
        .post(format!("{base}/api/v1/topology/edges"))
        .json(&serde_json::json!({
            "source_agent_id": hex(&OUT),
            "target_agent_id": hex(&OUT),
            "edge_type": "calls"
        }))
        .send()
        .await
        .expect("POST out-of-team edge");

    // Filter by f122-edge-team — only the in-team edge should be returned.
    let resp = client
        .get(format!("{base}/api/v1/topology/edges?team_id=f122-edge-team"))
        .send()
        .await
        .expect("GET topology/edges?team_id=f122-edge-team");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("filtered edges JSON");

    let edges = body["edges"].as_array().expect("edges array");
    assert_eq!(edges.len(), 1, "only the in-team edge should be returned");
    assert_eq!(edges[0]["source_agent_id"], hex(&IN1), "source should be IN1");
    assert_eq!(edges[0]["target_agent_id"], hex(&IN2), "target should be IN2");
}

// ---------------------------------------------------------------------------
// Caching
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn topology_overview_cache_serves_stale_within_ttl() {
    // The harness builds AppState with topology_overview_cache TTL = 1 s.
    // Two sequential GET /topology/overview calls within 500 ms should both
    // read from cache — so registering an agent between them does not change
    // the returned count (stale read).
    const G1: [u8; 16] = [0x51; 16];
    const G2: [u8; 16] = [0x52; 16];

    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("{}/api/v1/topology/overview", env.base_url());

    // Seed one agent and call overview — this populates the cache.
    env.agent_registry
        .register(root_agent(G1, Some(TEAM)))
        .expect("register G1");
    let body1: serde_json::Value = reqwest::get(&url)
        .await
        .expect("first GET overview")
        .json()
        .await
        .expect("first overview JSON");
    let first_count = body1["total_agent_count"].as_u64().expect("total_agent_count field");
    assert_eq!(first_count, 1, "first call: total_agent_count = 1");

    // Register a second agent directly in the registry — bypasses HTTP so the
    // cache write path is not triggered, leaving the cached overview stale.
    env.agent_registry
        .register(root_agent(G2, Some(TEAM)))
        .expect("register G2");

    // Second call within the TTL window (well under 500 ms) — must serve the
    // cached (stale) result; total_agent_count stays 1, not 2.
    let body2: serde_json::Value = reqwest::get(&url)
        .await
        .expect("second GET overview within TTL")
        .json()
        .await
        .expect("second overview JSON");
    assert_eq!(
        body2["total_agent_count"], first_count,
        "second call within TTL window should serve stale cache (count still 1, not 2)"
    );
}
