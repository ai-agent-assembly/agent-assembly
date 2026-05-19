//! AAASM-1524 / ST-L — E2E: Topology hierarchy + topology-aware policy.
//!
//! Covers two surfaces:
//!
//! ## Topology structure (tests 1–4)
//!
//! Seeds a 1+3+6 = 10-agent three-tier tree directly into the harness's
//! `Arc<AgentRegistry>` and exercises:
//!   - `GET /api/v1/topology/tree/{root}` — fan-out shape at each tier
//!   - `GET /api/v1/topology/lineage/{leaf}` — root-first ancestor chain
//!   - `GET /api/v1/topology/team/{team}` — full membership count
//!   - `GET /api/v1/topology/tree/{mid}` — subtree from a non-root node
//!
//! ## Topology-aware policy (tests 5–6)
//!
//! Loads `tests/common/fixtures/policies/topology_aware.yaml` via
//! `PolicyEngine::load_from_file` and attaches the harness registry so the
//! `agent.depth` variable resolves from real registry records.
//! Verifies that:
//!   - A depth-0 agent calling `delete` → `Allow`
//!   - A depth-2 agent calling `delete` → `RequiresApproval`
//!
//! ## Re-parenting (test 7)
//!
//! Marked `#[ignore]` — `AgentRegistry` does not yet implement re-parenting.

mod common;

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::registry::{AgentRecord, AgentStatus};
use common::TopologyTestEnv;

const TEAM: &str = "e2e-topology-it";

// ── 10-agent tree IDs (tests 1–4) ────────────────────────────────────────────
const ROOT: [u8; 16] = [0x10; 16];
const MID1: [u8; 16] = [0x11; 16];
const MID2: [u8; 16] = [0x12; 16];
const MID3: [u8; 16] = [0x13; 16];
const LEAF1: [u8; 16] = [0x21; 16]; // child of MID1
const LEAF2: [u8; 16] = [0x22; 16]; // child of MID1
const LEAF3: [u8; 16] = [0x23; 16]; // child of MID2
const LEAF4: [u8; 16] = [0x24; 16]; // child of MID2
const LEAF5: [u8; 16] = [0x25; 16]; // child of MID3
const LEAF6: [u8; 16] = [0x26; 16]; // child of MID3

// ── Policy evaluation IDs (tests 5–6) ────────────────────────────────────────
const DEPTH0_AGENT: [u8; 16] = [0xB0; 16];
const DEPTH2_AGENT: [u8; 16] = [0xB2; 16];

// ── Helpers ───────────────────────────────────────────────────────────────────

fn hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_record(
    id: [u8; 16],
    depth: u32,
    parent_key: Option<[u8; 16]>,
    root_agent_id: Option<[u8; 16]>,
    parent_agent_id: Option<String>,
) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: format!("e2e-topo-{}", &hex(&id)[..8]),
        framework: "e2e-topology-it".into(),
        version: "0.0.1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "deadbeef".into(),
        credential_token: "e2e-topology-token".into(),
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
        governance_level: GovernanceLevel::default(),
        parent_agent_id,
        team_id: Some(TEAM.to_string()),
        depth,
        delegation_reason: if depth > 0 {
            Some("e2e-test-delegation".into())
        } else {
            None
        },
        spawned_by_tool: None,
        root_agent_id,
        children: vec![],
        parent_key,
    }
}

fn seed_ten_agent_tree(env: &TopologyTestEnv) {
    env.agent_registry
        .register(make_record(ROOT, 0, None, Some(ROOT), None))
        .expect("register ROOT");

    for mid in [MID1, MID2, MID3] {
        env.agent_registry
            .register(make_record(mid, 1, Some(ROOT), Some(ROOT), Some(hex(&ROOT))))
            .expect("register mid agent");
    }

    let leaf_pairs = [
        (LEAF1, MID1),
        (LEAF2, MID1),
        (LEAF3, MID2),
        (LEAF4, MID2),
        (LEAF5, MID3),
        (LEAF6, MID3),
    ];
    for (leaf, parent) in leaf_pairs {
        env.agent_registry
            .register(make_record(leaf, 2, Some(parent), Some(ROOT), Some(hex(&parent))))
            .expect("register leaf agent");
    }
}

fn make_topology_engine(env: &TopologyTestEnv) -> PolicyEngine {
    let policy_path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/common/fixtures/policies/topology_aware.yaml");
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(1);
    PolicyEngine::load_from_file(&policy_path, alert_tx)
        .expect("topology_aware.yaml should load without errors")
        .with_registry(Arc::clone(&env.agent_registry))
}

fn make_agent_ctx(agent_id: [u8; 16]) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(agent_id),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(TEAM.to_string()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

/// A 3-tier 1+3+6 tree produces the correct fan-out at each level via the
/// `GET /api/v1/topology/tree/{root}` endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn tree_endpoint_for_three_tier_hierarchy_returns_correct_fan_out() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    seed_ten_agent_tree(&env);

    let url = format!("{}/api/v1/topology/tree/{}", env.base_url(), hex(&ROOT));
    let resp = reqwest::get(&url).await.expect("GET tree should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let tree: serde_json::Value = resp.json().await.expect("tree should parse as JSON");

    assert_eq!(tree["id"], hex(&ROOT), "root id should match ROOT");
    assert_eq!(tree["depth"], 0, "root depth should be 0");

    let root_children = tree["children"].as_array().expect("root.children should be an array");
    assert_eq!(root_children.len(), 3, "root should have exactly 3 mid-tier children");

    for child in root_children {
        assert_eq!(child["depth"], 1, "mid-tier agent depth should be 1");
        let grandchildren = child["children"].as_array().expect("mid.children should be an array");
        assert_eq!(
            grandchildren.len(),
            2,
            "each mid agent should have exactly 2 leaf children"
        );
        for grandchild in grandchildren {
            assert_eq!(grandchild["depth"], 2, "leaf depth should be 2");
            let great_grandchildren = grandchild["children"]
                .as_array()
                .expect("leaf.children should be array");
            assert!(
                great_grandchildren.is_empty(),
                "leaf nodes should have no further children"
            );
        }
    }
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

/// `GET /api/v1/topology/lineage/{leaf}` returns the full ancestor chain
/// root-first: `[ROOT, MID1, LEAF1]`.
#[tokio::test(flavor = "multi_thread")]
async fn lineage_endpoint_returns_full_ancestor_chain_root_first() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    seed_ten_agent_tree(&env);

    let url = format!("{}/api/v1/topology/lineage/{}", env.base_url(), hex(&LEAF1));
    let resp = reqwest::get(&url).await.expect("GET lineage should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("lineage should parse as JSON");

    assert_eq!(body["agent_id"], hex(&LEAF1), "subject agent id should be LEAF1");
    assert_eq!(
        body["ancestor_count"], 3,
        "chain length should be 3 (root + mid + leaf)"
    );

    let ancestors = body["ancestors"].as_array().expect("ancestors should be an array");
    assert_eq!(ancestors.len(), 3);
    assert_eq!(ancestors[0]["id"], hex(&ROOT), "ancestors[0] should be ROOT");
    assert_eq!(ancestors[0]["depth"], 0, "ROOT depth = 0");
    assert_eq!(ancestors[1]["id"], hex(&MID1), "ancestors[1] should be MID1");
    assert_eq!(ancestors[1]["depth"], 1, "MID1 depth = 1");
    assert_eq!(ancestors[2]["id"], hex(&LEAF1), "ancestors[2] should be LEAF1 itself");
    assert_eq!(ancestors[2]["depth"], 2, "LEAF1 depth = 2");
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

/// `GET /api/v1/topology/team/{team}` returns all 10 agents registered under
/// the shared team id.
#[tokio::test(flavor = "multi_thread")]
async fn team_endpoint_returns_all_ten_agents_sharing_same_team() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    seed_ten_agent_tree(&env);

    let url = format!("{}/api/v1/topology/team/{TEAM}", env.base_url());
    let resp = reqwest::get(&url).await.expect("GET team should succeed");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("team should parse as JSON");

    assert_eq!(body["team_id"], TEAM, "team_id should match");
    assert_eq!(
        body["agent_count"], 10,
        "all 10 seeded agents should belong to the team"
    );
    let members = body["members"].as_array().expect("members should be an array");
    assert_eq!(members.len(), 10, "members list length should equal 10");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

/// `GET /api/v1/topology/tree/{mid}` returns 422 when the queried agent is
/// not a root (depth > 0). The endpoint is root-only by design; callers
/// must always pass the root agent id.
#[tokio::test(flavor = "multi_thread")]
async fn tree_for_non_root_agent_returns_422() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    seed_ten_agent_tree(&env);

    // MID1 is depth 1 — not a root. The tree endpoint must reject it.
    let url = format!("{}/api/v1/topology/tree/{}", env.base_url(), hex(&MID1));
    let resp = reqwest::get(&url).await.expect("GET tree from MID1 should complete");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "tree endpoint should return 422 for a non-root agent"
    );
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

/// A depth-0 (root) agent calling `delete` is allowed without approval: the
/// `requires_approval_if: "agent.depth >= 2"` condition in
/// `topology_aware.yaml` does not fire at depth 0.
#[tokio::test(flavor = "multi_thread")]
async fn policy_allows_delete_tool_at_depth_zero() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    env.agent_registry
        .register(make_record(DEPTH0_AGENT, 0, None, Some(DEPTH0_AGENT), None))
        .expect("register depth-0 agent");

    let engine = make_topology_engine(&env);
    let ctx = make_agent_ctx(DEPTH0_AGENT);
    let action = GovernanceAction::ToolCall {
        name: "delete".into(),
        args: "{}".into(),
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert_eq!(
        result,
        PolicyResult::Allow,
        "depth-0 agent calling 'delete' should be allowed without approval (got {result:?})"
    );
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

/// A depth-2 (grandchild) agent calling `delete` triggers the
/// `requires_approval_if: "agent.depth >= 2"` condition and must return
/// `RequiresApproval`.
#[tokio::test(flavor = "multi_thread")]
async fn policy_requires_approval_for_delete_at_depth_two() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Register a synthetic parent chain so the depth-2 agent has a valid record.
    env.agent_registry
        .register(make_record(
            DEPTH2_AGENT,
            2,
            Some([0xB1; 16]),
            Some(DEPTH0_AGENT),
            Some(hex(&[0xB1; 16])),
        ))
        .expect("register depth-2 agent");

    let engine = make_topology_engine(&env);
    let ctx = make_agent_ctx(DEPTH2_AGENT);
    let action = GovernanceAction::ToolCall {
        name: "delete".into(),
        args: "{}".into(),
    };

    let result = engine.evaluate(&ctx, &action).decision;
    assert!(
        matches!(result, PolicyResult::RequiresApproval { .. }),
        "depth-2 agent calling 'delete' should require approval (got {result:?})"
    );
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

/// When an agent is re-parented its depth changes; a topology-aware policy
/// should reflect the new depth immediately on the next `evaluate()` call.
///
/// Marked `#[ignore]` because `AgentRegistry` does not yet implement
/// re-parenting. Unblock by implementing `AgentRegistry::reparent`.
#[ignore = "re-parenting not implemented in AgentRegistry (follow-up ticket pending)"]
#[tokio::test(flavor = "multi_thread")]
async fn policy_evaluates_against_current_topology_after_reparent() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let _ = env;
    unimplemented!("blocked: AgentRegistry::reparent not available");
}
