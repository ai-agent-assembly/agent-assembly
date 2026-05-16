//! Topology scenario builders for the integration-test harness (AAASM-1079 / ST-3).
//!
//! Registers fixed agent records directly into the harness's shared
//! `Arc<AgentRegistry>`. The ticket text envisaged the SDK driver populating
//! the registry over the wire; the actual codebase only exposes registration
//! via gRPC (`aa-gateway::server::serve_tcp`), and the in-process axum
//! harness deliberately stays HTTP-only. Direct registry insertion is the
//! pragmatic equivalent — it produces the same `AgentRecord` shape the REST
//! endpoint (`GET /api/v1/topology/tree/{root_id}`) and CLI (`aasm topology
//! tree`) read from. The ST-3 PR description documents the divergence and
//! how `tests/common/sdk_driver.rs` (shipped in ST-2) is exercised in the
//! ST-2 hermetic selftest instead.

use std::collections::{BTreeMap, VecDeque};

use aa_gateway::registry::{AgentRecord, AgentStatus};

use super::TopologyTestEnv;

/// Team id used by ST-3's three assertion tests.
pub const TEAM_ID: &str = "topology-it";

/// Raw 16-byte UUID for the parent agent registered by [`register_parent_child`].
pub const PARENT_AGENT_ID: [u8; 16] = [0x11; 16];

/// Raw 16-byte UUID for the child agent registered by [`register_parent_child`].
pub const CHILD_AGENT_ID: [u8; 16] = [0x22; 16];

/// Render a 16-byte agent id as the 32-char lowercase hex string used by
/// `aa-api`'s topology endpoints (see `aa_api::models::topology::format_id`).
pub fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Insert a parent + child pair into the harness's registry. Returns the
/// raw agent ids for the assertion module to consume.
///
/// Idempotent — subsequent calls return the same ids without re-inserting
/// (the registry would otherwise reject duplicate IDs).
pub fn register_parent_child(env: &TopologyTestEnv) -> ([u8; 16], [u8; 16]) {
    let registry = &env.agent_registry;

    if registry.get(&PARENT_AGENT_ID).is_none() {
        registry
            .register(make_record(
                PARENT_AGENT_ID,
                /* parent_key */ None,
                /* depth */ 0,
                /* root */ Some(PARENT_AGENT_ID),
                /* parent_agent_id string */ None,
            ))
            .expect("register parent agent");
    }

    if registry.get(&CHILD_AGENT_ID).is_none() {
        registry
            .register(make_record(
                CHILD_AGENT_ID,
                /* parent_key */ Some(PARENT_AGENT_ID),
                /* depth */ 1,
                /* root */ Some(PARENT_AGENT_ID),
                /* parent_agent_id string */ Some(hex_id(&PARENT_AGENT_ID)),
            ))
            .expect("register child agent");
    }

    (PARENT_AGENT_ID, CHILD_AGENT_ID)
}

fn make_record(
    id: [u8; 16],
    parent_key: Option<[u8; 16]>,
    depth: u32,
    root_agent_id: Option<[u8; 16]>,
    parent_agent_id: Option<String>,
) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: format!("topology-it-{}", &hex_id(&id)[..8]),
        framework: "topology-it".into(),
        version: "0.0.1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "deadbeef".into(),
        credential_token: "topology-it-token".into(),
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
        parent_agent_id,
        team_id: Some(TEAM_ID.to_string()),
        depth,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id,
        children: vec![],
        parent_key,
    }
}
