//! Tests for the TopologyService gRPC handlers.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::TopologyServiceImpl;
use aa_proto::assembly::topology::v1::topology_service_client::TopologyServiceClient;
use aa_proto::assembly::topology::v1::topology_service_server::TopologyServiceServer;
use aa_proto::assembly::topology::v1::{GetAgentTreeRequest, GetLineageRequest, GetTeamMembersRequest};
use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic::Code;

// ── Helpers ────────────────────────────────────────────────────────────────

async fn start_server() -> (SocketAddr, Arc<AgentRegistry>) {
    let registry = Arc::new(AgentRegistry::new());
    let service = TopologyServiceImpl::new(Arc::clone(&registry));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(TopologyServiceServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    (addr, registry)
}

fn make_record(
    id: [u8; 16],
    name: &str,
    depth: u32,
    parent_key: Option<[u8; 16]>,
    team_id: Option<&str>,
) -> AgentRecord {
    AgentRecord {
        agent_id: id,
        name: name.into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_test".into(),
        credential_token: "tok_test".into(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: std::collections::VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: team_id.map(str::to_owned),
        depth,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some(id),
        children: vec![],
        parent_key,
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    hex::encode(id)
}

// ── GetAgentTree tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn get_agent_tree_not_found_for_unknown_agent() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let unknown_id = hex_id(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let err = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: unknown_id,
            max_depth: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn get_agent_tree_invalid_hex_returns_invalid_argument() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let err = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: "not-valid-hex!!".into(),
            max_depth: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn get_agent_tree_single_root_no_children() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [1u8; 16];
    registry
        .register(make_record(root_id, "root-agent", 0, None, None))
        .unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: hex_id(&root_id),
            max_depth: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let root_node = resp.root.expect("root node missing");
    let agent = root_node.agent.expect("root agent missing");
    assert_eq!(agent.id, hex_id(&root_id));
    assert_eq!(agent.name, "root-agent");
    assert_eq!(agent.depth, 0);
    assert_eq!(agent.status, "active");
    assert!(root_node.children.is_empty());
}

#[tokio::test]
async fn get_agent_tree_includes_children_unlimited_depth() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [2u8; 16];
    let child_id: [u8; 16] = [3u8; 16];

    registry.register(make_record(root_id, "root", 0, None, None)).unwrap();

    let mut child_record = make_record(child_id, "child", 1, Some(root_id), None);
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // max_depth == 0 means unlimited
    let resp = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: hex_id(&root_id),
            max_depth: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let root_node = resp.root.expect("root node missing");
    assert_eq!(root_node.children.len(), 1);
    let child_node = &root_node.children[0];
    let child_agent = child_node.agent.as_ref().expect("child agent missing");
    assert_eq!(child_agent.id, hex_id(&child_id));
    assert_eq!(child_agent.depth, 1);
}

#[tokio::test]
async fn get_agent_tree_max_depth_limits_traversal() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [4u8; 16];
    let child_id: [u8; 16] = [5u8; 16];
    let grandchild_id: [u8; 16] = [6u8; 16];

    registry.register(make_record(root_id, "root", 0, None, None)).unwrap();

    let mut child_record = make_record(child_id, "child", 1, Some(root_id), None);
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut grandchild_record = make_record(grandchild_id, "grandchild", 2, Some(child_id), None);
    grandchild_record.root_agent_id = Some(root_id);
    registry.register(grandchild_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // max_depth == 1: root + its direct children, but NOT grandchildren
    let resp = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: hex_id(&root_id),
            max_depth: 1,
        })
        .await
        .unwrap()
        .into_inner();

    let root_node = resp.root.expect("root node missing");
    assert_eq!(root_node.children.len(), 1);
    // Grandchildren should be absent because depth was capped at 1.
    assert!(root_node.children[0].children.is_empty());
}

#[tokio::test]
async fn get_agent_tree_returns_failed_precondition_for_non_root_agent() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [0x10; 16];
    let child_id: [u8; 16] = [0x11; 16];

    registry.register(make_record(root_id, "root", 0, None, None)).unwrap();

    let mut child_record = make_record(child_id, "child", 1, Some(root_id), None);
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: hex_id(&child_id),
            max_depth: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::FailedPrecondition);
}

// ── GetLineage tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn get_lineage_not_found_for_unknown_agent() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let unknown_id = hex_id(&[0xaa, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let err = client
        .get_lineage(GetLineageRequest { agent_id: unknown_id })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn get_lineage_root_agent_returns_self_only() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [7u8; 16];
    registry
        .register(make_record(root_id, "standalone-root", 0, None, None))
        .unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .get_lineage(GetLineageRequest {
            agent_id: hex_id(&root_id),
        })
        .await
        .unwrap()
        .into_inner();

    // ancestors[0] is the agent itself; no parents exist for a root agent.
    assert_eq!(resp.ancestors.len(), 1);
    assert_eq!(resp.ancestors[0].id, hex_id(&root_id));
    assert_eq!(resp.ancestors[0].name, "standalone-root");
    assert_eq!(resp.ancestors[0].depth, 0);
}

#[tokio::test]
async fn get_lineage_sub_agent_includes_parent_chain() {
    let (addr, registry) = start_server().await;

    let root_id: [u8; 16] = [8u8; 16];
    let child_id: [u8; 16] = [9u8; 16];

    registry
        .register(make_record(root_id, "chain-root", 0, None, None))
        .unwrap();

    let mut child_record = make_record(child_id, "chain-child", 1, Some(root_id), None);
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .get_lineage(GetLineageRequest {
            agent_id: hex_id(&child_id),
        })
        .await
        .unwrap()
        .into_inner();

    // ancestors[0] = child itself, ancestors[1] = root parent
    assert_eq!(resp.ancestors.len(), 2);
    assert_eq!(resp.ancestors[0].id, hex_id(&child_id));
    assert_eq!(resp.ancestors[0].depth, 1);
    assert_eq!(resp.ancestors[1].id, hex_id(&root_id));
    assert_eq!(resp.ancestors[1].depth, 0);
}

// ── GetTeamMembers tests ───────────────────────────────────────────────────

#[tokio::test]
async fn get_team_members_empty_team_id_returns_invalid_argument() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let err = client
        .get_team_members(GetTeamMembersRequest { team_id: String::new() })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn get_team_members_not_found_for_unknown_team() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let err = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "no-such-team".into(),
        })
        .await
        .unwrap_err();

    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test]
async fn get_team_members_returns_agents_sorted_by_agent_id() {
    let (addr, registry) = start_server().await;

    // 0xa0... < 0xa1... lexicographically, so root sorts before child.
    let root_id: [u8; 16] = [0xa0; 16];
    let child_id: [u8; 16] = [0xa1; 16];

    registry
        .register(make_record(root_id, "alpha-root", 0, None, Some("alpha-team")))
        .unwrap();

    let mut child_record = make_record(child_id, "alpha-child", 1, Some(root_id), Some("alpha-team"));
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "alpha-team".into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.members.len(), 2);
    assert_eq!(resp.members[0].team_id, "alpha-team");
    // Sorted by agent_id string: a0a0... < a1a1..., so root agent comes first.
    assert_eq!(resp.members[0].id, hex_id(&root_id));
    assert_eq!(resp.members[1].id, hex_id(&child_id));
}

// ── Integration test ───────────────────────────────────────────────────────

/// Seeds a 3-level, 2-team registry and calls all three topology RPCs in one
/// test to assert cross-RPC consistency.
///
/// Fixture:
///   root  (depth 0, team-one)
///   └── child      (depth 1, team-one)
///       └── grandchild (depth 2, team-two)
#[tokio::test]
async fn topology_all_rpcs_3level_2team_fixture() {
    let (addr, registry) = start_server().await;

    // IDs chosen so that b0... < b1... < b2... for deterministic sort checks.
    let root_id: [u8; 16] = [0xb0; 16];
    let child_id: [u8; 16] = [0xb1; 16];
    let grandchild_id: [u8; 16] = [0xb2; 16];

    registry
        .register(make_record(root_id, "root", 0, None, Some("team-one")))
        .unwrap();

    let mut child_record = make_record(child_id, "child", 1, Some(root_id), Some("team-one"));
    child_record.root_agent_id = Some(root_id);
    registry.register(child_record).unwrap();

    let mut grandchild_record = make_record(grandchild_id, "grandchild", 2, Some(child_id), Some("team-two"));
    grandchild_record.root_agent_id = Some(root_id);
    registry.register(grandchild_record).unwrap();

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // ── GetAgentTree ──────────────────────────────────────────────────────
    let tree_resp = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: hex_id(&root_id),
            max_depth: 0,
        })
        .await
        .unwrap()
        .into_inner();

    let root_node = tree_resp.root.expect("root node missing");
    assert_eq!(root_node.agent.as_ref().unwrap().id, hex_id(&root_id));
    assert_eq!(root_node.children.len(), 1);
    let child_node = &root_node.children[0];
    assert_eq!(child_node.agent.as_ref().unwrap().id, hex_id(&child_id));
    assert_eq!(child_node.children.len(), 1);
    let grandchild_node = &child_node.children[0];
    assert_eq!(grandchild_node.agent.as_ref().unwrap().id, hex_id(&grandchild_id));
    assert!(grandchild_node.children.is_empty());

    // ── GetLineage ────────────────────────────────────────────────────────
    let lineage_resp = client
        .get_lineage(GetLineageRequest {
            agent_id: hex_id(&grandchild_id),
        })
        .await
        .unwrap()
        .into_inner();

    // ancestors[0] = grandchild, [1] = child, [2] = root
    assert_eq!(lineage_resp.ancestors.len(), 3);
    assert_eq!(lineage_resp.ancestors[0].id, hex_id(&grandchild_id));
    assert_eq!(lineage_resp.ancestors[1].id, hex_id(&child_id));
    assert_eq!(lineage_resp.ancestors[2].id, hex_id(&root_id));

    // ── GetTeamMembers("team-one") ────────────────────────────────────────
    let team_one_resp = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "team-one".into(),
        })
        .await
        .unwrap()
        .into_inner();

    // root (b0...) and child (b1...) — sorted by agent_id
    assert_eq!(team_one_resp.members.len(), 2);
    assert_eq!(team_one_resp.members[0].id, hex_id(&root_id));
    assert_eq!(team_one_resp.members[1].id, hex_id(&child_id));

    // ── GetTeamMembers("team-two") ────────────────────────────────────────
    let team_two_resp = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "team-two".into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(team_two_resp.members.len(), 1);
    assert_eq!(team_two_resp.members[0].id, hex_id(&grandchild_id));
    assert_eq!(team_two_resp.members[0].team_id, "team-two");
}
