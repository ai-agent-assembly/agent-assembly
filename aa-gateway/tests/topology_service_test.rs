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

// ── GetTeamMembers stub test ───────────────────────────────────────────────

#[tokio::test]
async fn get_team_members_returns_unimplemented() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let status = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "team-alpha".into(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), Code::Unimplemented);
}
