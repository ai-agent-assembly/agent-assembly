//! Unit tests for the TopologyService skeleton — each RPC must return Code::Unimplemented.

use std::net::SocketAddr;
use std::sync::Arc;

use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::TopologyServiceImpl;
use aa_proto::assembly::topology::v1::topology_service_client::TopologyServiceClient;
use aa_proto::assembly::topology::v1::topology_service_server::TopologyServiceServer;
use aa_proto::assembly::topology::v1::{GetAgentTreeRequest, GetLineageRequest, GetTeamMembersRequest};
use tokio::net::TcpListener;
use tonic::transport::Server;
use tonic::Code;

// ── Helper ─────────────────────────────────────────────────────────────────

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

// ── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_agent_tree_returns_unimplemented() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let status = client
        .get_agent_tree(GetAgentTreeRequest {
            agent_id: "deadbeef".into(),
            max_depth: 0,
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), Code::Unimplemented);
}

#[tokio::test]
async fn get_lineage_returns_unimplemented() {
    let (addr, _registry) = start_server().await;
    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let status = client
        .get_lineage(GetLineageRequest {
            agent_id: "deadbeef".into(),
        })
        .await
        .unwrap_err();

    assert_eq!(status.code(), Code::Unimplemented);
}

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
