//! Integration test: LangGraph node→node edge emission (AAASM-940 AC 7b).
//!
//! Simulates the LangGraph adapter calling ReportEdge when it detects a
//! node→node message transition. Verifies that a `Messages` edge is stored
//! correctly in the InMemoryEdgeRepo via the topology gRPC service.

use std::sync::Arc;

use aa_core::identity::AgentId;
use aa_core::topology::{EdgeRepo, EdgeType};
use aa_gateway::edges::InMemoryEdgeRepo;
use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::TopologyServiceImpl;
use aa_proto::assembly::topology::v1::{topology_service_server::TopologyService, ReportEdgeRequest};
use tonic::Request;

fn agent_id(b: u8) -> ([u8; 16], String) {
    let mut bytes = [0u8; 16];
    bytes[15] = b;
    let hex = bytes.iter().map(|x| format!("{x:02x}")).collect::<String>();
    (bytes, hex)
}

fn make_service() -> (TopologyServiceImpl, InMemoryEdgeRepo) {
    let repo = InMemoryEdgeRepo::new();
    let registry = Arc::new(AgentRegistry::new());
    let svc = TopologyServiceImpl::new(registry, repo.clone());
    (svc, repo)
}

/// Simulates a LangGraph node→node transition emitting a `messages` edge.
/// The LangGraph adapter detects a `node_a → node_b` message transition and
/// calls `ReportEdge` with `edge_type = "messages"`.
#[tokio::test]
async fn langgraph_node_to_node_messages_edge_is_stored() {
    let (svc, repo) = make_service();

    let (_, source_hex) = agent_id(0x01);
    let (_, target_hex) = agent_id(0x02);

    // Simulate the LangGraph adapter calling ReportEdge on node→node transition.
    let resp = svc
        .report_edge(Request::new(ReportEdgeRequest {
            source_agent_id: source_hex.clone(),
            target_agent_id: target_hex.clone(),
            edge_type: "messages".to_string(),
            metadata_json: r#"{"graph":"order_pipeline","node":"fulfillment"}"#.to_string(),
        }))
        .await
        .expect("report_edge should succeed");

    let edge_id = resp.into_inner().id;
    assert!(edge_id > 0, "auto-assigned id must be positive");

    // Verify the edge was persisted in the shared repo.
    let (source_bytes, _) = agent_id(0x01);
    let source_agent = AgentId::from_bytes(source_bytes);
    let outgoing = repo
        .list_outgoing(source_agent, Some(EdgeType::Messages), 10)
        .await
        .unwrap();

    assert_eq!(outgoing.len(), 1, "exactly one Messages edge should be stored");
    let stored = &outgoing[0];
    assert_eq!(stored.id, edge_id);
    assert_eq!(stored.edge_type, EdgeType::Messages);
    let meta = stored.metadata.as_ref().expect("metadata should be set");
    assert_eq!(meta["graph"], "order_pipeline");
}

/// Simulates the OpenAI Agents adapter emitting a `delegates_to` edge on handoff.
#[tokio::test]
async fn openai_agents_handoff_delegates_to_edge_is_stored() {
    let (svc, repo) = make_service();

    let (_, orchestrator_hex) = agent_id(0xA0);
    let (_, worker_hex) = agent_id(0xB0);

    svc.report_edge(Request::new(ReportEdgeRequest {
        source_agent_id: orchestrator_hex.clone(),
        target_agent_id: worker_hex.clone(),
        edge_type: "delegates_to".to_string(),
        metadata_json: r#"{"reason":"task_specialization"}"#.to_string(),
    }))
    .await
    .expect("delegates_to edge should be recorded");

    let (orchestrator_bytes, _) = agent_id(0xA0);
    let orchestrator = AgentId::from_bytes(orchestrator_bytes);
    let outgoing = repo
        .list_outgoing(orchestrator, Some(EdgeType::DelegatesTo), 10)
        .await
        .unwrap();

    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].edge_type, EdgeType::DelegatesTo);
}

/// Simulates the MCP tool-call interceptor emitting a `calls` edge.
#[tokio::test]
async fn mcp_tool_call_calls_edge_is_stored() {
    let (svc, repo) = make_service();

    let (_, caller_hex) = agent_id(0xC0);
    let (_, tool_hex) = agent_id(0xD0);

    svc.report_edge(Request::new(ReportEdgeRequest {
        source_agent_id: caller_hex.clone(),
        target_agent_id: tool_hex.clone(),
        edge_type: "calls".to_string(),
        metadata_json: r#"{"tool":"web_search","mcp_server":"search-mcp"}"#.to_string(),
    }))
    .await
    .expect("calls edge should be recorded");

    let (caller_bytes, _) = agent_id(0xC0);
    let caller = AgentId::from_bytes(caller_bytes);
    let outgoing = repo.list_outgoing(caller, Some(EdgeType::Calls), 10).await.unwrap();

    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].edge_type, EdgeType::Calls);
    let meta = outgoing[0].metadata.as_ref().unwrap();
    assert_eq!(meta["mcp_server"], "search-mcp");
}

/// Direct InMemoryEdgeRepo test — all six edge types accepted.
#[tokio::test]
async fn all_six_edge_types_round_trip_via_report_edge() {
    let (svc, repo) = make_service();

    let types = ["delegates_to", "calls", "reads", "writes", "approves", "messages"];

    for (i, edge_type) in types.iter().enumerate() {
        let (src_bytes, _) = agent_id((0x10 + i) as u8);
        let (tgt_bytes, _) = agent_id((0x20 + i) as u8);
        let src_hex = src_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let tgt_hex = tgt_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();

        let resp = svc
            .report_edge(Request::new(ReportEdgeRequest {
                source_agent_id: src_hex,
                target_agent_id: tgt_hex,
                edge_type: edge_type.to_string(),
                metadata_json: String::new(),
            }))
            .await
            .unwrap_or_else(|e| panic!("edge_type {edge_type} failed: {e}"));

        assert!(resp.into_inner().id > 0);

        let src_agent = AgentId::from_bytes(src_bytes);
        let outgoing = repo.list_outgoing(src_agent, None, 10).await.unwrap();
        assert_eq!(outgoing.len(), 1, "expected one edge for type {edge_type}");
    }
}
