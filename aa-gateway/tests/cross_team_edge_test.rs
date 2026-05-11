//! Integration tests for cross-team edge event publishing (AAASM-1001).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use aa_core::identity::AgentId;
use aa_core::topology::{EdgeRepo, EdgeType, NewEdge};
use aa_gateway::edges::{CrossTeamEdgeEvent, InMemoryEdgeRepo};
use aa_gateway::registry::{AgentRecord, AgentRegistry, AgentStatus};
use chrono::Utc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn agent_id(n: u8) -> AgentId {
    AgentId::from_bytes([n; 16])
}

fn make_record(n: u8, team_id: Option<&str>) -> AgentRecord {
    AgentRecord {
        agent_id: [n; 16],
        name: format!("agent-{n}"),
        framework: "test".into(),
        version: "0.0.1".into(),
        risk_tier: 1,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: "tok".into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
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
        team_id: team_id.map(str::to_string),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: Some([n; 16]),
        children: vec![],
        parent_key: None,
    }
}

async fn recv_with_timeout(
    rx: &mut tokio::sync::broadcast::Receiver<CrossTeamEdgeEvent>,
) -> Option<CrossTeamEdgeEvent> {
    tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .ok()
        .and_then(|r| r.ok())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_team_edge_publishes_event() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(make_record(0x01, Some("team-alpha"))).unwrap();
    registry.register(make_record(0x02, Some("team-beta"))).unwrap();

    let (repo, mut rx) = InMemoryEdgeRepo::with_events(registry);

    let edge_id = repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x02),
            edge_type: EdgeType::Messages,
            metadata: None,
        })
        .await
        .unwrap();

    let event = recv_with_timeout(&mut rx)
        .await
        .expect("expected CrossTeamEdgeEvent within 100ms");

    assert_eq!(event.edge_id, edge_id);
    assert_eq!(event.source_agent_id, agent_id(0x01));
    assert_eq!(event.target_agent_id, agent_id(0x02));
    assert_eq!(event.source_team_id, "team-alpha");
    assert_eq!(event.target_team_id, "team-beta");
    assert_eq!(event.edge_type, EdgeType::Messages);
}

#[tokio::test]
async fn same_team_edge_does_not_publish() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(make_record(0x01, Some("team-alpha"))).unwrap();
    registry.register(make_record(0x02, Some("team-alpha"))).unwrap();

    let (repo, mut rx) = InMemoryEdgeRepo::with_events(registry);

    repo.insert(NewEdge {
        source: agent_id(0x01),
        target: agent_id(0x02),
        edge_type: EdgeType::Messages,
        metadata: None,
    })
    .await
    .unwrap();

    assert!(
        recv_with_timeout(&mut rx).await.is_none(),
        "same-team edge must not publish a CrossTeamEdgeEvent"
    );
}

#[tokio::test]
async fn null_team_id_does_not_publish_event() {
    let registry = Arc::new(AgentRegistry::new());
    // source has a team, target does not
    registry.register(make_record(0x01, Some("team-alpha"))).unwrap();
    registry.register(make_record(0x02, None)).unwrap();

    let (repo, mut rx) = InMemoryEdgeRepo::with_events(registry);

    repo.insert(NewEdge {
        source: agent_id(0x01),
        target: agent_id(0x02),
        edge_type: EdgeType::DelegatesTo,
        metadata: None,
    })
    .await
    .unwrap();

    assert!(
        recv_with_timeout(&mut rx).await.is_none(),
        "edge with one null team_id must not publish a CrossTeamEdgeEvent"
    );
}

#[tokio::test]
async fn event_payload_contains_correct_edge_type() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(make_record(0x01, Some("team-a"))).unwrap();
    registry.register(make_record(0x02, Some("team-b"))).unwrap();

    let (repo, mut rx) = InMemoryEdgeRepo::with_events(registry);

    repo.insert(NewEdge {
        source: agent_id(0x01),
        target: agent_id(0x02),
        edge_type: EdgeType::DelegatesTo,
        metadata: None,
    })
    .await
    .unwrap();

    let event = recv_with_timeout(&mut rx).await.expect("expected event");
    assert_eq!(event.edge_type, EdgeType::DelegatesTo);
}

#[tokio::test]
async fn repo_without_events_still_inserts_correctly() {
    let repo = InMemoryEdgeRepo::new();
    assert!(repo.subscribe_cross_team_events().is_none());

    let id = repo
        .insert(NewEdge {
            source: agent_id(0x01),
            target: agent_id(0x02),
            edge_type: EdgeType::Calls,
            metadata: None,
        })
        .await
        .unwrap();

    let edges = repo.list_outgoing(agent_id(0x01), None, 10).await.unwrap();
    assert_eq!(edges.len(), 1);
    assert_eq!(edges[0].id, id);
}
