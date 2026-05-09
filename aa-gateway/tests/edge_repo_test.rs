//! Integration tests for `InMemoryEdgeRepo` (AAASM-985).

use aa_core::topology::{EdgeRepo, EdgeType, NewEdge};
use aa_gateway::edges::InMemoryEdgeRepo;
use chrono::Utc;

fn agent(n: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = n;
    id
}

fn edge(src: u8, tgt: u8, edge_type: EdgeType) -> NewEdge {
    NewEdge {
        source_agent_id: agent(src),
        target_agent_id: agent(tgt),
        edge_type,
        metadata: None,
    }
}

#[tokio::test]
async fn ids_are_monotonically_increasing() {
    let repo = InMemoryEdgeRepo::new();
    let id1 = repo.insert(edge(1, 2, EdgeType::Calls)).await.unwrap();
    let id2 = repo.insert(edge(1, 3, EdgeType::Reads)).await.unwrap();
    let id3 = repo.insert(edge(2, 3, EdgeType::Writes)).await.unwrap();
    assert!(id1 < id2);
    assert!(id2 < id3);
}

#[tokio::test]
async fn list_outgoing_returns_newest_first() {
    let repo = InMemoryEdgeRepo::new();
    repo.insert(edge(1, 2, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(1, 3, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(1, 4, EdgeType::Calls)).await.unwrap();

    let results = repo.list_outgoing(agent(1), None, 10).await;
    assert_eq!(results.len(), 3);
    assert!(results[0].id > results[1].id, "newest should be first");
    assert!(results[1].id > results[2].id);
}

#[tokio::test]
async fn list_outgoing_filtered_by_edge_type() {
    let repo = InMemoryEdgeRepo::new();
    repo.insert(edge(1, 2, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(1, 3, EdgeType::Reads)).await.unwrap();
    repo.insert(edge(1, 4, EdgeType::Calls)).await.unwrap();

    let calls = repo.list_outgoing(agent(1), Some(EdgeType::Calls), 10).await;
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|e| e.edge_type == EdgeType::Calls));

    let reads = repo.list_outgoing(agent(1), Some(EdgeType::Reads), 10).await;
    assert_eq!(reads.len(), 1);
}

#[tokio::test]
async fn list_incoming_returns_only_edges_to_target() {
    let repo = InMemoryEdgeRepo::new();
    repo.insert(edge(1, 3, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(2, 3, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(1, 4, EdgeType::Calls)).await.unwrap();

    let incoming = repo.list_incoming(agent(3), None, 10).await;
    assert_eq!(incoming.len(), 2);
    assert!(incoming.iter().all(|e| e.target_agent_id == agent(3)));
}

#[tokio::test]
async fn list_incoming_filtered_by_edge_type() {
    let repo = InMemoryEdgeRepo::new();
    repo.insert(edge(1, 3, EdgeType::Calls)).await.unwrap();
    repo.insert(edge(2, 3, EdgeType::DelegatesTo)).await.unwrap();

    let calls = repo.list_incoming(agent(3), Some(EdgeType::Calls), 10).await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].source_agent_id, agent(1));
}

#[tokio::test]
async fn list_by_type_filters_by_type_and_since() {
    let repo = InMemoryEdgeRepo::new();
    let before = Utc::now();
    repo.insert(edge(1, 2, EdgeType::Messages)).await.unwrap();
    repo.insert(edge(2, 3, EdgeType::Approves)).await.unwrap();
    repo.insert(edge(3, 4, EdgeType::Messages)).await.unwrap();

    let messages = repo.list_by_type(EdgeType::Messages, before, 10).await;
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|e| e.edge_type == EdgeType::Messages));

    let approves = repo.list_by_type(EdgeType::Approves, before, 10).await;
    assert_eq!(approves.len(), 1);
}

#[tokio::test]
async fn list_by_type_since_excludes_older_records() {
    let repo = InMemoryEdgeRepo::new();
    repo.insert(edge(1, 2, EdgeType::Calls)).await.unwrap();
    let after_first = Utc::now();
    repo.insert(edge(2, 3, EdgeType::Calls)).await.unwrap();

    let all = repo
        .list_by_type(EdgeType::Calls, chrono::DateTime::UNIX_EPOCH, 10)
        .await;
    assert_eq!(all.len(), 2);

    let recent = repo.list_by_type(EdgeType::Calls, after_first, 10).await;
    assert_eq!(recent.len(), 1);
}

#[tokio::test]
async fn limit_is_capped_at_1000() {
    let repo = InMemoryEdgeRepo::new();
    for i in 0..1100u16 {
        repo.insert(NewEdge {
            source_agent_id: agent(1),
            target_agent_id: agent(2),
            edge_type: EdgeType::Calls,
            metadata: None,
        })
        .await
        .unwrap();
        let _ = i;
    }
    let results = repo.list_outgoing(agent(1), None, usize::MAX).await;
    assert_eq!(results.len(), 1000);
}

#[tokio::test]
async fn empty_repo_returns_empty_vecs() {
    let repo = InMemoryEdgeRepo::new();
    assert!(repo.list_outgoing(agent(1), None, 10).await.is_empty());
    assert!(repo.list_incoming(agent(1), None, 10).await.is_empty());
    assert!(repo
        .list_by_type(EdgeType::Calls, chrono::DateTime::UNIX_EPOCH, 10)
        .await
        .is_empty());
}

#[tokio::test]
async fn all_six_edge_types_are_accepted() {
    let repo = InMemoryEdgeRepo::new();
    for &et in EdgeType::ALL {
        repo.insert(edge(1, 2, et)).await.unwrap();
    }
    let all = repo.list_outgoing(agent(1), None, 10).await;
    assert_eq!(all.len(), 6);
}
