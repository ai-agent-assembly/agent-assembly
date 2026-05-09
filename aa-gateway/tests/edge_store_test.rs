use aa_gateway::edges::{EdgeStoreError, InMemoryEdgeStore, NewEdge, VALID_EDGE_TYPES};
use chrono::Utc;

fn agent(n: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = n;
    id
}

fn edge(src: u8, tgt: u8, edge_type: &str) -> NewEdge {
    NewEdge {
        source_agent_id: agent(src),
        target_agent_id: agent(tgt),
        edge_type: edge_type.to_string(),
        metadata: None,
    }
}

#[test]
fn all_six_valid_edge_types_accepted() {
    let store = InMemoryEdgeStore::new();
    for &et in VALID_EDGE_TYPES {
        let id = store.insert(edge(1, 2, et)).expect("valid edge type should insert");
        assert!(id > 0, "returned id must be positive");
    }
}

#[test]
fn invalid_edge_type_is_rejected() {
    let store = InMemoryEdgeStore::new();
    let err = store.insert(edge(1, 2, "teleports")).unwrap_err();
    assert!(
        matches!(err, EdgeStoreError::InvalidEdgeType(_)),
        "unknown type must return InvalidEdgeType"
    );
}

#[test]
fn ids_are_monotonically_increasing() {
    let store = InMemoryEdgeStore::new();
    let id1 = store.insert(edge(1, 2, "calls")).unwrap();
    let id2 = store.insert(edge(1, 2, "calls")).unwrap();
    let id3 = store.insert(edge(1, 2, "calls")).unwrap();
    assert!(id1 < id2 && id2 < id3);
}

#[test]
fn list_outgoing_returns_newest_first() {
    let store = InMemoryEdgeStore::new();
    store.insert(edge(1, 2, "calls")).unwrap();
    store.insert(edge(1, 3, "calls")).unwrap();
    store.insert(edge(1, 4, "reads")).unwrap();

    let result = store.list_outgoing(agent(1), None, 100);
    assert_eq!(result.len(), 3);
    assert!(result[0].id > result[1].id, "newest edge must come first");
}

#[test]
fn list_outgoing_filtered_by_edge_type() {
    let store = InMemoryEdgeStore::new();
    store.insert(edge(1, 2, "calls")).unwrap();
    store.insert(edge(1, 3, "reads")).unwrap();
    store.insert(edge(1, 4, "calls")).unwrap();

    let calls = store.list_outgoing(agent(1), Some("calls"), 100);
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|e| e.edge_type == "calls"));
}

#[test]
fn list_incoming_returns_only_edges_to_target() {
    let store = InMemoryEdgeStore::new();
    store.insert(edge(1, 3, "messages")).unwrap();
    store.insert(edge(2, 3, "messages")).unwrap();
    store.insert(edge(1, 4, "messages")).unwrap(); // different target

    let incoming = store.list_incoming(agent(3), None, 100);
    assert_eq!(incoming.len(), 2);
    assert!(incoming.iter().all(|e| e.target_agent_id == agent(3)));
}

#[test]
fn list_by_type_filters_by_type_and_since() {
    let store = InMemoryEdgeStore::new();
    // Use a timestamp slightly in the past so all inserts land after it.
    let since = Utc::now() - chrono::TimeDelta::milliseconds(50);
    store.insert(edge(1, 2, "approves")).unwrap();
    store.insert(edge(1, 3, "approves")).unwrap();
    store.insert(edge(1, 4, "delegates_to")).unwrap();

    let approves = store.list_by_type("approves", since, 100);
    assert_eq!(approves.len(), 2);
    assert!(approves.iter().all(|e| e.edge_type == "approves"));
}

#[test]
fn limit_is_capped_at_1000() {
    let store = InMemoryEdgeStore::new();
    for _ in 0..1500 {
        store.insert(edge(1, 2, "writes")).unwrap();
    }
    let result = store.list_outgoing(agent(1), None, 9999);
    assert_eq!(result.len(), 1000, "limit must be capped at 1000");
}

#[test]
fn empty_store_returns_empty_vecs() {
    let store = InMemoryEdgeStore::new();
    assert!(store.list_outgoing(agent(1), None, 10).is_empty());
    assert!(store.list_incoming(agent(1), None, 10).is_empty());
    assert!(store.list_by_type("calls", Utc::now(), 10).is_empty());
}
