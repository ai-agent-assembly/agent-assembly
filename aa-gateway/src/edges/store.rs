use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};

use super::{EdgeRecord, EdgeStoreError, NewEdge, VALID_EDGE_TYPES};

struct EdgeData {
    records: Vec<EdgeRecord>,
    next_id: i64,
    /// Secondary index: (source_id, edge_type) → indices into `records`.
    by_source_type: HashMap<([u8; 16], String), Vec<usize>>,
    /// Secondary index: (target_id, edge_type) → indices into `records`.
    by_target_type: HashMap<([u8; 16], String), Vec<usize>>,
    /// Secondary index: source_id → all indices, for unfiltered outgoing queries.
    by_source: HashMap<[u8; 16], Vec<usize>>,
    /// Secondary index: target_id → all indices, for unfiltered incoming queries.
    by_target: HashMap<[u8; 16], Vec<usize>>,
}

impl EdgeData {
    fn new() -> Self {
        Self {
            records: Vec::new(),
            next_id: 1,
            by_source_type: HashMap::new(),
            by_target_type: HashMap::new(),
            by_source: HashMap::new(),
            by_target: HashMap::new(),
        }
    }
}

/// Append-only in-memory store for agent-graph mesh edges.
///
/// All writes are `O(1)`. Reads over secondary indexes are `O(result_size)`.
/// The `limit` parameter on every list method is silently capped at 1 000 to
/// bound response size, matching the intent of the DB index design.
#[derive(Clone)]
pub struct InMemoryEdgeStore {
    data: Arc<RwLock<EdgeData>>,
}

impl InMemoryEdgeStore {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(EdgeData::new())),
        }
    }

    /// Insert a new edge. Returns the auto-assigned `id`. Rejects unknown edge types.
    pub fn insert(&self, edge: NewEdge) -> Result<i64, EdgeStoreError> {
        if !VALID_EDGE_TYPES.contains(&edge.edge_type.as_str()) {
            return Err(EdgeStoreError::InvalidEdgeType(edge.edge_type));
        }
        let mut data = self.data.write().expect("edge store lock poisoned");
        let id = data.next_id;
        data.next_id += 1;
        let idx = data.records.len();

        data.by_source_type
            .entry((edge.source_agent_id, edge.edge_type.clone()))
            .or_default()
            .push(idx);
        data.by_target_type
            .entry((edge.target_agent_id, edge.edge_type.clone()))
            .or_default()
            .push(idx);
        data.by_source.entry(edge.source_agent_id).or_default().push(idx);
        data.by_target.entry(edge.target_agent_id).or_default().push(idx);

        data.records.push(EdgeRecord {
            id,
            source_agent_id: edge.source_agent_id,
            target_agent_id: edge.target_agent_id,
            edge_type: edge.edge_type,
            created_at: Utc::now(),
            metadata: edge.metadata,
        });
        Ok(id)
    }

    /// Return up to `limit` outgoing edges from `source`, newest first.
    pub fn list_outgoing(&self, source: [u8; 16], edge_type: Option<&str>, limit: usize) -> Vec<EdgeRecord> {
        let limit = limit.min(1000);
        let data = self.data.read().expect("edge store lock poisoned");
        let idxs: &[usize] = match edge_type {
            Some(et) => data
                .by_source_type
                .get(&(source, et.to_string()))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => data.by_source.get(&source).map(Vec::as_slice).unwrap_or_default(),
        };
        idxs.iter()
            .rev()
            .take(limit)
            .map(|&i| data.records[i].clone())
            .collect()
    }

    /// Return up to `limit` incoming edges to `target`, newest first.
    pub fn list_incoming(&self, target: [u8; 16], edge_type: Option<&str>, limit: usize) -> Vec<EdgeRecord> {
        let limit = limit.min(1000);
        let data = self.data.read().expect("edge store lock poisoned");
        let idxs: &[usize] = match edge_type {
            Some(et) => data
                .by_target_type
                .get(&(target, et.to_string()))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => data.by_target.get(&target).map(Vec::as_slice).unwrap_or_default(),
        };
        idxs.iter()
            .rev()
            .take(limit)
            .map(|&i| data.records[i].clone())
            .collect()
    }

    /// Return up to `limit` edges of `edge_type` with `created_at >= since`, newest first.
    pub fn list_by_type(&self, edge_type: &str, since: DateTime<Utc>, limit: usize) -> Vec<EdgeRecord> {
        let limit = limit.min(1000);
        let data = self.data.read().expect("edge store lock poisoned");
        data.records
            .iter()
            .filter(|r| r.edge_type == edge_type && r.created_at >= since)
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }
}

impl Default for InMemoryEdgeStore {
    fn default() -> Self {
        Self::new()
    }
}
