//! In-memory implementation of the `EdgeRepo` trait for the gateway.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use aa_core::identity::AgentId;
use aa_core::topology::{Edge, EdgeRepo, EdgeRepoError, EdgeType, NewEdge};

struct RepoData {
    records: Vec<Edge>,
    next_id: i64,
    by_source_type: HashMap<(AgentId, EdgeType), Vec<usize>>,
    by_target_type: HashMap<(AgentId, EdgeType), Vec<usize>>,
    by_source: HashMap<AgentId, Vec<usize>>,
    by_target: HashMap<AgentId, Vec<usize>>,
}

impl RepoData {
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

/// Append-only in-memory [`EdgeRepo`] for the gateway.
///
/// Writes are `O(1)`. Reads over secondary indexes are `O(result_size)`.
/// The `limit` parameter on every list method is silently capped at 1 000.
/// Thread-safe via `Arc<RwLock<_>>`.
#[derive(Clone)]
pub struct InMemoryEdgeRepo {
    data: Arc<RwLock<RepoData>>,
}

impl InMemoryEdgeRepo {
    /// Create an empty `InMemoryEdgeRepo`.
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(RepoData::new())),
        }
    }
}

impl Default for InMemoryEdgeRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EdgeRepo for InMemoryEdgeRepo {
    async fn insert(&self, edge: NewEdge) -> Result<i64, EdgeRepoError> {
        let mut data = self.data.write().expect("edge repo lock poisoned");
        let id = data.next_id;
        data.next_id += 1;
        let idx = data.records.len();

        data.by_source_type
            .entry((edge.source, edge.edge_type))
            .or_default()
            .push(idx);
        data.by_target_type
            .entry((edge.target, edge.edge_type))
            .or_default()
            .push(idx);
        data.by_source.entry(edge.source).or_default().push(idx);
        data.by_target.entry(edge.target).or_default().push(idx);

        data.records.push(Edge {
            id,
            source: edge.source,
            target: edge.target,
            edge_type: edge.edge_type,
            created_at: Utc::now(),
            metadata: edge.metadata,
        });
        Ok(id)
    }

    async fn list_outgoing(
        &self,
        source: AgentId,
        edge_type: Option<EdgeType>,
        limit: u32,
    ) -> Result<Vec<Edge>, EdgeRepoError> {
        let limit = (limit as usize).min(1000);
        let data = self.data.read().expect("edge repo lock poisoned");
        let idxs: &[usize] = match edge_type {
            Some(et) => data
                .by_source_type
                .get(&(source, et))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => data.by_source.get(&source).map(Vec::as_slice).unwrap_or_default(),
        };
        Ok(idxs
            .iter()
            .rev()
            .take(limit)
            .map(|&i| data.records[i].clone())
            .collect())
    }

    async fn list_incoming(
        &self,
        target: AgentId,
        edge_type: Option<EdgeType>,
        limit: u32,
    ) -> Result<Vec<Edge>, EdgeRepoError> {
        let limit = (limit as usize).min(1000);
        let data = self.data.read().expect("edge repo lock poisoned");
        let idxs: &[usize] = match edge_type {
            Some(et) => data
                .by_target_type
                .get(&(target, et))
                .map(Vec::as_slice)
                .unwrap_or_default(),
            None => data.by_target.get(&target).map(Vec::as_slice).unwrap_or_default(),
        };
        Ok(idxs
            .iter()
            .rev()
            .take(limit)
            .map(|&i| data.records[i].clone())
            .collect())
    }

    async fn list_by_type(
        &self,
        edge_type: EdgeType,
        since: DateTime<Utc>,
        limit: u32,
    ) -> Result<Vec<Edge>, EdgeRepoError> {
        let limit = (limit as usize).min(1000);
        let data = self.data.read().expect("edge repo lock poisoned");
        Ok(data
            .records
            .iter()
            .filter(|r| r.edge_type == edge_type && r.created_at >= since)
            .rev()
            .take(limit)
            .cloned()
            .collect())
    }
}
