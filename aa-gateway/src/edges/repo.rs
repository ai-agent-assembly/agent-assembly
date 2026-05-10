//! In-memory implementation of the `EdgeRepo` trait for the gateway.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::broadcast;

use aa_core::identity::AgentId;
use aa_core::topology::{Edge, EdgeRepo, EdgeRepoError, EdgeType, NewEdge};

use crate::edges::events::{CrossTeamEdgeEvent, CROSS_TEAM_CHANNEL_CAPACITY};
use crate::registry::AgentRegistry;

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
///
/// When constructed with [`InMemoryEdgeRepo::with_events`], every `insert` that
/// crosses team boundaries publishes a [`CrossTeamEdgeEvent`] to the internal
/// broadcast channel. Subscribers call [`InMemoryEdgeRepo::subscribe_cross_team_events`].
#[derive(Clone)]
pub struct InMemoryEdgeRepo {
    data: Arc<RwLock<RepoData>>,
    registry: Option<Arc<AgentRegistry>>,
    event_tx: Option<broadcast::Sender<CrossTeamEdgeEvent>>,
}

impl InMemoryEdgeRepo {
    /// Create an empty repo with no event publishing.
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(RepoData::new())),
            registry: None,
            event_tx: None,
        }
    }

    /// Create a repo that publishes [`CrossTeamEdgeEvent`]s when an inserted
    /// edge crosses team boundaries.
    pub fn with_events(registry: Arc<AgentRegistry>) -> (Self, broadcast::Receiver<CrossTeamEdgeEvent>) {
        let (tx, rx) = broadcast::channel(CROSS_TEAM_CHANNEL_CAPACITY);
        let repo = Self {
            data: Arc::new(RwLock::new(RepoData::new())),
            registry: Some(registry),
            event_tx: Some(tx),
        };
        (repo, rx)
    }

    /// Subscribe to cross-team edge events.  Returns `None` when the repo was
    /// constructed without event publishing (i.e. via [`InMemoryEdgeRepo::new`]).
    pub fn subscribe_cross_team_events(&self) -> Option<broadcast::Receiver<CrossTeamEdgeEvent>> {
        self.event_tx.as_ref().map(|tx| tx.subscribe())
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
        // --- write critical section: hold lock only for the store update ---
        let (id, source, target, edge_type, occurred_at) = {
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

            let occurred_at = Utc::now();
            data.records.push(Edge {
                id,
                source: edge.source,
                target: edge.target,
                edge_type: edge.edge_type,
                created_at: occurred_at,
                metadata: edge.metadata,
            });
            (id, edge.source, edge.target, edge.edge_type, occurred_at)
        };
        // --- lock released; now do registry lookup + event publish ---

        if let (Some(registry), Some(tx)) = (&self.registry, &self.event_tx) {
            let src_team = registry.get(source.as_bytes()).and_then(|r| r.team_id);
            let tgt_team = registry.get(target.as_bytes()).and_then(|r| r.team_id);
            match (src_team, tgt_team) {
                (Some(source_team_id), Some(target_team_id)) if source_team_id != target_team_id => {
                    let _ = tx.send(CrossTeamEdgeEvent {
                        edge_id: id,
                        source_agent_id: source,
                        source_team_id,
                        target_agent_id: target,
                        target_team_id,
                        edge_type,
                        occurred_at,
                    });
                }
                (None, _) | (_, None) => {
                    tracing::info!(
                        edge_id = id,
                        "cross-team check skipped: one or both agents have no team_id"
                    );
                }
                _ => {} // same team — no event needed
            }
        }

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
