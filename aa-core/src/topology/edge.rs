//! Domain types and trait for the agent-graph mesh edge model (AAASM-985).

/// The six relationship kinds that can exist between agents in the topology graph.
///
/// Serialises to / deserialises from the snake_case wire string
/// (e.g. `"delegates_to"`, `"calls"`) when the `serde` feature is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EdgeType {
    /// Agent A has granted authority to Agent B to act on its behalf.
    DelegatesTo,
    /// Agent A invokes Agent B as a sub-agent or tool.
    Calls,
    /// Agent A reads data owned or produced by Agent B.
    Reads,
    /// Agent A writes data that Agent B owns or consumes.
    Writes,
    /// Agent A approves an action or output of Agent B.
    Approves,
    /// Agent A sends a message to Agent B.
    Messages,
}

impl EdgeType {
    /// Returns the canonical snake_case wire string for this edge type.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeType::DelegatesTo => "delegates_to",
            EdgeType::Calls => "calls",
            EdgeType::Reads => "reads",
            EdgeType::Writes => "writes",
            EdgeType::Approves => "approves",
            EdgeType::Messages => "messages",
        }
    }

    /// All six valid edge type variants in declaration order.
    pub const ALL: &'static [EdgeType] = &[
        EdgeType::DelegatesTo,
        EdgeType::Calls,
        EdgeType::Reads,
        EdgeType::Writes,
        EdgeType::Approves,
        EdgeType::Messages,
    ];
}

impl core::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a string cannot be parsed into an [`EdgeType`].
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct UnknownEdgeType(pub alloc::string::String);

#[cfg(feature = "alloc")]
impl core::fmt::Display for UnknownEdgeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown edge type: {:?}", self.0)
    }
}

#[cfg(feature = "alloc")]
impl core::convert::TryFrom<&str> for EdgeType {
    type Error = UnknownEdgeType;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "delegates_to" => Ok(EdgeType::DelegatesTo),
            "calls" => Ok(EdgeType::Calls),
            "reads" => Ok(EdgeType::Reads),
            "writes" => Ok(EdgeType::Writes),
            "approves" => Ok(EdgeType::Approves),
            "messages" => Ok(EdgeType::Messages),
            other => Err(UnknownEdgeType(alloc::string::String::from(other))),
        }
    }
}

/// Input for recording a new directed edge between two agents.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct NewEdge {
    /// Raw UUID bytes of the agent that originates the relationship.
    pub source_agent_id: [u8; 16],
    /// Raw UUID bytes of the agent that is the target of the relationship.
    pub target_agent_id: [u8; 16],
    /// The kind of relationship.
    pub edge_type: EdgeType,
    /// Optional structured metadata (e.g. graph name, reason, key names).
    pub metadata: Option<serde_json::Value>,
}

/// A recorded directed edge between two agents in the topology graph.
#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Edge {
    /// Auto-assigned monotonically increasing identifier.
    pub id: i64,
    /// Raw UUID bytes of the agent that originates the relationship.
    pub source_agent_id: [u8; 16],
    /// Raw UUID bytes of the agent that is the target of the relationship.
    pub target_agent_id: [u8; 16],
    /// The kind of relationship.
    pub edge_type: EdgeType,
    /// When this edge was recorded.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Optional structured metadata attached at emission time.
    pub metadata: Option<serde_json::Value>,
}

/// Error returned by [`EdgeRepo`] operations.
#[cfg(feature = "std")]
#[derive(Debug, thiserror::Error)]
pub enum EdgeRepoError {
    /// The requested operation cannot be completed in the backing store.
    #[error("edge store error: {0}")]
    Store(String),
}

/// Async repository abstraction for the agent-graph edge store.
///
/// Implementations are provided by `InMemoryEdgeRepo` (tests and single-node
/// deployments) and will be backed by a persistent store in production.
/// All list methods return results ordered newest-first and silently cap
/// `limit` at 1 000.
#[cfg(feature = "std")]
#[async_trait::async_trait]
pub trait EdgeRepo: Send + Sync {
    /// Record a new directed edge. Returns the auto-assigned `id`.
    async fn insert(&self, edge: NewEdge) -> Result<i64, EdgeRepoError>;

    /// Return up to `limit` outgoing edges from `source`, newest first.
    ///
    /// If `edge_type` is `Some`, only edges of that type are returned.
    async fn list_outgoing(&self, source: [u8; 16], edge_type: Option<EdgeType>, limit: usize) -> Vec<Edge>;

    /// Return up to `limit` incoming edges to `target`, newest first.
    ///
    /// If `edge_type` is `Some`, only edges of that type are returned.
    async fn list_incoming(&self, target: [u8; 16], edge_type: Option<EdgeType>, limit: usize) -> Vec<Edge>;

    /// Return up to `limit` edges of `edge_type` with `created_at >= since`, newest first.
    async fn list_by_type(&self, edge_type: EdgeType, since: chrono::DateTime<chrono::Utc>, limit: usize) -> Vec<Edge>;
}

/// Test-only [`EdgeRepo`] that stores edges in memory with no secondary indexes.
///
/// Use this as a test double in unit tests that depend on [`EdgeRepo`] but
/// whose assertion target is not the edge storage logic itself.
/// Gated on the `test-utils` feature.
#[cfg(all(feature = "std", feature = "test-utils"))]
pub struct MockEdgeRepo {
    inner: std::sync::Mutex<Vec<Edge>>,
    next_id: std::sync::atomic::AtomicI64,
}

#[cfg(all(feature = "std", feature = "test-utils"))]
impl MockEdgeRepo {
    /// Create an empty `MockEdgeRepo`.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Vec::new()),
            next_id: std::sync::atomic::AtomicI64::new(1),
        }
    }

    /// Return a snapshot of all recorded edges in insertion order.
    pub fn snapshot(&self) -> Vec<Edge> {
        self.inner.lock().expect("mock lock poisoned").clone()
    }
}

#[cfg(all(feature = "std", feature = "test-utils"))]
impl Default for MockEdgeRepo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(feature = "std", feature = "test-utils"))]
#[async_trait::async_trait]
impl EdgeRepo for MockEdgeRepo {
    async fn insert(&self, edge: NewEdge) -> Result<i64, EdgeRepoError> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let record = Edge {
            id,
            source_agent_id: edge.source_agent_id,
            target_agent_id: edge.target_agent_id,
            edge_type: edge.edge_type,
            created_at: chrono::Utc::now(),
            metadata: edge.metadata,
        };
        self.inner.lock().expect("mock lock poisoned").push(record);
        Ok(id)
    }

    async fn list_outgoing(&self, source: [u8; 16], edge_type: Option<EdgeType>, limit: usize) -> Vec<Edge> {
        let data = self.inner.lock().expect("mock lock poisoned");
        data.iter()
            .filter(|e| e.source_agent_id == source && edge_type.map_or(true, |et| e.edge_type == et))
            .rev()
            .take(limit.min(1000))
            .cloned()
            .collect()
    }

    async fn list_incoming(&self, target: [u8; 16], edge_type: Option<EdgeType>, limit: usize) -> Vec<Edge> {
        let data = self.inner.lock().expect("mock lock poisoned");
        data.iter()
            .filter(|e| e.target_agent_id == target && edge_type.map_or(true, |et| e.edge_type == et))
            .rev()
            .take(limit.min(1000))
            .cloned()
            .collect()
    }

    async fn list_by_type(&self, edge_type: EdgeType, since: chrono::DateTime<chrono::Utc>, limit: usize) -> Vec<Edge> {
        let data = self.inner.lock().expect("mock lock poisoned");
        data.iter()
            .filter(|e| e.edge_type == edge_type && e.created_at >= since)
            .rev()
            .take(limit.min(1000))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

    #[test]
    fn all_six_variants_parse_from_wire_strings() {
        let cases = [
            ("delegates_to", EdgeType::DelegatesTo),
            ("calls", EdgeType::Calls),
            ("reads", EdgeType::Reads),
            ("writes", EdgeType::Writes),
            ("approves", EdgeType::Approves),
            ("messages", EdgeType::Messages),
        ];
        for (s, expected) in cases {
            assert_eq!(EdgeType::try_from(s).unwrap(), expected, "parsing {s:?}");
        }
    }

    #[test]
    fn unknown_string_returns_error() {
        assert!(EdgeType::try_from("follows").is_err());
        assert!(EdgeType::try_from("").is_err());
    }

    #[test]
    fn as_str_round_trips() {
        for &variant in EdgeType::ALL {
            assert_eq!(EdgeType::try_from(variant.as_str()).unwrap(), variant);
        }
    }

    #[test]
    fn display_matches_as_str() {
        for &variant in EdgeType::ALL {
            assert_eq!(format!("{variant}"), variant.as_str());
        }
    }

    #[test]
    fn all_contains_all_six_variants() {
        assert_eq!(EdgeType::ALL.len(), 6);
    }
}
