//! Append-only in-memory edge store for the agent-graph mesh model.
//!
//! Mirrors the logical schema of the `agent_graph_edges` table defined in
//! AAASM-980: append-only rows, `created_at DESC` ordering, and secondary
//! indexes on `(source_agent_id, edge_type)` and `(target_agent_id, edge_type)`.

use chrono::{DateTime, Utc};

/// Input used when inserting a new edge into the store.
#[derive(Debug, Clone)]
pub struct NewEdge {
    /// Raw UUID bytes of the originating agent.
    pub source_agent_id: [u8; 16],
    /// Raw UUID bytes of the target agent.
    pub target_agent_id: [u8; 16],
    /// Relationship kind — must be one of the six `VALID_EDGE_TYPES` strings.
    pub edge_type: String,
    /// Optional structured metadata (e.g. graph name, reason, key names).
    pub metadata: Option<serde_json::Value>,
}

/// A recorded edge between two agents in the topology graph.
#[derive(Debug, Clone)]
pub struct EdgeRecord {
    /// Auto-assigned monotonically increasing identifier.
    pub id: i64,
    /// Raw UUID bytes of the agent that originated the relationship.
    pub source_agent_id: [u8; 16],
    /// Raw UUID bytes of the agent that was the target of the relationship.
    pub target_agent_id: [u8; 16],
    /// Relationship kind — one of the six valid `VALID_EDGE_TYPES` strings.
    pub edge_type: String,
    /// When this edge was recorded.
    pub created_at: DateTime<Utc>,
    /// Optional structured metadata attached at emission time.
    pub metadata: Option<serde_json::Value>,
}
