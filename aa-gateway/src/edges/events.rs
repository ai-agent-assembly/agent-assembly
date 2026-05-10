//! Cross-team edge detection events (AAASM-1001).
//!
//! Published to the internal broadcast channel whenever an `EdgeRepo::insert`
//! records an edge whose source and target agents belong to different teams.
//! Consumers (e.g. the inter-team channel work in AAASM-198) subscribe via
//! `InMemoryEdgeRepo::subscribe_cross_team_events()`.

use chrono::{DateTime, Utc};

use aa_core::identity::AgentId;
use aa_core::topology::EdgeType;

/// Capacity of the cross-team edge event broadcast channel.
pub(crate) const CROSS_TEAM_CHANNEL_CAPACITY: usize = 64;

/// Emitted whenever an edge is inserted between agents in different teams.
///
/// Both `source_team_id` and `target_team_id` are always non-empty — the event
/// is only published when both agents have a known, non-NULL `team_id`.
#[derive(Debug, Clone)]
pub struct CrossTeamEdgeEvent {
    /// The auto-assigned id of the inserted edge.
    pub edge_id: i64,
    /// The agent that originated the relationship.
    pub source_agent_id: AgentId,
    /// Team the source agent belongs to.
    pub source_team_id: String,
    /// The agent that was the target of the relationship.
    pub target_agent_id: AgentId,
    /// Team the target agent belongs to.
    pub target_team_id: String,
    /// Semantic type of the edge.
    pub edge_type: EdgeType,
    /// When the edge was recorded (UTC).
    pub occurred_at: DateTime<Utc>,
}
