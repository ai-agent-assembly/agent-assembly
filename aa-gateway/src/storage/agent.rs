//! Agent-registry storage value types — slim records for persistence.
//!
//! These are deliberately distinct from the richer
//! [`crate::registry::store::AgentRecord`] runtime state: the registry layer
//! owns liveness, heartbeats, and credential tokens; the storage layer
//! persists only the durable identity / configuration fields. Conversion
//! between the two happens at the wiring layer (Epic 18 S-I).

use std::collections::BTreeMap;

use aa_core::identity::AgentId;
use chrono::{DateTime, Utc};

/// Team identifier used by the storage layer.
///
/// Kept as a type alias for now so existing `String` team_ids in the gateway
/// can be passed through unchanged. May be replaced with a newtype later.
pub type TeamId = String;

/// Storage-layer agent record — the durable shape of a registered agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    /// Stable agent identifier.
    pub agent_id: AgentId,
    /// Owning team, if assigned.
    pub team_id: Option<TeamId>,
    /// Owning org, if assigned.
    pub org_id: Option<String>,
    /// Arbitrary metadata (k/v).
    pub metadata: BTreeMap<String, String>,
    /// Initial registration timestamp (UTC).
    pub registered_at: DateTime<Utc>,
    /// Last time the agent was observed (UTC).
    pub last_seen_at: DateTime<Utc>,
    /// Enforcement mode — `"enforce"`, `"shadow"`, `"observe"`, etc.
    pub enforcement_mode: String,
}

/// Filter applied to agent-registry queries.
#[derive(Debug, Clone, Default)]
pub struct AgentFilter {
    /// Restrict to agents owned by this team.
    pub team_id: Option<TeamId>,
    /// Restrict to agents owned by this org.
    pub org_id: Option<String>,
    /// Substring match on agent metadata `name` key.
    pub name_contains: Option<String>,
    /// Maximum number of agents to return.
    pub limit: Option<u32>,
    /// Offset into the result set.
    pub offset: Option<u32>,
}
