//! Orphan handling policy applied when a parent agent deregisters.

/// Policy controlling what happens to children when their parent deregisters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrphanMode {
    /// Suspend each orphaned child with reason `ParentDeregistered` (default).
    #[default]
    Suspend,
    /// Promote each direct child to a root agent: clear parent link, reset depth to 0.
    PromoteToRoot,
    /// Recursively deregister all descendants.
    CascadeDeregister,
}

/// Records what the registry did to one agent as a result of orphan handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanEffect {
    /// Registry key of the affected agent.
    pub agent_key: [u8; 16],
    /// Human-readable agent_id string of the affected agent.
    pub agent_id_str: String,
    /// What happened: `"suspended"`, `"promoted_to_root"`, or `"deregistered"`.
    pub action: &'static str,
    /// Previous status string for AgentStatusChanged event.
    pub old_status: String,
    /// New status string for AgentStatusChanged event.
    pub new_status: String,
}
