//! Agent registry — in-memory agent identity store and lifecycle tracking.
//!
//! This module maintains the set of registered agents, their identity records,
//! credential tokens, and heartbeat state. It is the server-side backing store
//! for the `AgentLifecycleService` gRPC service defined in `proto/agent.proto`.

pub mod convert;
pub mod lineage;
pub mod store;
pub mod token;

pub use lineage::Lineage;
pub use store::{ActiveSession, AgentGraph, AgentRecord, AgentRegistry, RecentEvent};

/// Errors returned by [`AgentRegistry`](store::AgentRegistry) operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// Attempted to register an agent whose ID is already present.
    #[error("agent already registered: {0:?}")]
    AlreadyRegistered([u8; 16]),
    /// Referenced an agent ID that does not exist in the registry.
    #[error("agent not found: {0:?}")]
    NotFound([u8; 16]),
    /// A lineage validation check failed during registration.
    #[error("lineage validation failed: {0}")]
    Lineage(#[from] LineageError),
}

/// Error returned when agent lineage validation fails during registration.
#[derive(Debug, thiserror::Error)]
pub enum LineageError {
    /// The new agent would create a cycle in the delegation graph.
    #[error("circular agent delegation detected: {cycle:?}")]
    CircularDelegation {
        /// Cycle path: starts with the new agent_id, traverses ancestors, ends when the new agent_id is found again.
        cycle: Vec<[u8; 16]>,
    },
    /// The new agent would exceed the maximum allowed delegation depth.
    #[error("max delegation depth exceeded: depth {depth} > max {max}")]
    MaxDepthExceeded { depth: u32, max: u32 },
}

/// Reason an agent was suspended — determines whether auto-resume is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendReason {
    /// Suspended because a budget limit was exceeded. Auto-resumable when budget resets.
    BudgetExceeded,
    /// Suspended by an operator or external system. Only manually resumable.
    Manual,
    /// Suspended because a parent agent was suspended. Cleared when the child is explicitly resumed.
    ParentSuspended {
        /// The direct parent that caused this cascading suspension.
        parent_agent_id: [u8; 16],
    },
}

/// Runtime status of a registered agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    /// Agent is actively running and sending heartbeats.
    Active,
    /// Agent has been suspended by the gateway. Contains the reason for suspension.
    Suspended(SuspendReason),
    /// Agent has been removed from the registry (clean shutdown or forced removal).
    Deregistered,
}

/// Event emitted when an agent's suspension status changes.
///
/// Returned by [`AgentRegistry::suspend_with_cascade`] for each agent
/// whose status transitioned from Active to Suspended during the cascade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentStatusChanged {
    /// The agent whose status changed.
    pub agent_id: [u8; 16],
    /// The new status after the change.
    pub new_status: AgentStatus,
    /// The suspension reason that triggered the status change.
    pub suspend_reason: SuspendReason,
}
