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
}

/// Reason an agent was suspended — determines whether auto-resume is possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendReason {
    /// Suspended because a budget limit was exceeded. Auto-resumable when budget resets.
    BudgetExceeded,
    /// Suspended by an operator or external system. Only manually resumable.
    Manual,
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
