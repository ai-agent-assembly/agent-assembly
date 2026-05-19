//! Control plane for Agent Assembly — policy enforcement and agent registry.
//!
//! The gateway is the central coordination point: it maintains the agent
//! registry, evaluates governance policies, routes enforcement decisions
//! back to proxies and SDK shims, and writes the audit trail.

pub mod alerts;
pub mod anomaly;
pub mod approval;
pub mod audit;
pub mod audit_reader;
pub mod budget;
pub mod edges;
pub mod engine;
pub mod events;
pub mod iam;
pub mod message_router;
pub mod policy;
pub mod registry;
pub mod server;
pub mod service;
pub mod simulation;

pub use audit_reader::AuditReader;
pub use engine::{EvaluationResult, PolicyEngine, PolicyLoadError};
pub use registry::{AgentRecord, AgentRegistry, AgentStatus};
pub use service::PolicyServiceImpl;
