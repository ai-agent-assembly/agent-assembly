//! Control plane for Agent Assembly — policy evaluation and agent registry.
//!
//! The gateway is the central coordination point: it maintains the agent
//! registry, evaluates governance policies, routes policy decisions back to
//! proxies and SDK shims, and writes the audit trail.
//!
//! It is E1 of ADR 0033 and only E1: it evaluates and holds no traffic, so a
//! `Deny` here is exactly as strong as the caller that blocks on the answer.

pub mod alerts;
pub mod anomaly;
pub mod app_state;
pub mod approval;
pub mod audit;
// strip-for-publish:begin audit-consumer
// AAASM-2388: gateway-internal NATS->Postgres audit consumer. Compiled only
// under the `audit-consumer` feature (held back from crates.io publish).
#[cfg(feature = "audit-consumer")]
pub mod audit_consumer;
// strip-for-publish:end audit-consumer
pub mod audit_reader;
pub mod auth;
pub mod budget;
pub mod dashboard_server;
pub mod edges;
pub mod engine;
pub mod events;
pub mod iam;
pub mod invalidation;
pub mod local_mode;
pub mod message_router;
pub mod ops;
pub mod policy;
pub mod registry;
pub mod remote_mode;
pub mod routes;
pub mod sanitizer;
pub mod secrets;
pub mod server;
pub mod service;
pub mod simulation;
pub mod storage;

pub use app_state::AppState;
pub use audit_reader::AuditReader;
pub use engine::{EvaluationResult, PolicyEngine, PolicyLoadError};
pub use registry::{AgentRecord, AgentRegistry, AgentStatus};
pub use service::PolicyServiceImpl;
