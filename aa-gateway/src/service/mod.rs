//! gRPC service layer — wires tonic-generated services to business logic.

pub mod approval_service;
pub mod audit_service;
pub mod convert;
pub mod lifecycle_service;
pub mod policy_service;
pub mod topology_service;

pub use approval_service::ApprovalServiceImpl;
pub use audit_service::AuditServiceImpl;
pub use lifecycle_service::AgentLifecycleServiceImpl;
pub use policy_service::PolicyServiceImpl;
pub use topology_service::TopologyServiceImpl;
