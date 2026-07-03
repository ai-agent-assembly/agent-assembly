//! gRPC service layer — wires tonic-generated services to business logic.

/// Deployment tenancy posture governing the cross-tenant `caller_may_*` checks
/// (AAASM-4021).
///
/// The cross-tenant guards fall back to *allow* whenever either the caller or
/// the resource is untenanted, so a single-tenant / OSS deployment (where
/// nothing carries a `team_id`) works with zero configuration. That same
/// fallback, however, lets a **registered but team-less caller** pass every
/// tenant's check — reading or acting on another tenant's resource — once
/// tenancy is actually in use. This posture makes the distinction explicit:
///
/// * [`Untenanted`](TenancyMode::Untenanted) — the legacy permissive fallback;
///   a team-less caller is unconfined. This is the default so OSS/single-tenant
///   deployments are unaffected.
/// * [`Tenanted`](TenancyMode::Tenanted) — tenancy is enforced; a team-less
///   caller may **not** be treated as cross-tenant-allowed against a tenanted
///   resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenancyMode {
    /// Single-tenant / OSS: a team-less caller is unconfined (legacy fallback).
    #[default]
    Untenanted,
    /// Multi-tenant: a team-less caller cannot act on a tenanted resource.
    Tenanted,
}

pub mod approval_service;
pub mod audit_service;
pub mod convert;
pub mod lifecycle_service;
pub mod policy_service;
pub mod secrets_service;
pub mod topology_service;

pub use approval_service::ApprovalServiceImpl;
pub use audit_service::AuditServiceImpl;
pub use lifecycle_service::AgentLifecycleServiceImpl;
pub use policy_service::PolicyServiceImpl;
pub use secrets_service::SecretsServiceImpl;
pub use topology_service::TopologyServiceImpl;
