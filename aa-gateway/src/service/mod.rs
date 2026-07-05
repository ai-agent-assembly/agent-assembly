//! gRPC service layer — wires tonic-generated services to business logic.

/// Deployment tenancy posture governing team-less agent **registration**
/// (AAASM-4021, AAASM-4032).
///
/// Cross-tenant *access* is always fail-safe: since AAASM-4140 a team-less
/// caller can never act on or read a resource owned by a tenant, in any posture
/// (see `approval_service::caller_may_act_on` and
/// `topology_service::caller_may_read`). An untenanted resource stays accessible
/// with zero configuration. This posture therefore governs only whether a
/// *team-less registration* is admitted:
///
/// * [`Untenanted`](TenancyMode::Untenanted) — team-less registration is
///   allowed. This is the default so OSS/single-tenant deployments register with
///   zero configuration.
/// * [`Tenanted`](TenancyMode::Tenanted) — every agent must belong to a team;
///   a team-less registration is rejected up front (AAASM-4032).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenancyMode {
    /// Single-tenant / OSS: team-less registration is admitted.
    #[default]
    Untenanted,
    /// Multi-tenant: every agent must belong to a team; team-less registration
    /// is rejected.
    Tenanted,
}

impl TenancyMode {
    /// Environment variable that selects the deployment tenancy posture at
    /// gateway boot (AAASM-4032).
    pub const ENV_VAR: &'static str = "AA_GATEWAY_TENANCY_MODE";

    /// Resolve the tenancy posture from [`Self::ENV_VAR`].
    ///
    /// Accepts `tenanted` / `untenanted` case-insensitively (surrounding
    /// whitespace ignored). An unset, empty, or unrecognised value falls back to
    /// the [`Untenanted`](Self::Untenanted) default, so OSS/single-tenant
    /// deployments keep zero-config behaviour.
    pub fn from_env() -> Self {
        match std::env::var(Self::ENV_VAR) {
            Ok(v) => Self::parse(&v),
            Err(_) => Self::default(),
        }
    }

    /// Parse a posture string, defaulting to [`Untenanted`](Self::Untenanted)
    /// for anything other than an explicit `tenanted`.
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "tenanted" => Self::Tenanted,
            _ => Self::Untenanted,
        }
    }
}

#[cfg(test)]
mod tenancy_mode_tests {
    use super::TenancyMode;

    #[test]
    fn default_is_untenanted() {
        assert_eq!(TenancyMode::default(), TenancyMode::Untenanted);
    }

    #[test]
    fn parse_tenanted_variants() {
        assert_eq!(TenancyMode::parse("tenanted"), TenancyMode::Tenanted);
        assert_eq!(TenancyMode::parse("Tenanted"), TenancyMode::Tenanted);
        assert_eq!(TenancyMode::parse("  TENANTED  "), TenancyMode::Tenanted);
    }

    #[test]
    fn parse_untenanted_and_unknown_fall_back_to_untenanted() {
        assert_eq!(TenancyMode::parse("untenanted"), TenancyMode::Untenanted);
        assert_eq!(TenancyMode::parse(""), TenancyMode::Untenanted);
        assert_eq!(TenancyMode::parse("nonsense"), TenancyMode::Untenanted);
    }
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
