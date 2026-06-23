//! Policy YAML parser and validator for aa-gateway.
//!
//! Entry point: [`validator::PolicyValidator::from_yaml`].
//!
//! # Single canonical AST (AAASM-3607)
//!
//! The cross-layer-shared dimensions of a policy (capabilities, network
//! egress, tool rules) are defined once in [`aa_security::policy`]. The gateway
//! keeps its richer in-crate [`PolicyDocument`] for L7-only evaluation (CEL,
//! history, budget) but projects onto the canonical AST via
//! [`PolicyDocument::to_canonical`]. The eBPF kernel rules are lowered
//! (`aa_security::policy::lower_to_ebpf`) from that same canonical projection,
//! so the L7 engine and the kernel layer provably share one definition — there
//! is no second, divergent copy of the shared schema.

pub(crate) mod canonical;
pub(crate) mod context;
pub mod document;
pub mod error;
pub(crate) mod expr;
pub mod history;
pub mod network;
pub mod raw;
pub mod rbac;
pub mod scope;
pub mod validator;

pub use document::{ActiveHours, BudgetPolicy, DataPolicy, NetworkPolicy, PolicyDocument, SchedulePolicy, ToolPolicy};
pub use error::{PolicyParseError, ValidationError, ValidationWarning};
pub use network::{check_network_egress, EgressDecision};
pub use rbac::{required_role_for, CallerRole, MutationKind, PolicyScopeKind};
pub use scope::{OrgId, PolicyScope, TeamId};
pub use validator::{PolicyValidator, PolicyValidatorOutput};

// Re-export the canonical, cross-layer policy AST so consumers of
// `aa_gateway::policy` reach the single source of truth in `aa-security`.
pub use aa_security::policy::{
    lower_to_ebpf, Capability as CanonicalCapability, CapabilitySet as CanonicalCapabilitySet, EbpfRuleSet, PathRule,
    PathVerdict, PolicyDocument as CanonicalPolicyDocument,
};
