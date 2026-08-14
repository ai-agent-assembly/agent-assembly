//! Policy YAML parser, validator and version history — the single
//! authoritative implementation of policy-document semantics.
//!
//! Entry point: [`validator::PolicyValidator::from_yaml`].
//!
//! # Why this is a leaf crate (AAASM-5349)
//!
//! Three consumers need to answer "what policy is in effect, and is it
//! enforced?" from the same code: `aa-gateway` evaluates it, the `aa-runtime`
//! developer-integration service reports it on `status`/`verify`, and `aa-cli`
//! resolves it before a governed launch. Two of those must not depend on the
//! third — the runtime is the enforcement point and cannot depend on the
//! gateway — so the semantics live below all of them rather than inside any
//! one. A second copy of this parser anywhere would be a second definition of
//! what "governed" means.
//!
//! Evaluation *context* (budget trackers, the agent registry) stays in
//! `aa-gateway`: it needs runtime state this crate deliberately knows nothing
//! about.
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

pub mod canonical;
pub mod context;
pub mod digest;
pub mod document;
pub mod error;
pub mod expr;
pub mod filesystem;
pub mod history;
pub mod network;
pub mod raw;
pub mod rbac;
pub mod resolve;
pub mod scope;

#[cfg(test)]
mod test_support;
pub mod validator;

pub use context::{ContextError, PolicyContext};
pub use document::{ActiveHours, BudgetPolicy, DataPolicy, NetworkPolicy, PolicyDocument, SchedulePolicy, ToolPolicy};
pub use error::{PolicyParseError, ValidationError, ValidationWarning};
pub use expr::{evaluate_clause, ClauseKind, ResolutionFailure};
pub use filesystem::{merge_cascade as merge_filesystem_cascade, CascadeFilesystemScope, EmptyCascadeRefusal};
pub use network::{check_network_egress, EgressDecision};
pub use rbac::{required_role_for, CallerRole, MutationKind, PolicyScopeKind};
pub use scope::{OrgId, PolicyScope, TeamId};
pub use validator::{PolicyValidator, PolicyValidatorOutput};

// Re-export the canonical, cross-layer policy AST so consumers of
// `aa_gateway::policy` reach the single source of truth in `aa-security`.
pub use aa_security::policy::{
    lower_to_ebpf, Capability as CanonicalCapability, CapabilitySet as CanonicalCapabilitySet, EbpfRuleSet,
    FilesystemPolicy, PathRule, PathScope, PathScopeError, PathVerdict, PolicyDocument as CanonicalPolicyDocument,
};
