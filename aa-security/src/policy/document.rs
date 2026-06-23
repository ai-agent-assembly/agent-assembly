//! The canonical, cross-layer policy AST.
//!
//! [`PolicyDocument`] is the single typed source of truth that both the
//! gateway rule engine (L7) and the eBPF map compiler (kernel) consume, so a
//! policy is described exactly once and the two enforcement layers cannot
//! drift apart. See AAASM-3606 / AAASM-3561.
//!
//! This is deliberately the *canonical* (lowering-relevant) shape: the
//! filesystem/capability and network-egress dimensions that the kernel layer
//! can enforce, plus the tool-path predicates needed to derive in-kernel path
//! rules. Gateway-only evaluation concerns (history stores, CEL contexts,
//! budget accounting) stay in `aa-gateway` and operate *on top of* this AST.

use super::capability::CapabilitySet;

/// Network egress policy: the set of hosts an agent may connect to.
///
/// An empty (or absent) allowlist means "no egress restriction" — matching the
/// documented semantics in `policy-examples/strict.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetworkPolicy {
    /// Host glob patterns the agent may connect to.
    pub allowlist: Vec<String>,
}

/// A single tool rule from the policy `tools:` map.
///
/// Only the fields needed for cross-layer lowering + L7 evaluation are kept on
/// the canonical AST. `requires_approval_if` is preserved verbatim so the
/// eBPF lowering can extract the `path starts_with "…"` predicates that map to
/// in-kernel `PathPattern` deny rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ToolRule {
    /// Tool name (map key), e.g. `write_file` or the `*` wildcard.
    pub name: String,
    /// Whether the tool is permitted.
    pub allow: bool,
    /// Raw CEL-ish `requires_approval_if` expression, if present.
    pub requires_approval_if: Option<String>,
}

/// The canonical policy document shared across enforcement layers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyDocument {
    /// Human-readable policy name (`metadata.name`).
    pub name: Option<String>,
    /// Network egress policy.
    pub network: Option<NetworkPolicy>,
    /// Capability allow/deny floor for this policy scope.
    pub capabilities: Option<CapabilitySet>,
    /// Per-tool rules, in declaration order.
    pub tools: Vec<ToolRule>,
}

