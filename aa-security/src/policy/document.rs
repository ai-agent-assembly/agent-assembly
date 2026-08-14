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
use super::syscall::SyscallAllowlist;

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
    /// Kernel syscall allowlist for this workload (AAASM-3624). When set, the
    /// eBPF enforcement probe default-denies any syscall not listed for a
    /// monitored PID. Lowered to `SYSCALL_ALLOWLIST` map entries by
    /// AAASM-3635.
    pub syscall_allowlist: Option<SyscallAllowlist>,
}

impl PolicyDocument {
    /// Return the capability deny set, or an empty slice if unset.
    pub fn denied_capabilities(&self) -> Vec<&super::capability::Capability> {
        self.capabilities
            .as_ref()
            .map(|c| c.deny.iter().collect())
            .unwrap_or_default()
    }

    /// Return the network egress allowlist, or an empty slice if unset.
    pub fn egress_allowlist(&self) -> &[String] {
        self.network.as_ref().map(|n| n.allowlist.as_slice()).unwrap_or(&[])
    }

    /// Return the permitted syscalls, or an empty iterator if no syscall
    /// allowlist is set.
    pub fn allowed_syscalls(&self) -> Vec<super::syscall::Syscall> {
        self.syscall_allowlist
            .as_ref()
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::super::capability::Capability;
    use super::*;

    #[test]
    fn default_document_is_empty() {
        let doc = PolicyDocument::default();
        assert!(doc.name.is_none());
        assert!(doc.network.is_none());
        assert!(doc.capabilities.is_none());
        assert!(doc.tools.is_empty());
        assert!(doc.denied_capabilities().is_empty());
        assert!(doc.egress_allowlist().is_empty());
        assert!(doc.syscall_allowlist.is_none());
        assert!(doc.allowed_syscalls().is_empty());
    }

    #[test]
    fn accessors_read_through() {
        use super::super::syscall::{Syscall, SyscallAllowlist};
        let mut caps = CapabilitySet::default();
        caps.deny.insert(Capability::FileWrite);
        let doc = PolicyDocument {
            name: Some("strict".to_string()),
            network: Some(NetworkPolicy {
                allowlist: vec!["api.openai.com".to_string()],
            }),
            capabilities: Some(caps),
            tools: vec![ToolRule {
                name: "write_file".to_string(),
                allow: false,
                requires_approval_if: None,
            }],
            syscall_allowlist: Some(SyscallAllowlist::from_names(["read", "write"]).unwrap()),
        };
        assert_eq!(doc.denied_capabilities(), vec![&Capability::FileWrite]);
        assert_eq!(doc.egress_allowlist(), ["api.openai.com"]);
        assert_eq!(doc.tools.len(), 1);
        assert_eq!(doc.allowed_syscalls(), vec![Syscall::Read, Syscall::Write]);
    }
}
