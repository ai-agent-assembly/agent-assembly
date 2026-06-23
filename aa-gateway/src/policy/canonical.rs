//! Bridge from the gateway's rich [`PolicyDocument`] to the canonical,
//! cross-layer [`aa_security::policy::PolicyDocument`] (AAASM-3607).
//!
//! The canonical AST in `aa-security` is the single source of truth shared by
//! the gateway rule engine (L7) and the eBPF map compiler (kernel). The gateway
//! keeps its richer in-crate document for L7-only evaluation concerns (CEL
//! contexts, history stores, budget accounting), but it projects onto the
//! canonical AST here so the *exact same* typed definition feeds the kernel
//! lowering — there is no second, divergent copy of the shared dimensions.
//!
//! This is the mechanism that closes the schema-mismatch seam an attacker would
//! otherwise live in: the kernel rules are lowered (`aa_security::policy::
//! lower_to_ebpf`) from what this bridge produces, which is derived from the
//! same validated gateway document the L7 engine evaluates.

use aa_security::policy::{
    Capability as CanonCapability, CapabilitySet as CanonCapabilitySet, NetworkPolicy as CanonNetworkPolicy,
    PolicyDocument as CanonPolicyDocument, ToolRule as CanonToolRule,
};

use crate::policy::document::PolicyDocument;

/// Map an `aa_core::Capability` onto the canonical `aa_security` capability.
///
/// The two enums share an identical variant vocabulary; this is a total,
/// lossless mapping kept explicit so a future divergence is a compile error.
fn to_canon_capability(cap: &aa_core::Capability) -> CanonCapability {
    match cap {
        aa_core::Capability::FileRead => CanonCapability::FileRead,
        aa_core::Capability::FileWrite => CanonCapability::FileWrite,
        aa_core::Capability::NetworkOutbound => CanonCapability::NetworkOutbound,
        aa_core::Capability::NetworkInbound => CanonCapability::NetworkInbound,
        aa_core::Capability::TerminalExec => CanonCapability::TerminalExec,
        aa_core::Capability::McpTool(n) => CanonCapability::McpTool(n.clone()),
        aa_core::Capability::Model(n) => CanonCapability::Model(n.clone()),
        aa_core::Capability::AgentSpawn => CanonCapability::AgentSpawn,
    }
}

impl PolicyDocument {
    /// Project this validated gateway document onto the canonical, cross-layer
    /// [`aa_security::policy::PolicyDocument`].
    ///
    /// Only the shared dimensions (capabilities, network egress, tool rules)
    /// are carried over; L7-only sections (budget, schedule, data scanner,
    /// approval routing) are intentionally dropped — they are documented as
    /// L7-only carve-outs in `aa_security::policy::ebpf::L7_ONLY_DIMENSIONS`.
    pub fn to_canonical(&self) -> CanonPolicyDocument {
        let capabilities = self.capabilities.as_ref().map(|caps| {
            let mut set = CanonCapabilitySet::default();
            for c in &caps.allow {
                set.allow.insert(to_canon_capability(c));
            }
            for c in &caps.deny {
                set.deny.insert(to_canon_capability(c));
            }
            set
        });

        let network = self.network.as_ref().map(|n| CanonNetworkPolicy {
            allowlist: n.allowlist.clone(),
        });

        let mut tools: Vec<CanonToolRule> = self
            .tools
            .iter()
            .map(|(name, t)| CanonToolRule {
                name: name.clone(),
                allow: t.allow,
                requires_approval_if: t.requires_approval_if.clone(),
            })
            .collect();
        // HashMap iteration order is nondeterministic; sort so the canonical
        // projection (and the kernel rules lowered from it) are stable.
        tools.sort_by(|a, b| a.name.cmp(&b.name));

        CanonPolicyDocument {
            name: self.name.clone(),
            network,
            capabilities,
            tools,
        }
    }
}

