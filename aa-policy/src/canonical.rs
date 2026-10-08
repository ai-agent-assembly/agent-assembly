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

use crate::document::PolicyDocument;

/// Map an `aa_core::Capability` onto the canonical `aa_security` capability.
///
/// The two enums share an identical variant vocabulary; this is a total,
/// lossless mapping kept explicit so a future divergence is a compile error.
fn to_canon_capability(cap: &aa_core::Capability) -> CanonCapability {
    match cap {
        aa_core::Capability::FileRead => CanonCapability::FileRead,
        aa_core::Capability::FileWrite => CanonCapability::FileWrite,
        aa_core::Capability::FileDelete => CanonCapability::FileDelete,
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
    /// The shared dimensions — capabilities, network egress, tool rules, the
    /// path scope (AAASM-5751) and the syscall allowlist (AAASM-5753) — are
    /// carried over. L7-only sections (budget, schedule, data scanner,
    /// approval routing) are intentionally dropped; they are documented as
    /// L7-only carve-outs in `aa_security::policy::ebpf::L7_ONLY_DIMENSIONS`.
    ///
    /// A dimension the canonical AST models is either carried here or listed
    /// there as a deliberate carve-out. Silently dropping one is the defect
    /// AAASM-5753 records: it compiles, validates and ships, and the loss shows
    /// up only as a downstream layer reporting a domain nobody restricted.
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
            // AAASM-5753 — the syscall-allowlist node (AAASM-3624) crosses the
            // bridge. It previously did not: this site hard-coded `None`, so a
            // document that reached the canonical AST here carried no syscall
            // allowlist however it was authored, and the AAASM-5707 lowering
            // could report the domain only as unstated.
            //
            // Both `Option` states are carried verbatim, and the difference
            // between them is the security content: `None` is "the operator
            // said nothing", `Some` with an empty set is "a restriction is in
            // force and permits no call". Collapsing the second onto the first
            // would read the strictest posture the schema can express as the
            // absence of one.
            syscall_allowlist: self.syscall_allowlist.clone(),
            // AAASM-5751 — the path-scope node, on the same terms. Both are a
            // move rather than a translation: this document holds the canonical
            // types themselves, so there is no gateway-side twin that could be
            // forgotten here and no second definition to drift.
            filesystem: self.filesystem.clone(),
        }
    }
}

/// Canonical form of one authored [`crate::document::LeaseGrant`]
/// (AAASM-6275).
///
/// Structurally identical to the validated [`LeaseGrant`] today — there is no
/// richer L7-only computation to fold in yet, unlike `budget`/`schedule`'s
/// relationship to their raw sections. Kept as its own type and reached
/// through its own method ([`PolicyDocument::to_canonical_leases`]) rather
/// than folded into [`PolicyDocument::to_canonical`], and that separation is
/// deliberate: [`to_canonical`](PolicyDocument::to_canonical) projects onto
/// [`CanonPolicyDocument`], the exact AST `aa_isolation::lowering::lower_policy`
/// reads to build `ControlRequirement`s. A lease must never be reachable
/// through that path — see [`crate::document::LeaseDomain`]'s doc comment for
/// the hazard this separation exists to prevent — so this is a different
/// function, reading a different source field, writing to a type
/// `aa_security` never sees.
///
/// [`LeaseGrant`]: crate::document::LeaseGrant
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLeaseGrant {
    /// Which capability domain this lease grants authority over.
    pub domain: crate::document::LeaseDomain,
    /// What within the domain the lease covers.
    pub scope: crate::document::LeaseScope,
    /// Maximum number of times this lease may be exercised.
    pub max_count: Option<u64>,
    /// Seconds from issuance before this lease expires.
    pub ttl_seconds: Option<u64>,
    /// Whether a child launch may inherit this lease, narrowed.
    pub delegable: bool,
    /// Free-text identity reference this lease is issued on behalf of.
    pub issuer: Option<String>,
    /// The named policy rule this lease was authored under.
    pub policy_rule: Option<String>,
    /// A reference to a recorded approval, when issuance was gated on one.
    pub approval_ref: Option<String>,
    /// Why this lease is granted, in words an operator can act on.
    pub reason: String,
}

impl From<&crate::document::LeaseGrant> for CanonicalLeaseGrant {
    fn from(grant: &crate::document::LeaseGrant) -> Self {
        Self {
            domain: grant.domain,
            scope: grant.scope.clone(),
            max_count: grant.max_count,
            ttl_seconds: grant.ttl_seconds,
            delegable: grant.delegable,
            issuer: grant.issuer.clone(),
            policy_rule: grant.policy_rule.clone(),
            approval_ref: grant.approval_ref.clone(),
            reason: grant.reason.clone(),
        }
    }
}

impl PolicyDocument {
    /// Lower this document's authored leases into their canonical form.
    ///
    /// Deliberately separate from [`Self::to_canonical`] — see
    /// [`CanonicalLeaseGrant`]'s doc comment for why.
    pub fn to_canonical_leases(&self) -> Vec<CanonicalLeaseGrant> {
        self.leases.iter().map(CanonicalLeaseGrant::from).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aa_core::CapabilitySet;

    use super::*;
    use crate::document::ToolPolicy;
    use crate::scope::PolicyScope;

    fn base_doc() -> PolicyDocument {
        PolicyDocument {
            name: Some("t".to_string()),
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: None,
            filesystem: None,
            syscall_allowlist: None,
            leases: Vec::new(),
        }
    }

    #[test]
    fn projects_capabilities() {
        let mut caps = CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::FileWrite);
        caps.allow.insert(aa_core::Capability::FileRead);
        let mut doc = base_doc();
        doc.capabilities = Some(caps);

        let canon = doc.to_canonical();
        let cc = canon.capabilities.unwrap();
        assert!(cc.deny.contains(&CanonCapability::FileWrite));
        assert!(cc.allow.contains(&CanonCapability::FileRead));
    }

    #[test]
    fn projects_network_and_sorted_tools() {
        let mut doc = base_doc();
        doc.network = Some(crate::document::NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        doc.tools.insert(
            "zebra".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        doc.tools.insert(
            "alpha".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: Some("path starts_with \"/etc\"".to_string()),
            },
        );

        let canon = doc.to_canonical();
        assert_eq!(canon.egress_allowlist(), ["api.openai.com"]);
        // deterministic order
        assert_eq!(canon.tools[0].name, "alpha");
        assert_eq!(canon.tools[1].name, "zebra");
        assert_eq!(
            canon.tools[0].requires_approval_if.as_deref(),
            Some("path starts_with \"/etc\"")
        );
    }

    /// AAASM-5751 / AAASM-5753 — both operator-authored nodes that hold a
    /// canonical type verbatim must survive the bridge.
    ///
    /// Until AAASM-5753 the syscall node was the control here: it was dropped
    /// by construction, so the two nodes behaved differently and that
    /// difference was the assertion. Both cross now, so the control has moved
    /// to the *unstated* document beside each one — a bridge that manufactured
    /// a node, or that hard-coded either field, fails one half.
    #[test]
    fn the_path_scope_and_syscall_nodes_both_cross_the_bridge() {
        use aa_security::policy::{FilesystemPolicy, PathScope, Syscall, SyscallAllowlist};

        let mut doc = base_doc();
        doc.filesystem = Some(FilesystemPolicy {
            read: Some(PathScope::from_paths(["/workspace"]).unwrap()),
            write: Some(PathScope::from_paths(Vec::<&str>::new()).unwrap()),
        });
        doc.syscall_allowlist = Some(SyscallAllowlist::from_names(["read", "close"]).unwrap());

        let canon = doc.to_canonical();
        let fs = canon.filesystem.as_ref().expect("the path node crosses");
        assert!(fs.read.as_ref().unwrap().permits("/workspace/src/main.rs"));
        assert!(!fs.read.as_ref().unwrap().permits("/etc/passwd"));
        assert!(fs.write.as_ref().unwrap().permits_nothing());

        let allow = canon.syscall_allowlist.as_ref().expect("the syscall node crosses");
        assert!(allow.permits(Syscall::Read));
        assert!(allow.permits(Syscall::Close));
        assert!(!allow.permits(Syscall::Openat));

        // The controls: an unstated node stays unstated across the bridge
        // rather than becoming an empty (deny-all) or absent-but-present value.
        let silent = base_doc().to_canonical();
        assert!(silent.filesystem.is_none());
        assert!(silent.syscall_allowlist.is_none());
    }

    /// AAASM-5753 — the authored allowlist arrives as the **same set**.
    ///
    /// Asserting `is_some()` would pass against a bridge that manufactured an
    /// allowlist of its own, which is a different bug with the same shape as
    /// the one this ticket fixes. So the assertion is set equality in both
    /// directions — the exact membership, plus a name from the vocabulary the
    /// author did **not** write.
    ///
    /// The control moves with the authored document rather than sitting beside
    /// it: two fixtures with disjoint allowlists are projected, and each is
    /// asserted against its own author. A projection returning a fixed value —
    /// `None`, an empty set, or a hard-coded set — fails at least one of them,
    /// so a pass is attributable to the node being carried and not to the
    /// fixture happening to match.
    #[test]
    fn an_authored_syscall_allowlist_arrives_as_the_same_set() {
        use aa_security::policy::{Syscall, SyscallAllowlist};

        let mut io = base_doc();
        io.syscall_allowlist = Some(SyscallAllowlist::from_names(["read", "openat", "exit_group"]).unwrap());
        let io_canon = io.to_canonical();

        // `allowed_syscalls` reads through a BTreeSet, so the vector is the set
        // in enum-declaration order: Read (0), Openat (3), ExitGroup (12).
        assert_eq!(
            io_canon.allowed_syscalls(),
            vec![Syscall::Read, Syscall::Openat, Syscall::ExitGroup],
            "the projected allowlist is not the authored set"
        );
        let io_node = io_canon.syscall_allowlist.as_ref().expect("stated");
        assert!(!io_node.permits(Syscall::Write), "the projection widened the set");
        assert!(!io_node.permits_nothing());

        // The moving control: a disjoint second author, through the same call.
        let mut mem = base_doc();
        mem.syscall_allowlist = Some(SyscallAllowlist::from_names(["mmap", "munmap", "brk"]).unwrap());
        let mem_canon = mem.to_canonical();
        assert_eq!(
            mem_canon.allowed_syscalls(),
            vec![Syscall::Mmap, Syscall::Munmap, Syscall::Brk]
        );
        assert_ne!(
            io_canon.syscall_allowlist, mem_canon.syscall_allowlist,
            "two disjoint authors projected onto one allowlist"
        );
    }

    /// AAASM-5753 — an **absent** allowlist and an **empty** one are two facts.
    ///
    /// The schema's answer, stated: absent (`None`) is the operator having said
    /// nothing about syscalls; empty (`Some` with no members) is a restriction
    /// in force that permits no call — the strictest posture authorable here.
    /// That is the reading `aa_security::policy::FilesystemPolicy` documents
    /// for an empty `PathScope` and the one
    /// `aa_security::policy::PolicyDocument::from_yaml` already gives an
    /// `allow`-less `syscalls:` section, so the two ingest paths for one
    /// on-disk contract agree rather than each inventing an answer.
    ///
    /// The bridge has to preserve the difference, because collapsing empty onto
    /// absent downstream reads the strictest posture as the absence of one.
    #[test]
    fn an_absent_syscall_allowlist_stays_distinguishable_from_an_empty_one() {
        use aa_security::policy::SyscallAllowlist;

        let absent = base_doc().to_canonical();
        assert!(absent.syscall_allowlist.is_none(), "an absent node was manufactured");

        let mut doc = base_doc();
        doc.syscall_allowlist = Some(SyscallAllowlist::default());
        let empty = doc.to_canonical();

        let node = empty
            .syscall_allowlist
            .as_ref()
            .expect("a stated empty allowlist is in force, not silence");
        assert!(node.permits_nothing());
        assert_ne!(
            absent.syscall_allowlist, empty.syscall_allowlist,
            "an in-force deny-all collapsed onto silence"
        );

        // Both read as "no syscall is permitted" through the accessor, which is
        // exactly why the accessor cannot be what tells them apart.
        assert!(absent.allowed_syscalls().is_empty());
        assert!(empty.allowed_syscalls().is_empty());
    }

    #[test]
    fn canonical_lowers_to_ebpf_rules() {
        // Proves the same gateway document feeds the kernel lowering.
        let mut caps = CapabilitySet::default();
        caps.deny.insert(aa_core::Capability::FileWrite);
        let mut doc = base_doc();
        doc.capabilities = Some(caps);

        let rules = aa_security::policy::lower_to_ebpf(&doc.to_canonical());
        assert!(rules.deny_paths().any(|p| p == "/etc"));
    }

    // ── AAASM-6275 — authority.leases canonical lowering ────────────────────

    #[test]
    fn leases_round_trip_through_to_canonical_leases() {
        use crate::document::{LeaseDomain, LeaseGrant, LeaseScope};

        let mut doc = base_doc();
        doc.leases = vec![LeaseGrant {
            domain: LeaseDomain::NetworkEgress,
            scope: LeaseScope::Selectors(vec!["api.example.com".to_string()]),
            max_count: Some(10),
            ttl_seconds: Some(3600),
            delegable: true,
            issuer: Some("ops-team".to_string()),
            policy_rule: Some("egress-build-step".to_string()),
            approval_ref: Some("approval-123".to_string()),
            reason: "scoped egress for the build step".to_string(),
        }];

        let canonical = doc.to_canonical_leases();
        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].domain, LeaseDomain::NetworkEgress);
        assert_eq!(
            canonical[0].scope,
            LeaseScope::Selectors(vec!["api.example.com".to_string()])
        );
        assert_eq!(canonical[0].max_count, Some(10));
        assert_eq!(canonical[0].ttl_seconds, Some(3600));
        assert!(canonical[0].delegable);
        assert_eq!(canonical[0].issuer.as_deref(), Some("ops-team"));
        assert_eq!(canonical[0].reason, "scoped egress for the build step");
    }

    #[test]
    fn no_authored_leases_lowers_to_an_empty_canonical_list() {
        assert!(base_doc().to_canonical_leases().is_empty());
    }

    /// The central hazard this node exists to avoid, stated as an assertion:
    /// authoring a lease must never change the `ControlRequirement`-building
    /// bridge's output. `to_canonical` and `to_canonical_leases` must stay
    /// provably independent, not merely independent by convention.
    #[test]
    fn authoring_a_lease_does_not_change_the_control_requirement_bridge() {
        use crate::document::{LeaseDomain, LeaseGrant, LeaseScope};

        let without = base_doc().to_canonical();

        let mut with_lease = base_doc();
        with_lease.leases = vec![LeaseGrant {
            domain: LeaseDomain::FilesystemWrite,
            scope: LeaseScope::Whole,
            max_count: None,
            ttl_seconds: None,
            delegable: false,
            issuer: None,
            policy_rule: None,
            approval_ref: None,
            reason: "fixture".to_string(),
        }];

        assert_eq!(without, with_lease.to_canonical());
    }
}
