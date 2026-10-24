//! Policy-authored lease grants lowered into `aa-isolation` vocabulary
//! (AAASM-6259, moved from `aa-cli`'s `aasm run`).
//!
//! Inside the `devtool` strip-for-publish region: `aa-isolation` is
//! `publish = false`, so this module does not exist in the crates.io build.

use aa_isolation::lease_lowering::AuthoredLease;
use aa_isolation::{CapabilityDomain, RequirementScope};
use aa_policy::LeaseDomain;

/// Map an authored lease domain to its capability domain.
///
/// Exhaustive with no wildcard arm: a variant added to either side without an
/// arm here is a compile error, never a silently dropped grant.
pub fn capability_domain_from(domain: LeaseDomain) -> CapabilityDomain {
    match domain {
        LeaseDomain::FilesystemRead => CapabilityDomain::FilesystemRead,
        LeaseDomain::FilesystemWrite => CapabilityDomain::FilesystemWrite,
        LeaseDomain::NetworkEgress => CapabilityDomain::NetworkEgress,
        LeaseDomain::NameResolution => CapabilityDomain::NameResolution,
        LeaseDomain::Syscall => CapabilityDomain::Syscall,
        LeaseDomain::ProcessCreation => CapabilityDomain::ProcessCreation,
        LeaseDomain::Ipc => CapabilityDomain::Ipc,
        LeaseDomain::Credential => CapabilityDomain::Credential,
        LeaseDomain::Resource => CapabilityDomain::Resource,
        LeaseDomain::WorkspaceTransaction => CapabilityDomain::WorkspaceTransaction,
    }
}

/// Convert one authored [`aa_policy::CanonicalLeaseGrant`] into this
/// crate's own [`AuthoredLease`] (AAASM-6277).
///
/// `aa-isolation` cannot depend on `aa-policy`'s type — see
/// `aa_isolation::lease_lowering`'s own module documentation, "Why the
/// input is not `aa_policy`'s own type" — so a crate that depends on
/// both has to host this conversion. It lives here, in `aa-runtime`, so
/// `aasm run` and the runtime's lease gate share one implementation; a second
/// copy could drift on the selector prefix below and silently stop matching. The domain
/// match is **exhaustive, with no wildcard arm**: a future
/// `LeaseDomain`/`CapabilityDomain` variant added to one side without a
/// corresponding arm here is a compile error, never a silently dropped
/// grant.
///
/// `LeaseScope::Selectors` is converted through
/// [`aa_isolation::permit_only_selector`] — never passed through
/// verbatim. `aa_isolation::lowering::lower_policy`'s own requirement
/// selectors, `egress_gate`'s coverage check and `scope_order`'s
/// comparator all operate on the `permit-only:`-prefixed vocabulary;
/// `authority.leases`' own validator fixtures author bare selectors
/// (e.g. `api.example.com`, not `permit-only:api.example.com`). Without
/// this conversion, no authored selector lease would ever match anything
/// it is meant to cover. An author who writes the prefix themselves gets
/// double-prefixed (`permit-only:permit-only:x`), which can never match —
/// that is a safe refusal, not a silent admission, which is why this
/// applies the prefix unconditionally rather than detecting and skipping
/// an already-prefixed selector.
pub fn authored_lease_from(grant: &aa_policy::CanonicalLeaseGrant) -> AuthoredLease {
    let domain = capability_domain_from(grant.domain);

    let scope = match &grant.scope {
        aa_policy::LeaseScope::Whole => RequirementScope::Whole,
        aa_policy::LeaseScope::Selectors(selectors) => RequirementScope::Selectors(
            selectors
                .iter()
                .map(|s| aa_isolation::permit_only_selector(s))
                .collect(),
        ),
    };

    AuthoredLease {
        domain,
        scope,
        max_count: grant.max_count,
        ttl_seconds: grant.ttl_seconds,
        delegable: grant.delegable,
        issuer: grant.issuer.clone(),
        policy_rule: grant.policy_rule.clone(),
        approval_ref: grant.approval_ref.clone(),
        reason: grant.reason.clone(),
    }
}
