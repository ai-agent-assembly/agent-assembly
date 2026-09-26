//! The runtime-wide explicit-authority contract (AAASM-6160, ADR 0038).
//!
//! # The invariant this module exists to hold
//!
//! *Effective runtime authority is derived only from explicit
//! [`ExecutionSpec`]/policy grants, validated [`CapabilityLease`]s and
//! documented compatibility residuals — never merely from supervisor/host
//! possession.*
//!
//! Before this module, nothing in this crate asked "was this run ever
//! authorized to touch this domain" — [`crate::plan::negotiate`] only asks
//! "can the selected backend mechanically do this". Those are independent
//! questions: a backend can be perfectly capable of enforcing
//! [`CapabilityDomain::Credential`] and a run can still have no business
//! touching it. [`authority_gate`] is where the first question gets asked, and
//! it runs *before* `negotiate` so that a domain no explicit grant covers is
//! refused before backend capability is even consulted — closing the gap
//! `negotiate`'s own documentation names: a domain no [`ControlRequirement`]
//! mentions simply never enters `negotiate`'s loop, so nothing there can ever
//! refuse it by omission. Composing the two in this order, rather than folding
//! this module's checks into `negotiate` itself, is what keeps `negotiate`
//! the single decision point for backend-capability questions while giving
//! authority its own, independently testable decision point for
//! provenance questions.
//!
//! # Three mechanisms, one contract
//!
//! * [`EffectiveAuthority`] is a domain-total record of what a spec is
//!   actually authorized for. It is constructible only via
//!   [`EffectiveAuthority::deny_all`], so every domain starts explicitly
//!   denied — there is no default that reads as "ambiently allowed", and
//!   nothing in this type's own API ever reads a grant out of
//!   [`crate::capability::BackendCapabilities`] or out of the host
//!   environment. That absence is the proof behind this crate's negative
//!   control: supervisor/host possession has no code path into this type at
//!   all.
//! * [`AuthorityWitness`] is proof, not data — its only field is private and
//!   its only constructor is inside this module's [`authority_gate`]. A call
//!   site that requires one as a parameter before proceeding cannot be
//!   satisfied by constructing authority some other way; it has to have
//!   called the gate.
//! * [`authority_gate`] is the function that actually walks a spec's
//!   requirements against an [`EffectiveAuthority`] built from that same spec
//!   and either returns the witness or a fully specific
//!   [`AuthorityRefusal`].
//!
//! # The compatibility residual, precisely
//!
//! ADR 0038 requires existing rc.7 policy/config to remain valid, and no rc.7
//! spec has ever carried a [`CapabilityLease`]. [`EffectiveAuthority::from_spec`]
//! therefore treats "this spec carries no lease at all" as a single, spec-wide
//! signal rather than inspecting leases domain by domain: when
//! [`ExecutionSpec::leases`] is empty, every domain a [`ControlRequirement`]
//! names is recorded as [`AuthorityState::CompatibilityResidual`] — an
//! explicit policy grant, sourced from the spec's own requirement list, which
//! is exactly what an rc.7 policy already produces. The moment a spec carries
//! even one lease, this compatibility path stops applying spec-wide: every
//! domain a requirement names must then have its own valid, covering lease, or
//! [`authority_gate`] refuses it — a [`ControlRequirement`] alone is no longer
//! read as a grant once the caller has opted into the lease system, which is
//! exactly the property this crate's negative control test pins down (see
//! `tests::supervisor_possession_without_a_lease_is_denied_once_leases_are_in_play`).

use std::time::SystemTime;

use crate::capability::CapabilityDomain;
use crate::lease::{CapabilityLease, LeaseInvalid};
use crate::spec::{ExecutionSpec, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// What a spec is actually authorized for, on one [`CapabilityDomain`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AuthorityState {
    /// No explicit grant exists for this domain. The default for every domain
    /// under [`EffectiveAuthority::deny_all`], and the only state a domain
    /// this module never heard a case for can be in.
    Denied,
    /// A validated [`CapabilityLease`] authorizes this domain.
    ///
    /// Boxed: `CapabilityLease` carries a `LeaseBasis` and a `RequirementScope`,
    /// both of which can hold arbitrarily long strings/vectors, and
    /// `clippy::large_enum_variant` is right that inlining it would make every
    /// `AuthorityState` — including the overwhelmingly common `Denied` — pay
    /// for the largest variant's size.
    Leased(Box<CapabilityLease>),
    /// This domain's authority is the rc.7 compatibility residual: the spec
    /// carries no lease at all, and a [`ControlRequirement`] named this
    /// domain, which under the pre-lease contract already was the explicit
    /// policy grant. See this module's documentation for exactly when this
    /// applies and when it stops applying.
    CompatibilityResidual,
}

impl AuthorityState {
    /// Whether this state authorizes the domain at all.
    pub fn is_granted(&self) -> bool {
        !matches!(self, Self::Denied)
    }

    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Leased(_) => "leased",
            Self::CompatibilityResidual => "compatibility_residual",
        }
    }
}

/// A domain-total record of what a spec is authorized for.
///
/// "Domain-total" means every member of [`CapabilityDomain::ALL`] has an entry
/// — there is no domain this type can be silent about, which is what makes
/// [`state`](Self::state) a total function rather than one that has to define
/// what an absent entry means. Nothing here is ever read from
/// [`crate::capability::BackendCapabilities`], a process environment, or any
/// other notion of what the supervisor happens to possess: the only inputs
/// are an [`ExecutionSpec`]'s own requirements and leases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAuthority {
    // A `Vec` keyed by `CapabilityDomain::ALL`'s own order rather than a map:
    // this type's whole point is that every domain has an entry, and building
    // it by iterating `ALL` once, at construction, is what makes "every
    // domain" a fact the compiler can help hold rather than a documentation
    // claim a map's `Entry` API could silently stop being true of.
    states: Vec<(CapabilityDomain, AuthorityState)>,
}

impl EffectiveAuthority {
    /// Every domain, explicitly denied.
    ///
    /// The only public constructor. There is deliberately no
    /// `EffectiveAuthority::from_backend_capabilities` or
    /// `EffectiveAuthority::ambient()` — adding either would give supervisor
    /// possession a way back into this type.
    pub fn deny_all() -> Self {
        Self {
            states: CapabilityDomain::ALL
                .iter()
                .map(|&d| (d, AuthorityState::Denied))
                .collect(),
        }
    }

    fn set(&mut self, domain: CapabilityDomain, state: AuthorityState) {
        if let Some(entry) = self.states.iter_mut().find(|(d, _)| *d == domain) {
            entry.1 = state;
        }
    }

    /// The authority state recorded for `domain`.
    ///
    /// Total: every [`CapabilityDomain`] has an entry from construction, so
    /// this never needs to return an `Option`.
    pub fn state(&self, domain: CapabilityDomain) -> &AuthorityState {
        self.states
            .iter()
            .find(|(d, _)| *d == domain)
            .map(|(_, s)| s)
            .expect("EffectiveAuthority is domain-total by construction")
    }

    /// Whether `spec` carries at least one [`CapabilityLease`] — the signal
    /// that switches [`from_spec`](Self::from_spec) out of the rc.7
    /// compatibility path. See this module's documentation.
    pub fn is_lease_aware(spec: &ExecutionSpec) -> bool {
        !spec.leases().is_empty()
    }

    /// Build the authority state a spec actually has.
    ///
    /// See this module's documentation for the compatibility rule this method
    /// implements. Every lease `spec` carries is recorded as
    /// [`AuthorityState::Leased`] regardless of whether it currently
    /// validates — validity is a function of *when* a lease is checked, not
    /// of the lease's own existence, so [`authority_gate`] is what decides,
    /// at the instant it actually needs an answer, whether a recorded lease
    /// is honored. Recording an invalid lease as `Denied` here instead would
    /// throw away *why* it is invalid before [`authority_gate`] ever gets to
    /// say so.
    ///
    /// # Errors
    ///
    /// [`AuthorityBuildError::DuplicateLeaseDomain`] when `spec` carries two
    /// leases for the same domain — accepting one over the other would decide
    /// a security question by declaration order, mirroring
    /// [`crate::capability::DuplicateDomain`]'s reasoning for
    /// [`crate::capability::BackendCapabilities`].
    pub fn from_spec(spec: &ExecutionSpec) -> Result<Self, AuthorityBuildError> {
        let mut authority = Self::deny_all();

        if !Self::is_lease_aware(spec) {
            for requirement in spec.requirements() {
                authority.set(requirement.domain(), AuthorityState::CompatibilityResidual);
            }
            return Ok(authority);
        }

        for (index, lease) in spec.leases().iter().enumerate() {
            if spec.leases()[..index].iter().any(|l| l.domain() == lease.domain()) {
                return Err(AuthorityBuildError::DuplicateLeaseDomain(lease.domain()));
            }
            authority.set(lease.domain(), AuthorityState::Leased(Box::new(lease.clone())));
        }

        Ok(authority)
    }
}

/// Why [`EffectiveAuthority::from_spec`] could not build a result at all.
///
/// Distinct from [`AuthorityRefusal`]: this is a malformed *input* (two
/// leases claiming the same domain), not a legitimate spec that failed the
/// gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityBuildError {
    /// Two leases in the same spec name the same domain.
    DuplicateLeaseDomain(CapabilityDomain),
}

impl core::fmt::Display for AuthorityBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateLeaseDomain(domain) => {
                write!(f, "spec carries two leases for domain `{domain}`")
            }
        }
    }
}

impl std::error::Error for AuthorityBuildError {}

/// Unforgeable-by-construction proof that [`authority_gate`] ran and every
/// requirement in the spec it checked had explicit authority behind it.
///
/// The single private field and the absence of any public constructor other
/// than [`authority_gate`] are the whole mechanism: a call site that takes
/// `AuthorityWitness` as a parameter cannot be satisfied by building one any
/// other way, anywhere outside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityWitness(());

/// Why [`authority_gate`] refused a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthorityRefusal {
    /// A required domain has no explicit grant at all — the negative-control
    /// case: whatever the backend or supervisor possesses for this domain,
    /// nothing in the spec authorized the run to use it.
    NoExplicitGrant {
        /// The domain with no grant.
        domain: CapabilityDomain,
    },
    /// A lease covers the domain but is not currently valid.
    LeaseInvalid {
        /// The domain the invalid lease was for.
        domain: CapabilityDomain,
        /// Why.
        reason: LeaseInvalid,
    },
    /// A lease covers the domain and is valid, but its scope does not cover
    /// what the requirement actually asks for.
    LeaseScopeInsufficient {
        /// The domain whose lease did not cover the requested scope.
        domain: CapabilityDomain,
    },
    /// [`EffectiveAuthority::from_spec`] could not be built at all.
    Malformed(AuthorityBuildError),
}

impl AuthorityRefusal {
    /// The domain this refusal concerns, when it names one.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::NoExplicitGrant { domain }
            | Self::LeaseInvalid { domain, .. }
            | Self::LeaseScopeInsufficient { domain } => Some(*domain),
            Self::Malformed(AuthorityBuildError::DuplicateLeaseDomain(domain)) => Some(*domain),
        }
    }
}

impl core::fmt::Display for AuthorityRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoExplicitGrant { domain } => {
                write!(f, "no explicit grant or lease authorizes domain `{domain}`")
            }
            Self::LeaseInvalid { domain, reason } => {
                write!(f, "the lease for domain `{domain}` is not valid: {reason:?}")
            }
            Self::LeaseScopeInsufficient { domain } => {
                write!(f, "the lease for domain `{domain}` does not cover the requested scope")
            }
            Self::Malformed(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for AuthorityRefusal {}

/// Whether `scope` is covered by `authority`'s recorded state for `domain`.
fn covered(state: &AuthorityState, domain: CapabilityDomain, scope: &RequirementScope) -> Result<(), AuthorityRefusal> {
    match state {
        AuthorityState::Denied => Err(AuthorityRefusal::NoExplicitGrant { domain }),
        AuthorityState::CompatibilityResidual => Ok(()),
        AuthorityState::Leased(lease) => {
            if lease.covers(scope) {
                Ok(())
            } else {
                Err(AuthorityRefusal::LeaseScopeInsufficient { domain })
            }
        }
    }
}

/// Check every requirement `spec` states against the explicit authority it
/// actually carries, before [`crate::plan::negotiate`] ever asks what the
/// backend can mechanically do.
///
/// This is the second of the two questions this crate's negotiation now
/// answers in sequence: `authority_gate` asks "was this authorized", and only
/// once that holds does `negotiate` get to ask "can the backend do it". A
/// caller composes them by calling this first and calling `negotiate` only on
/// success — see `aa-cli`'s `IsolationPlan::resolve_boundary` for the one
/// production call site this ticket wires.
///
/// `now` is a parameter for the same reason [`CapabilityLease::validate_at`]
/// takes one: a security decision must not depend on reading the wall clock
/// from inside the function under test.
///
/// # Errors
///
/// [`AuthorityRefusal`] on the first requirement whose domain has no covering,
/// valid, explicit grant. Unlike [`crate::plan::PlanRefusal`], this stops at
/// the first failure rather than collecting every one — the gate's job is to
/// answer "may this proceed to backend negotiation at all", and a spec that
/// fails it does not reach `negotiate`, so there is no downstream reader that
/// benefits from a complete list the way `PlanRefusal`'s reader (an operator
/// deciding what to change) does.
pub fn authority_gate(spec: &ExecutionSpec, now: SystemTime) -> Result<AuthorityWitness, AuthorityRefusal> {
    let authority = EffectiveAuthority::from_spec(spec).map_err(AuthorityRefusal::Malformed)?;

    for requirement in spec.requirements() {
        let domain = requirement.domain();
        let state = authority.state(domain);
        if let AuthorityState::Leased(lease) = state {
            if let Err(reason) = lease.validate_at(now) {
                return Err(AuthorityRefusal::LeaseInvalid { domain, reason });
            }
        }
        covered(state, domain, requirement.scope())?;
    }

    Ok(AuthorityWitness(()))
}

/// Build the authority a spec actually carries, for reporting purposes only.
///
/// A thin, infallible-in-practice wrapper the reporting layer uses so it does
/// not have to duplicate [`EffectiveAuthority::from_spec`]'s own logic; a
/// malformed spec is reported as every domain `Denied` rather than surfacing
/// a second error type into a projection whose job is to describe what
/// happened, not to gate it a second time.
pub fn effective_authority_for_report(spec: &ExecutionSpec) -> EffectiveAuthority {
    EffectiveAuthority::from_spec(spec).unwrap_or_else(|_| EffectiveAuthority::deny_all())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        BackendAvailability, BackendCapabilities, CapabilityReport, DecisionTiming, Mediation, PlatformBoundary,
        Synchrony,
    };
    use crate::lease::{LeaseBasis, LeaseId, RevocationState};
    use crate::spec::{ControlRequirement, IdentityRef};
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn identity() -> IdentityRef {
        IdentityRef::root("agent-under-test")
    }

    fn base_spec() -> ExecutionSpec {
        ExecutionSpec::new("echo", identity())
    }

    fn lease_for(domain: CapabilityDomain, scope: RequirementScope) -> CapabilityLease {
        CapabilityLease::new(
            LeaseId::new("lease-under-test"),
            identity(),
            domain,
            scope,
            t(1_000),
            t(2_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
    }

    /// `deny_all` must actually deny every domain there is — a domain missing
    /// from `CapabilityDomain::ALL`'s sweep would silently read as
    /// unauthorized-but-untested, which is the opposite of the totality this
    /// type exists to guarantee.
    #[test]
    fn deny_all_denies_every_domain() {
        let authority = EffectiveAuthority::deny_all();
        for &domain in CapabilityDomain::ALL {
            assert_eq!(authority.state(domain), &AuthorityState::Denied);
        }
    }

    /// Falsification target 1: a valid, covering, in-scope lease permits.
    #[test]
    fn valid_in_scope_lease_permits() {
        let spec = base_spec().with_requirement(
            ControlRequirement::observe(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(vec!["/workspace".to_string()])),
        );
        let spec = attach_lease(
            spec,
            lease_for(
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["/workspace".to_string()]),
            ),
        );
        assert!(authority_gate(&spec, t(1_500)).is_ok());
    }

    /// Falsification target 2a: an expired lease denies.
    #[test]
    fn expired_lease_denies() {
        let spec = base_spec().with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead));
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::FilesystemRead, RequirementScope::Whole),
        );
        let result = authority_gate(&spec, t(2_500));
        assert_eq!(
            result,
            Err(AuthorityRefusal::LeaseInvalid {
                domain: CapabilityDomain::FilesystemRead,
                reason: LeaseInvalid::Expired { expires_at: t(2_000) },
            })
        );
    }

    /// Falsification target 2b: a revoked lease denies.
    #[test]
    fn revoked_lease_denies() {
        let spec = base_spec().with_requirement(ControlRequirement::observe(CapabilityDomain::NetworkEgress));
        let revoked = lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole).with_revocation(
            RevocationState::Revoked {
                generation: 1,
                reason: "operator revoked".to_string(),
            },
        );
        let spec = attach_lease(spec, revoked);
        let result = authority_gate(&spec, t(1_500));
        assert!(
            matches!(result, Err(AuthorityRefusal::LeaseInvalid { domain, .. }) if domain == CapabilityDomain::NetworkEgress)
        );
    }

    /// Falsification target 2c: an out-of-scope lease denies.
    #[test]
    fn out_of_scope_lease_denies() {
        let spec = base_spec().with_requirement(
            ControlRequirement::observe(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(vec!["/etc".to_string()])),
        );
        let spec = attach_lease(
            spec,
            lease_for(
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["/workspace".to_string()]),
            ),
        );
        assert_eq!(
            authority_gate(&spec, t(1_500)),
            Err(AuthorityRefusal::LeaseScopeInsufficient {
                domain: CapabilityDomain::FilesystemRead
            })
        );
    }

    /// Falsification target 3, and the key negative control for the AC
    /// "supervisor/parent authority does not appear in the child absent a
    /// grant": once a spec is lease-aware (carries any lease at all), a
    /// *different* domain's `ControlRequirement` — with no lease of its own —
    /// must be denied, even when a `BackendCapabilities` shows the backend
    /// (standing in for "the supervisor") fully possesses that domain
    /// (`Mediation::Enforce`, `DecisionTiming::Pre`, `Synchrony::Sync` — the
    /// exact shape `CapabilityReport::can_prevent` requires). Possession is
    /// never consulted by `authority_gate` at all; this test proves it by
    /// showing the refusal fires without `authority_gate` ever being handed
    /// the capabilities value.
    #[test]
    fn supervisor_possession_without_a_lease_is_denied_once_leases_are_in_play() {
        let fully_possessed_by_backend = CapabilityReport::new(
            CapabilityDomain::Credential,
            Mediation::Enforce,
            DecisionTiming::Pre,
            Synchrony::Sync,
        );
        let capabilities = BackendCapabilities::new(
            BackendAvailability::Available,
            PlatformBoundary::SharedHostKernel,
            vec![fully_possessed_by_backend],
        )
        .expect("single-domain report set is not a duplicate");
        assert!(
            capabilities
                .report_for(CapabilityDomain::Credential)
                .expect("just inserted")
                .can_prevent(),
            "the fixture must actually model full backend possession, or this test proves nothing"
        );

        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::Credential))
            .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead));
        // Opts the spec into lease-aware mode via a lease for an unrelated
        // domain; `Credential` itself gets none.
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::FilesystemRead, RequirementScope::Whole),
        );

        assert_eq!(
            authority_gate(&spec, t(1_500)),
            Err(AuthorityRefusal::NoExplicitGrant {
                domain: CapabilityDomain::Credential
            }),
            "backend possession of a domain must never substitute for an explicit grant"
        );
    }

    /// Falsification target 4: a domain-agnostic version mismatch fails
    /// closed even though the lease's time window and scope both check out.
    #[test]
    fn version_mismatch_fails_closed_despite_otherwise_valid_lease() {
        let spec = base_spec().with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead));
        let stale = lease_for(CapabilityDomain::FilesystemRead, RequirementScope::Whole)
            .with_schema_version(crate::lease::LEASE_SCHEMA_VERSION + 1);
        let spec = attach_lease(spec, stale);
        let result = authority_gate(&spec, t(1_500));
        assert!(matches!(
            result,
            Err(AuthorityRefusal::LeaseInvalid {
                reason: LeaseInvalid::SchemaVersionMismatch { .. },
                ..
            })
        ));
    }

    /// Falsification target 5 (compatibility): an rc.7-shaped spec with no
    /// leases at all must still pass, on the strength of its
    /// `ControlRequirement`s alone — this is the regression test for "existing
    /// rc.7 policy/config remains valid".
    #[test]
    fn legacy_spec_with_no_leases_passes_on_policy_grants_alone() {
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite))
            .with_requirement(ControlRequirement::observe(CapabilityDomain::NetworkEgress));
        assert!(!EffectiveAuthority::is_lease_aware(&spec));
        assert!(authority_gate(&spec, t(1_500)).is_ok());
    }

    /// The same legacy spec, spot-checked: attach one lease anywhere and the
    /// unrelated domain that used to pass on policy grants alone now must be
    /// denied. This is the exact edge the compatibility rule turns on, so it
    /// is worth its own test distinct from the negative-control test above.
    #[test]
    fn adding_any_lease_switches_the_whole_spec_out_of_the_legacy_path() {
        let spec = base_spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        assert!(authority_gate(&spec, t(1_500)).is_ok());

        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole),
        );
        assert!(EffectiveAuthority::is_lease_aware(&spec));
        assert_eq!(
            authority_gate(&spec, t(1_500)),
            Err(AuthorityRefusal::NoExplicitGrant {
                domain: CapabilityDomain::FilesystemWrite
            })
        );
    }

    /// End-to-end across two different domain families — filesystem and a
    /// non-filesystem domain — satisfying the AC that at least one of each is
    /// exercised.
    #[test]
    fn filesystem_and_network_domains_both_permit_with_covering_leases() {
        let spec = base_spec()
            .with_requirement(
                ControlRequirement::observe(CapabilityDomain::FilesystemRead)
                    .with_scope(RequirementScope::Selectors(vec!["/workspace".to_string()])),
            )
            .with_requirement(ControlRequirement::observe(CapabilityDomain::NetworkEgress));
        let spec = attach_lease(
            spec,
            lease_for(
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["/workspace".to_string()]),
            ),
        );
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole),
        );
        assert!(authority_gate(&spec, t(1_500)).is_ok());
    }

    #[test]
    fn duplicate_lease_domain_is_rejected_as_malformed() {
        let spec = base_spec();
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole),
        );
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole),
        );
        assert_eq!(
            authority_gate(&spec, t(1_500)),
            Err(AuthorityRefusal::Malformed(AuthorityBuildError::DuplicateLeaseDomain(
                CapabilityDomain::NetworkEgress
            )))
        );
    }

    /// `AuthorityWitness` cannot be constructed except by `authority_gate` —
    /// this is a structural property (no public constructor exists), and the
    /// closest thing to a runtime pin for it is that every successful gate
    /// call returns one, and every refused call returns none, with no third
    /// path.
    #[test]
    fn authority_gate_is_the_only_source_of_a_witness() {
        let spec = base_spec();
        let witness = authority_gate(&spec, t(1_500));
        assert!(witness.is_ok());
    }

    /// Helper: attach a lease to a spec without a public `with_lease` existing
    /// on the test's own vocabulary — exercises the real builder.
    fn attach_lease(spec: ExecutionSpec, lease: CapabilityLease) -> ExecutionSpec {
        spec.with_lease(lease)
    }
}
