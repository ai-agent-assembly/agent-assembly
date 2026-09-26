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

use crate::attenuation::{Ancestry, ParentAuthority};
use crate::capability::CapabilityDomain;
use crate::lease::{
    limits_narrower_or_equal, revocation_generation, CapabilityLease, DelegationRule, LeaseInvalid, ScopeOrdering,
};
use crate::spec::{ExecutionSpec, IdentityRef, RequirementScope};

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
    /// The spec claims lineage (a non-empty `IdentityRef.lineage`) but
    /// `authority_gate` was not handed a resolved
    /// [`crate::attenuation::ParentAuthority`] for it.
    ///
    /// The fail-closed answer to "we could not resolve the claimed parent" —
    /// never read as "no parent, proceed unattenuated". See
    /// [`crate::attenuation::Ancestry`].
    AncestryUnresolved {
        /// The ancestor agent id the spec's lineage names.
        claimed_ancestor: String,
        /// Why resolution failed.
        detail: String,
    },
    /// The resolved parent's own agent id does not appear anywhere in the
    /// spec's own lineage.
    AncestryMismatch {
        /// The resolved parent's agent id.
        claimed_ancestor: String,
    },
    /// A child lease claims authority for `domain` that its parent never held,
    /// or claims a scope its parent's lease for that domain does not cover —
    /// and no independently-attributable grant authorizes the difference.
    ChildExceedsParent {
        /// The domain whose child lease exceeds its parent's.
        domain: CapabilityDomain,
    },
    /// The per-domain [`crate::lease::ScopeOrder`] could not compare the
    /// parent's and child's scope for `domain`, and no independently-attributable
    /// grant authorizes the child's claim.
    ///
    /// Fails closed identically to [`ChildExceedsParent`](Self::ChildExceedsParent)
    /// — kept as a distinct variant because an operator's next action differs:
    /// this means the scope grammar could not be interpreted at all, not that
    /// it was interpreted and found too broad.
    AttenuationIncomparable {
        /// The domain whose scopes could not be compared.
        domain: CapabilityDomain,
    },
    /// A child lease's `expires_at` is later than its parent's, and no
    /// independently-attributable grant authorizes the extension.
    ChildExtendsExpiry {
        /// The domain whose child lease extends expiry.
        domain: CapabilityDomain,
    },
    /// A child lease's quantitative ceiling exceeds its parent's, and no
    /// independently-attributable grant authorizes the increase.
    ChildExceedsLimits {
        /// The domain whose child lease exceeds a quantitative ceiling.
        domain: CapabilityDomain,
    },
    /// The child lease's recorded [`crate::lease::DelegationProvenance::parent_lease`]
    /// does not name the parent lease actually held for this domain.
    ProvenanceMismatch {
        /// The domain whose provenance does not match.
        domain: CapabilityDomain,
    },
    /// The child lease's current [`crate::lease::CapabilityLease::delegation`]
    /// exceeds the [`crate::lease::DelegationProvenance::parent_delegation`]
    /// recorded for it at derivation — the re-widening-after-derivation hole
    /// a public `with_delegation` call could otherwise reopen.
    DelegationRightsExceedParent {
        /// The domain whose delegation rights were widened after derivation.
        domain: CapabilityDomain,
    },
    /// The child lease's recorded
    /// [`crate::lease::DelegationProvenance::parent_generation`] does not
    /// match the parent lease's current revocation generation — the
    /// concurrent-revocation catch on the read side.
    StaleParentGeneration {
        /// The domain whose provenance generation is stale.
        domain: CapabilityDomain,
    },
    /// A child lease that is wider than, or absent from, its parent's
    /// authority is not backed by an independently-attributable
    /// policy/approval grant.
    EscalationNotIndependentlyApproved {
        /// The domain whose escalation was not independently approved.
        domain: CapabilityDomain,
    },
}

impl AuthorityRefusal {
    /// The domain this refusal concerns, when it names one.
    ///
    /// `None` for the two ancestry-level refusals
    /// ([`AncestryUnresolved`](Self::AncestryUnresolved),
    /// [`AncestryMismatch`](Self::AncestryMismatch)): both are spec-wide facts
    /// about the launch's claimed lineage, decided before any domain is
    /// walked, so neither one is about a specific domain.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::NoExplicitGrant { domain }
            | Self::LeaseInvalid { domain, .. }
            | Self::LeaseScopeInsufficient { domain }
            | Self::ChildExceedsParent { domain }
            | Self::AttenuationIncomparable { domain }
            | Self::ChildExtendsExpiry { domain }
            | Self::ChildExceedsLimits { domain }
            | Self::ProvenanceMismatch { domain }
            | Self::DelegationRightsExceedParent { domain }
            | Self::StaleParentGeneration { domain }
            | Self::EscalationNotIndependentlyApproved { domain } => Some(*domain),
            Self::Malformed(AuthorityBuildError::DuplicateLeaseDomain(domain)) => Some(*domain),
            Self::AncestryUnresolved { .. } | Self::AncestryMismatch { .. } => None,
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
            Self::AncestryUnresolved {
                claimed_ancestor,
                detail,
            } => {
                write!(
                    f,
                    "spec claims ancestor `{claimed_ancestor}` but its authority could not be resolved: {detail}"
                )
            }
            Self::AncestryMismatch { claimed_ancestor } => {
                write!(
                    f,
                    "resolved parent `{claimed_ancestor}` does not appear in this spec's own lineage"
                )
            }
            Self::ChildExceedsParent { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` claims authority its parent never held"
                )
            }
            Self::AttenuationIncomparable { domain } => {
                write!(
                    f,
                    "the child and parent scopes for domain `{domain}` could not be compared"
                )
            }
            Self::ChildExtendsExpiry { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` expires later than its parent's"
                )
            }
            Self::ChildExceedsLimits { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` exceeds its parent's quantitative ceiling"
                )
            }
            Self::ProvenanceMismatch { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` names a parent lease other than the one actually held"
                )
            }
            Self::DelegationRightsExceedParent { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` was widened past its recorded delegation ceiling"
                )
            }
            Self::StaleParentGeneration { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` was derived from a stale parent generation"
                )
            }
            Self::EscalationNotIndependentlyApproved { domain } => {
                write!(
                    f,
                    "the child lease for domain `{domain}` exceeds its parent's authority with no \
                     independently-attributable approval"
                )
            }
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
///
/// # Ancestry (AAASM-6161)
///
/// `ancestry` is the parameter that lets this function ask a second,
/// independent question once `spec` claims lineage: not just "was this
/// authorized" but "was this authorized *by the parent that stands behind
/// it*". See [`attenuation_applies`] for exactly when that question is asked,
/// and `crate::attenuation` for why an unresolved claimed parent is refused
/// rather than treated as no parent at all.
pub fn authority_gate(
    spec: &ExecutionSpec,
    ancestry: &Ancestry,
    now: SystemTime,
) -> Result<AuthorityWitness, AuthorityRefusal> {
    let authority = EffectiveAuthority::from_spec(spec).map_err(AuthorityRefusal::Malformed)?;

    let parent = if attenuation_applies(spec, ancestry) {
        match ancestry {
            Ancestry::Parent(parent) => Some(parent.as_ref()),
            Ancestry::Root => {
                return Err(AuthorityRefusal::AncestryUnresolved {
                    claimed_ancestor: spec.identity().lineage.last().cloned().unwrap_or_default(),
                    detail: "this spec claims lineage but no parent authority was resolved for it".to_string(),
                });
            }
            Ancestry::UnresolvedParent {
                claimed_ancestor,
                detail,
            } => {
                return Err(AuthorityRefusal::AncestryUnresolved {
                    claimed_ancestor: claimed_ancestor.clone(),
                    detail: detail.clone(),
                });
            }
        }
    } else {
        None
    };

    if let Some(parent) = parent {
        if !spec
            .identity()
            .lineage
            .iter()
            .any(|ancestor| ancestor == &parent.identity().agent_id)
        {
            return Err(AuthorityRefusal::AncestryMismatch {
                claimed_ancestor: parent.identity().agent_id.clone(),
            });
        }
    }

    for requirement in spec.requirements() {
        let domain = requirement.domain();
        let state = authority.state(domain);
        if let AuthorityState::Leased(lease) = state {
            if let Err(reason) = lease.validate_at(now) {
                return Err(AuthorityRefusal::LeaseInvalid { domain, reason });
            }
        }
        covered(state, domain, requirement.scope())?;

        if let Some(parent) = parent {
            check_attenuation(parent, domain, state, spec.identity())?;
        }
    }

    Ok(AuthorityWitness(()))
}

/// Whether ancestry attenuation applies to `spec` at all.
///
/// Both conditions must hold: a spec with no claimed lineage has nothing to
/// attenuate against, and a spec that never opted into the lease system
/// ([`EffectiveAuthority::is_lease_aware`]) is still on the rc.7
/// compatibility residual, where an ancestry question was never asked before
/// this ticket and must not start being asked now. In particular,
/// `aasm run --root-agent` sets lineage today but no policy path issues a
/// lease yet, so this predicate is false for every real launch until a
/// lease-issuing policy source exists — see `aa-cli`'s `IsolationPlan` for
/// where that residual is documented.
fn attenuation_applies(spec: &ExecutionSpec, _ancestry: &Ancestry) -> bool {
    !spec.identity().lineage.is_empty() && EffectiveAuthority::is_lease_aware(spec)
}

/// A stable numeric rank for [`DelegationRule`], used only to compare a
/// child's *current* rule against the ceiling recorded in its
/// [`crate::lease::DelegationProvenance`] — [`DelegationRule`] intentionally
/// carries no [`Ord`] impl of its own since a two-value enum has no ordering
/// question outside this one check.
fn delegation_rank(rule: DelegationRule) -> u8 {
    match rule {
        DelegationRule::NotDelegable => 0,
        DelegationRule::DelegableWithNarrowerScope => 1,
    }
}

/// Check one domain's leased child authority against its parent's, per
/// AAASM-6161's monotonic-attenuation invariant.
///
/// Returns `Ok(())` immediately for any [`AuthorityState`] other than
/// [`AuthorityState::Leased`] — [`AuthorityState::Denied`] was already refused
/// by [`covered`], and [`AuthorityState::CompatibilityResidual`] carries no
/// lease for ancestry to attenuate.
fn check_attenuation(
    parent: &ParentAuthority,
    domain: CapabilityDomain,
    state: &AuthorityState,
    child_identity: &IdentityRef,
) -> Result<(), AuthorityRefusal> {
    let AuthorityState::Leased(child_lease) = state else {
        return Ok(());
    };
    let parent_lease = parent.lease_for(domain);

    // The first bullet a child's claim actually violates, if any. `None`
    // means the child is provably within the ceiling its parent granted.
    let violation = match parent_lease {
        None => Some(AuthorityRefusal::ChildExceedsParent { domain }),
        Some(parent_lease) => {
            match crate::scope_order::order_for(domain).compare(parent_lease.scope(), child_lease.scope()) {
                ScopeOrdering::Wider => Some(AuthorityRefusal::ChildExceedsParent { domain }),
                ScopeOrdering::Incomparable => Some(AuthorityRefusal::AttenuationIncomparable { domain }),
                ScopeOrdering::Narrower | ScopeOrdering::Equal => {
                    if child_lease.expires_at() > parent_lease.expires_at() {
                        Some(AuthorityRefusal::ChildExtendsExpiry { domain })
                    } else if let Some(child_limits) = child_lease.limits() {
                        let parent_limits = parent_lease.limits().copied().unwrap_or_default();
                        if limits_narrower_or_equal(&parent_limits, child_limits) {
                            None
                        } else {
                            Some(AuthorityRefusal::ChildExceedsLimits { domain })
                        }
                    } else {
                        None
                    }
                }
            }
        }
    };

    if let Some(refusal) = violation {
        let basis = child_lease.basis();
        let attempted_attribution = basis.approval_ref.is_some() || basis.policy_rule.is_some();
        return if !attempted_attribution {
            // Nothing about this lease claims independent attribution at
            // all — this is not an escalation attempt, it is simply a
            // child that exceeds its parent, and the specific violation
            // already computed above is the more actionable answer than a
            // generic "not independently approved".
            Err(refusal)
        } else if basis.is_independently_attributable(child_identity, parent.identity()) {
            // An independent issuer explicitly granted authority beyond what
            // the parent held — this is escalation, not attenuation, and it
            // is authorized. Provenance-integrity checks below are about a
            // claimed *derivation* from this parent, which an independent
            // grant is not, so they do not apply here.
            Ok(())
        } else {
            // Attribution was attempted, but the issuer is the parent's own
            // subject or the child's own — self-approval, refused under the
            // specific name for that failure rather than the generic one.
            Err(AuthorityRefusal::EscalationNotIndependentlyApproved { domain })
        };
    }

    // Provenance integrity: only meaningful for a child that claims to be a
    // derivation of the parent's own lease for this domain.
    if let (Some(parent_lease), Some(provenance)) = (parent_lease, child_lease.provenance()) {
        if provenance.parent_lease != *parent_lease.id() {
            return Err(AuthorityRefusal::ProvenanceMismatch { domain });
        }
        if delegation_rank(child_lease.delegation()) > delegation_rank(provenance.parent_delegation) {
            return Err(AuthorityRefusal::DelegationRightsExceedParent { domain });
        }
        if provenance.parent_generation != revocation_generation(parent_lease.revocation()) {
            return Err(AuthorityRefusal::StaleParentGeneration { domain });
        }
    }

    Ok(())
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
        assert!(authority_gate(&spec, &Ancestry::Root, t(1_500)).is_ok());
    }

    /// Falsification target 2a: an expired lease denies.
    #[test]
    fn expired_lease_denies() {
        let spec = base_spec().with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead));
        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::FilesystemRead, RequirementScope::Whole),
        );
        let result = authority_gate(&spec, &Ancestry::Root, t(2_500));
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
        let result = authority_gate(&spec, &Ancestry::Root, t(1_500));
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
            authority_gate(&spec, &Ancestry::Root, t(1_500)),
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
            authority_gate(&spec, &Ancestry::Root, t(1_500)),
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
        let result = authority_gate(&spec, &Ancestry::Root, t(1_500));
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
        assert!(authority_gate(&spec, &Ancestry::Root, t(1_500)).is_ok());
    }

    /// The same legacy spec, spot-checked: attach one lease anywhere and the
    /// unrelated domain that used to pass on policy grants alone now must be
    /// denied. This is the exact edge the compatibility rule turns on, so it
    /// is worth its own test distinct from the negative-control test above.
    #[test]
    fn adding_any_lease_switches_the_whole_spec_out_of_the_legacy_path() {
        let spec = base_spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
        assert!(authority_gate(&spec, &Ancestry::Root, t(1_500)).is_ok());

        let spec = attach_lease(
            spec,
            lease_for(CapabilityDomain::NetworkEgress, RequirementScope::Whole),
        );
        assert!(EffectiveAuthority::is_lease_aware(&spec));
        assert_eq!(
            authority_gate(&spec, &Ancestry::Root, t(1_500)),
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
        assert!(authority_gate(&spec, &Ancestry::Root, t(1_500)).is_ok());
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
            authority_gate(&spec, &Ancestry::Root, t(1_500)),
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
        let witness = authority_gate(&spec, &Ancestry::Root, t(1_500));
        assert!(witness.is_ok());
    }

    /// Helper: attach a lease to a spec without a public `with_lease` existing
    /// on the test's own vocabulary — exercises the real builder.
    fn attach_lease(spec: ExecutionSpec, lease: CapabilityLease) -> ExecutionSpec {
        spec.with_lease(lease)
    }

    // -----------------------------------------------------------------
    // AAASM-6161: monotonic capability attenuation across ancestry.
    // -----------------------------------------------------------------

    mod attenuation_tests {
        use super::*;
        use crate::attenuation::ParentAuthority;
        use crate::lease::{ChildLeaseRequest, DelegationRule, InheritanceMode};
        use crate::scope_order::PathPrefixOrder;

        fn parent_identity() -> IdentityRef {
            IdentityRef::root("parent-agent")
        }

        fn child_identity() -> IdentityRef {
            IdentityRef::root("child-agent").with_ancestor("parent-agent")
        }

        /// A parent spec carrying one delegable `FilesystemRead` lease over
        /// `/workspace`, already gated so a real [`AuthorityWitness`] backs
        /// the returned [`ParentAuthority`].
        fn gated_parent(lease: CapabilityLease) -> ParentAuthority {
            let spec = ExecutionSpec::new("echo", parent_identity()).with_lease(lease);
            let witness = authority_gate(&spec, &Ancestry::Root, t(1_500)).expect("parent must gate cleanly");
            ParentAuthority::from_gated_spec(&spec, &witness)
        }

        fn parent_fs_lease(scope: RequirementScope) -> CapabilityLease {
            CapabilityLease::new(
                crate::lease::LeaseId::new("parent-fs-lease"),
                parent_identity(),
                CapabilityDomain::FilesystemRead,
                scope,
                t(1_000),
                t(5_000),
                crate::lease::LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
            )
            .with_delegation(DelegationRule::DelegableWithNarrowerScope)
        }

        fn child_spec_with_lease(lease: CapabilityLease, scope: RequirementScope) -> ExecutionSpec {
            ExecutionSpec::new("echo", child_identity())
                .with_requirement(ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(scope))
                .with_lease(lease)
        }

        /// Positive control (§4.2): without this passing, every negative test
        /// below would be equally well satisfied by a gate that refuses
        /// everything.
        #[test]
        fn a_narrower_child_is_derived_and_passes_the_gate() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let child_lease = parent_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("child-fs-lease"),
                        child_subject: child_identity(),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
                        child_expires_at: t(4_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::NotDelegable,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_100),
                )
                .expect("a narrower child scope must derive");
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));
            let child_spec = child_spec_with_lease(
                child_lease,
                RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
            );
            assert!(authority_gate(&child_spec, &ancestry, t(1_500)).is_ok());
        }

        /// §4.3: a child requesting a path outside its parent's grant is
        /// refused, even though the lease is otherwise well-formed.
        #[test]
        fn a_child_requesting_a_path_outside_its_parents_grant_is_refused() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));

            let wider_child_lease = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["permit-only:/etc".to_string()]),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            let child_spec = child_spec_with_lease(
                wider_child_lease,
                RequirementScope::Selectors(vec!["permit-only:/etc".to_string()]),
            );
            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::ChildExceedsParent {
                    domain: CapabilityDomain::FilesystemRead
                })
            );
        }

        /// A child claiming a domain its parent's authority never covered at
        /// all — not merely a narrower/wider scope of the same domain.
        #[test]
        fn a_child_requesting_a_domain_its_parent_never_held_is_refused() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));

            let network_lease = CapabilityLease::new(
                crate::lease::LeaseId::new("child-net-lease"),
                child_identity(),
                CapabilityDomain::NetworkEgress,
                RequirementScope::Whole,
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            let child_spec = ExecutionSpec::new("echo", child_identity())
                .with_requirement(ControlRequirement::observe(CapabilityDomain::NetworkEgress))
                .with_lease(network_lease);
            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::ChildExceedsParent {
                    domain: CapabilityDomain::NetworkEgress
                })
            );
        }

        /// A child cannot extend its own expiry beyond its parent's, even
        /// when its scope is otherwise identical.
        #[test]
        fn a_child_cannot_extend_expiry_beyond_its_parent() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));

            let overextended_child = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
                t(1_000),
                t(9_999),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            let child_spec = child_spec_with_lease(
                overextended_child,
                RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            );
            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::ChildExtendsExpiry {
                    domain: CapabilityDomain::FilesystemRead
                })
            );
        }

        /// A child cannot raise a quantitative ceiling above its parent's.
        #[test]
        fn a_child_cannot_raise_a_quantitative_ceiling_above_its_parent() {
            let mut parent_lease =
                parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            parent_lease = parent_lease.with_limits(crate::spec::ResourceLimits {
                max_memory_bytes: Some(1_000),
                ..Default::default()
            });
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));

            let mut over_limit_child = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            over_limit_child = over_limit_child.with_limits(crate::spec::ResourceLimits {
                max_memory_bytes: Some(2_000),
                ..Default::default()
            });
            let child_spec = child_spec_with_lease(
                over_limit_child,
                RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            );
            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::ChildExceedsLimits {
                    domain: CapabilityDomain::FilesystemRead
                })
            );
        }

        /// Falsification target for the `with_delegation` re-widening hole:
        /// a derived child's delegation flag, widened after derivation via
        /// the public builder, is caught at the gate even though the lease's
        /// scope and expiry are both perfectly in-bounds.
        #[test]
        fn a_derived_lease_re_widened_via_with_delegation_is_refused_at_the_gate() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let derived = parent_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("child-fs-lease"),
                        child_subject: child_identity(),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
                        child_expires_at: t(2_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::NotDelegable,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_100),
                )
                .expect("a narrower child scope must derive");
            // Re-widen the delegation flag after derivation, via the public
            // builder — this is the exact hole the gate must close.
            let widened = derived.with_delegation(DelegationRule::DelegableWithNarrowerScope);

            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));
            let child_spec = child_spec_with_lease(
                widened,
                RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
            );
            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::DelegationRightsExceedParent {
                    domain: CapabilityDomain::FilesystemRead
                })
            );
        }

        /// §4.4: unknown parent is not unrestricted — a spec claiming
        /// lineage with no resolved parent is refused, and the identical
        /// spec with a resolved parent passes, proving the refusal is about
        /// the ancestry and not the requirement shape.
        #[test]
        fn a_lease_aware_spec_claiming_lineage_with_no_resolved_parent_is_refused() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let child_lease = parent_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("child-fs-lease"),
                        child_subject: child_identity(),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
                        child_expires_at: t(2_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::NotDelegable,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_100),
                )
                .expect("a narrower child scope must derive");
            let child_spec = child_spec_with_lease(
                child_lease.clone(),
                RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
            );

            assert_eq!(
                authority_gate(&child_spec, &Ancestry::Root, t(1_500)),
                Err(AuthorityRefusal::AncestryUnresolved {
                    claimed_ancestor: "parent-agent".to_string(),
                    detail: "this spec claims lineage but no parent authority was resolved for it".to_string(),
                })
            );

            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));
            assert!(authority_gate(&child_spec, &ancestry, t(1_500)).is_ok());
        }

        /// A resolved parent whose agent id is absent from the child's own
        /// lineage is refused.
        #[test]
        fn a_parent_whose_agent_id_is_absent_from_the_childs_lineage_is_refused() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let parent = gated_parent(parent_lease.clone());
            let ancestry = Ancestry::Parent(Box::new(parent));

            let child_lease = parent_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("child-fs-lease"),
                        child_subject: IdentityRef::root("child-agent").with_ancestor("someone-else"),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
                        child_expires_at: t(2_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::NotDelegable,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_100),
                )
                .expect("a narrower child scope must derive");
            let child_spec = ExecutionSpec::new("echo", IdentityRef::root("child-agent").with_ancestor("someone-else"))
                .with_requirement(
                    ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(
                        RequirementScope::Selectors(vec!["permit-only:/workspace/sub".to_string()]),
                    ),
                )
                .with_lease(child_lease);

            assert_eq!(
                authority_gate(&child_spec, &ancestry, t(1_500)),
                Err(AuthorityRefusal::AncestryMismatch {
                    claimed_ancestor: "parent-agent".to_string()
                })
            );
        }

        /// A root launch and a legacy no-lease spec are both unaffected by
        /// ancestry attenuation — the rc.7 compatibility regression.
        #[test]
        fn a_root_launch_and_a_legacy_no_lease_spec_are_unaffected() {
            let root_spec =
                base_spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
            assert!(!attenuation_applies(&root_spec, &Ancestry::Root));
            assert!(authority_gate(&root_spec, &Ancestry::Root, t(1_500)).is_ok());

            let legacy_spec = ExecutionSpec::new("echo", child_identity())
                .with_requirement(ControlRequirement::prevent(CapabilityDomain::FilesystemWrite));
            assert!(!EffectiveAuthority::is_lease_aware(&legacy_spec));
            assert!(!attenuation_applies(&legacy_spec, &Ancestry::Root));
            assert!(authority_gate(&legacy_spec, &Ancestry::Root, t(1_500)).is_ok());
        }

        /// §4.5: a grandchild cannot recover authority removed at the child
        /// level — nested attenuation is monotonic by construction because a
        /// grandchild's `ParentAuthority` is built from the child's own
        /// already-attenuated spec and witness, never from the grandparent's.
        #[test]
        fn a_grandchild_cannot_recover_authority_removed_at_the_child_level() {
            let grandparent_lease =
                parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let grandparent = gated_parent(grandparent_lease.clone());
            let grandparent_ancestry = Ancestry::Parent(Box::new(grandparent));

            // Child attenuates to `/workspace/a`.
            let child_lease = grandparent_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("child-fs-lease"),
                        child_subject: child_identity(),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/a".to_string()]),
                        child_expires_at: t(4_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::DelegableWithNarrowerScope,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_100),
                )
                .expect("a narrower child scope must derive");
            let child_spec = child_spec_with_lease(
                child_lease.clone(),
                RequirementScope::Selectors(vec!["permit-only:/workspace/a".to_string()]),
            );
            let child_witness = authority_gate(&child_spec, &grandparent_ancestry, t(1_500))
                .expect("child must gate against grandparent");
            let child_as_parent = ParentAuthority::from_gated_spec(&child_spec, &child_witness);
            let child_ancestry = Ancestry::Parent(Box::new(child_as_parent));

            // Lineage names the whole ancestor chain, outermost first — both
            // the grandparent and the child — so the mismatch check passes
            // whichever ancestry (the child's or the grandparent's directly,
            // per control (ii) below) this spec is gated against.
            let grandchild_identity = IdentityRef::root("grandchild-agent")
                .with_ancestor("parent-agent")
                .with_ancestor("child-agent");

            // The grandchild asking for authority the grandparent granted
            // but the child attenuated away — `/workspace/b` is within the
            // grandparent's grant but outside the child's own narrower one.
            let escaping_grandchild_lease = CapabilityLease::new(
                crate::lease::LeaseId::new("grandchild-fs-lease"),
                grandchild_identity.clone(),
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["permit-only:/workspace/b".to_string()]),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            let escaping_spec = ExecutionSpec::new("echo", grandchild_identity.clone())
                .with_requirement(
                    ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(
                        RequirementScope::Selectors(vec!["permit-only:/workspace/b".to_string()]),
                    ),
                )
                .with_lease(escaping_grandchild_lease);
            assert_eq!(
                authority_gate(&escaping_spec, &child_ancestry, t(1_500)),
                Err(AuthorityRefusal::ChildExceedsParent {
                    domain: CapabilityDomain::FilesystemRead
                })
            );

            // Control (i): a grandchild asking for a path still inside the
            // child's own narrower grant succeeds — the chain is not
            // refuse-everything.
            let inbound_grandchild_lease = child_lease
                .derive_child(
                    ChildLeaseRequest {
                        child_id: crate::lease::LeaseId::new("grandchild-fs-lease-ok"),
                        child_subject: grandchild_identity.clone(),
                        child_scope: RequirementScope::Selectors(vec!["permit-only:/workspace/a/deep".to_string()]),
                        child_expires_at: t(3_000),
                        mode: InheritanceMode::Narrower,
                        child_delegation: DelegationRule::NotDelegable,
                        child_limits: None,
                    },
                    &PathPrefixOrder,
                    t(1_200),
                )
                .expect("a narrower grandchild scope must derive");
            let inbound_spec = ExecutionSpec::new("echo", grandchild_identity.clone())
                .with_requirement(
                    ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(
                        RequirementScope::Selectors(vec!["permit-only:/workspace/a/deep".to_string()]),
                    ),
                )
                .with_lease(inbound_grandchild_lease);
            assert!(authority_gate(&inbound_spec, &child_ancestry, t(1_500)).is_ok());

            // Control (ii): the identical `/workspace/b` request, built
            // against the *grandparent's* witness directly, succeeds — the
            // refusal above comes from the child's attenuated ceiling, not
            // from the request's shape.
            let against_grandparent_lease = CapabilityLease::new(
                crate::lease::LeaseId::new("grandchild-fs-lease-b"),
                grandchild_identity.clone(),
                CapabilityDomain::FilesystemRead,
                RequirementScope::Selectors(vec!["permit-only:/workspace/b".to_string()]),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "hand-built, not derived"),
            );
            let against_grandparent_spec = ExecutionSpec::new("echo", grandchild_identity)
                .with_requirement(
                    ControlRequirement::observe(CapabilityDomain::FilesystemRead).with_scope(
                        RequirementScope::Selectors(vec!["permit-only:/workspace/b".to_string()]),
                    ),
                )
                .with_lease(against_grandparent_lease);
            assert!(authority_gate(&against_grandparent_spec, &grandparent_ancestry, t(1_500)).is_ok());
        }

        /// §4.7: a wider child lease is refused unless an independent issuer
        /// approved it — three bases in one test so the admission is a
        /// decision, not an accident of matching strings.
        #[test]
        fn a_wider_child_lease_is_refused_unless_an_independent_issuer_approved_it() {
            let parent_lease = parent_fs_lease(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
            let parent = gated_parent(parent_lease);
            let ancestry = Ancestry::Parent(Box::new(parent));

            let wider_scope = RequirementScope::Selectors(vec!["permit-only:/etc".to_string()]);

            // (i) issuer == parent subject: refused.
            let issuer_is_parent = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease-i"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                wider_scope.clone(),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(parent_identity(), "self-approved by parent")
                    .with_approval_ref("approval-1"),
            );
            let spec_i = child_spec_with_lease(issuer_is_parent, wider_scope.clone());
            assert_eq!(
                authority_gate(&spec_i, &ancestry, t(1_500)),
                Err(AuthorityRefusal::EscalationNotIndependentlyApproved {
                    domain: CapabilityDomain::FilesystemRead
                })
            );

            // (ii) issuer == child subject: refused (no self-approval).
            let issuer_is_child = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease-ii"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                wider_scope.clone(),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(child_identity(), "self-approved by child")
                    .with_approval_ref("approval-2"),
            );
            let spec_ii = child_spec_with_lease(issuer_is_child, wider_scope.clone());
            assert_eq!(
                authority_gate(&spec_ii, &ancestry, t(1_500)),
                Err(AuthorityRefusal::EscalationNotIndependentlyApproved {
                    domain: CapabilityDomain::FilesystemRead
                })
            );

            // (iii) a third-party issuer with an approval reference: admitted.
            let issuer_is_third_party = CapabilityLease::new(
                crate::lease::LeaseId::new("child-fs-lease-iii"),
                child_identity(),
                CapabilityDomain::FilesystemRead,
                wider_scope.clone(),
                t(1_000),
                t(2_000),
                crate::lease::LeaseBasis::new(IdentityRef::root("compliance-officer"), "explicit break-glass approval")
                    .with_approval_ref("approval-3"),
            );
            let spec_iii = child_spec_with_lease(issuer_is_third_party, wider_scope);
            assert!(authority_gate(&spec_iii, &ancestry, t(1_500)).is_ok());
        }

        /// §4.3: a child cannot reuse a parent credential lease unless
        /// delegation permits it — the default-`NotDelegable` control on the
        /// `Credential` domain family.
        #[test]
        fn a_child_cannot_reuse_a_parent_credential_lease_unless_delegation_permits_it() {
            let parent_cred_lease = CapabilityLease::new(
                crate::lease::LeaseId::new("parent-cred-lease"),
                parent_identity(),
                CapabilityDomain::Credential,
                RequirementScope::Selectors(vec![
                    "permit-only:API_TOKEN".to_string(),
                    "permit-only:DB_PASSWORD".to_string(),
                ]),
                t(1_000),
                t(5_000),
                crate::lease::LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
            );
            // Default `NotDelegable`.
            let denied = parent_cred_lease.derive_child(
                ChildLeaseRequest {
                    child_id: crate::lease::LeaseId::new("child-cred-lease"),
                    child_subject: child_identity(),
                    child_scope: RequirementScope::Selectors(vec!["permit-only:API_TOKEN".to_string()]),
                    child_expires_at: t(2_000),
                    mode: InheritanceMode::Narrower,
                    child_delegation: DelegationRule::NotDelegable,
                    child_limits: None,
                },
                &crate::scope_order::ExactTokenOrder,
                t(1_100),
            );
            assert_eq!(denied, Err(crate::lease::DelegationDenied::NotDelegable));

            // Control: the same parent, explicitly delegable, with a
            // genuinely narrower name set (one of the two names, not both),
            // succeeds.
            let delegable_parent = parent_cred_lease.with_delegation(DelegationRule::DelegableWithNarrowerScope);
            let allowed = delegable_parent.derive_child(
                ChildLeaseRequest {
                    child_id: crate::lease::LeaseId::new("child-cred-lease-2"),
                    child_subject: child_identity(),
                    child_scope: RequirementScope::Selectors(vec!["permit-only:API_TOKEN".to_string()]),
                    child_expires_at: t(2_000),
                    mode: InheritanceMode::Narrower,
                    child_delegation: DelegationRule::NotDelegable,
                    child_limits: None,
                },
                &crate::scope_order::ExactTokenOrder,
                t(1_100),
            );
            assert!(allowed.is_ok());
        }
    }
}
