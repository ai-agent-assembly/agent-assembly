//! A child launch whose authority the parent actually held, kept apart from
//! one that recovered authority the parent did not (AAASM-6161, ADR 0038
//! amendment).
//!
//! `crate::authority::authority_gate` (AAASM-6160) answers "was this run
//! explicitly authorized to touch a domain at all", built from a spec's own
//! leases. It never asks a second question a process tree makes urgent: when
//! a run *is* a sub-agent of another run, was the domain it claims ever
//! actually held by its parent, or has it recovered authority nobody above it
//! granted? This module supplies the parameter that lets `authority_gate`
//! ask that second question — [`Ancestry`] — and the two supporting pieces
//! that make the answer trustworthy rather than merely asserted:
//!
//! * [`ParentAuthority`] is constructible **only** from a spec and an
//!   [`AuthorityWitness`](crate::authority::AuthorityWitness) — and the only
//!   place that type is ever minted is inside `authority_gate` itself. A
//!   `ParentAuthority` therefore cannot exist for a parent whose own
//!   authority was never checked, which is also what makes nested
//!   attenuation monotonic *by construction*: a grandchild's
//!   `ParentAuthority` is built from the **child's** already-attenuated spec
//!   and the **child's** own witness, never from the grandparent's, so the
//!   ceiling a grandchild is compared against can only ever have shrunk on
//!   the way down.
//! * [`DelegationLedger`] serializes the one piece of shared mutable state a
//!   concurrent derivation touches — a parent lease's revocation generation —
//!   so that a revocation racing a derivation can never be observed as "never
//!   happened" by the child it produces.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::authority::{AuthorityWitness, EffectiveAuthority};
use crate::capability::CapabilityDomain;
use crate::lease::{
    revocation_generation, CapabilityLease, ChildLeaseRequest, DelegationDenied, LeaseId, RevocationState,
};
use crate::spec::{CredentialPosture, ExecutionSpec, IdentityRef};

/// A launch's position in an execution ancestry.
///
/// Three states, and the third is the security-relevant one: "we could not
/// resolve the claimed parent" must be distinguishable from "there is no
/// parent", or `authority_gate` has no way to refuse the one case that
/// actually needs refusing — a spec that *claims* lineage (a non-empty
/// `IdentityRef.lineage`) but arrives with nothing proving what that parent
/// was actually authorized for. Reading an unresolved parent as `Root` would
/// let a claimed-but-unverified ancestry launch with full, unattenuated
/// authority; that is the fail-open outcome this type exists to make
/// unrepresentable.
#[derive(Debug, Clone, Default)]
pub enum Ancestry {
    /// This launch has no parent — either a genuine root launch, or a launch
    /// whose spec carries no lineage at all.
    #[default]
    Root,
    /// This launch's parent authority is known and was itself gated.
    Parent(Box<ParentAuthority>),
    /// This launch's spec claims a parent (non-empty lineage) but no
    /// [`ParentAuthority`] for that ancestor could be resolved.
    UnresolvedParent {
        /// The ancestor agent id the spec's lineage names.
        claimed_ancestor: String,
        /// Why resolution failed, in words an operator can act on.
        detail: String,
    },
}

/// The parent's authority, constructible only from a parent that itself
/// passed [`crate::authority::authority_gate`].
///
/// The single mechanism this type relies on is
/// [`from_gated_spec`](Self::from_gated_spec)'s parameter list:
/// [`AuthorityWitness`] has no public constructor anywhere outside
/// `authority_gate`, so a caller cannot fabricate a `ParentAuthority` for a
/// spec whose authority was never actually checked, and cannot backdate one
/// for a spec that has since changed — a fresh witness is required every
/// time.
#[derive(Debug, Clone)]
pub struct ParentAuthority {
    identity: IdentityRef,
    authority: EffectiveAuthority,
    credentials: CredentialPosture,
}

impl ParentAuthority {
    /// Build the parent authority record from a spec that has already passed
    /// [`crate::authority::authority_gate`], proven by `witness`.
    ///
    /// `witness` is never inspected — its only role is that a caller cannot
    /// have one without having called the gate, which is the whole proof
    /// this method needs. Because the gate only returns a witness once
    /// `EffectiveAuthority::from_spec` has already succeeded against `spec`,
    /// rebuilding it here cannot fail in practice; a hypothetical `Err` would
    /// mean `spec` was mutated between gating and this call, which no caller
    /// in this codebase does.
    pub fn from_gated_spec(spec: &ExecutionSpec, _witness: &AuthorityWitness) -> Self {
        Self {
            identity: spec.identity().clone(),
            authority: crate::authority::effective_authority_for_report(spec),
            credentials: spec.credentials().clone(),
        }
    }

    /// The parent's own identity. Asserted, not verified — see [`IdentityRef`].
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// The lease the parent held for `domain`, when its authority for that
    /// domain came from a lease rather than the rc.7 compatibility residual
    /// or no grant at all.
    pub fn lease_for(&self, domain: CapabilityDomain) -> Option<&CapabilityLease> {
        match self.authority.state(domain) {
            crate::authority::AuthorityState::Leased(lease) => Some(lease.as_ref()),
            _ => None,
        }
    }

    /// The parent's full effective authority record.
    pub fn authority(&self) -> &EffectiveAuthority {
        &self.authority
    }

    /// The parent's credential posture, for a future ticket that wants to
    /// check credential inheritance against ancestry too. Unused by this
    /// ticket's own checks.
    pub fn credentials(&self) -> &CredentialPosture {
        &self.credentials
    }
}

/// Serializes the one piece of shared mutable state a concurrent lease
/// derivation touches: a parent lease's revocation generation.
///
/// [`CapabilityLease`] values are otherwise immutable and travel by clone —
/// there is no shared mutable lease object for two derivations to race over.
/// The one exception is revocation: an issuer can revoke a parent lease at
/// any time, and two racing calls to [`derive_child`](Self::derive_child)
/// must agree on whether that revocation had already taken effect before
/// either of them produced a child. This type is that single point of
/// agreement.
#[derive(Debug, Default)]
pub struct DelegationLedger {
    generations: Mutex<HashMap<LeaseId, RevocationState>>,
}

impl DelegationLedger {
    /// A ledger tracking no parent leases yet.
    pub fn new() -> Self {
        Self {
            generations: Mutex::new(HashMap::new()),
        }
    }

    /// Start tracking `lease`'s revocation state, if this ledger has not seen
    /// it before.
    ///
    /// A no-op for a lease id the ledger already tracks: the ledger's own
    /// state is the one this crate treats as authoritative from that point
    /// forward, and re-seeding it from a possibly-stale clone of `lease`
    /// would let a caller resurrect a revoked lease by calling this again
    /// with an older snapshot.
    pub fn register_parent(&self, lease: &CapabilityLease) {
        let mut generations = self.generations.lock().expect("DelegationLedger mutex poisoned");
        generations
            .entry(lease.id().clone())
            .or_insert_with(|| lease.revocation().clone());
    }

    /// Record that `parent` is revoked as of `generation`.
    pub fn revoke(&self, parent: &LeaseId, generation: u64, reason: impl Into<String>) {
        let mut generations = self.generations.lock().expect("DelegationLedger mutex poisoned");
        generations.insert(
            parent.clone(),
            RevocationState::Revoked {
                generation,
                reason: reason.into(),
            },
        );
    }

    /// Read `parent`'s current tracked state and derive a child lease under
    /// one lock.
    ///
    /// A parent revoked before this call acquires the lock yields
    /// [`DelegationDenied::ParentRevoked`] — never a child lease. A parent
    /// still active at the moment the lock is held yields a child whose
    /// recorded [`crate::lease::DelegationProvenance::parent_generation`] is
    /// the generation observed **inside this critical section**, which is
    /// what lets a caller later distinguish "derived before the revocation"
    /// from "derived after" even though both calls may have started before
    /// the revoking call returned.
    pub fn derive_child(
        &self,
        parent: &CapabilityLease,
        request: ChildLeaseRequest,
        issued_at: SystemTime,
    ) -> Result<CapabilityLease, DelegationDenied> {
        let mut generations = self.generations.lock().expect("DelegationLedger mutex poisoned");
        let state = generations
            .entry(parent.id().clone())
            .or_insert_with(|| parent.revocation().clone());
        if !state.is_active() {
            return Err(DelegationDenied::ParentRevoked);
        }
        let generation = revocation_generation(state);
        // The scope order lives in `crate::scope_order` (AAASM-6161's real
        // comparators) rather than being threaded in by the caller — this is
        // the one call site that replaces `UndefinedScopeOrder` with a real
        // per-domain comparator, per ADR 0038 §4's promise that AAASM-6161
        // could plug one in without a `derive_child` signature change.
        let order = crate::scope_order::order_for(parent.domain());
        let child = parent.derive_child(request, order, issued_at)?;
        Ok(child.with_provenance_generation(generation))
    }
}

/// Whether a lease's basis is attributable to an issuer independent of both
/// the child and its parent — the escalation predicate
/// `crate::authority::authority_gate` checks before ever admitting a child
/// lease that is wider than (or absent from) its parent.
///
/// A parent cannot self-approve its own child's escalation, and a child
/// cannot self-approve its own: both are ruled out by the identity comparison
/// below, independent of whatever `approval_ref`/`policy_rule` string is
/// attached, because a self-asserted reference is not independent attribution
/// no matter how it is worded.
impl crate::lease::LeaseBasis {
    /// `true` iff this basis carries an `approval_ref` or a `policy_rule`
    /// **and** its issuer is neither `child_subject` nor `parent_subject`.
    pub fn is_independently_attributable(&self, child_subject: &IdentityRef, parent_subject: &IdentityRef) -> bool {
        (self.approval_ref.is_some() || self.policy_rule.is_some())
            && self.issuer.agent_id != child_subject.agent_id
            && self.issuer.agent_id != parent_subject.agent_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::authority_gate;
    use crate::capability::CapabilityDomain;
    use crate::lease::{DelegationRule, InheritanceMode, LeaseBasis, LeaseId as LId};
    use crate::spec::RequirementScope;
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn parent_lease() -> CapabilityLease {
        CapabilityLease::new(
            LId::new("parent-lease"),
            IdentityRef::root("parent-agent"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            t(1_000),
            t(5_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope)
    }

    fn child_request(scope: RequirementScope) -> ChildLeaseRequest {
        ChildLeaseRequest {
            child_id: LId::new("child-lease"),
            child_subject: IdentityRef::root("child-agent").with_ancestor("parent-agent"),
            child_scope: scope,
            child_expires_at: t(4_000),
            mode: InheritanceMode::Narrower,
            child_delegation: DelegationRule::NotDelegable,
            child_limits: None,
        }
    }

    /// `ParentAuthority` can only be built from a spec that actually passed
    /// the gate — this pins the mechanism rather than merely describing it:
    /// there is no code path here that could produce one without calling
    /// `authority_gate` first.
    #[test]
    fn parent_authority_requires_a_real_witness_from_the_gate() {
        let spec = ExecutionSpec::new("echo", IdentityRef::root("parent-agent")).with_lease(parent_lease());
        let witness = authority_gate(&spec, &Ancestry::Root, t(1_500)).expect("root launch with its own lease gates");
        let parent = ParentAuthority::from_gated_spec(&spec, &witness);
        assert_eq!(parent.identity().agent_id, "parent-agent");
        assert!(parent.lease_for(CapabilityDomain::FilesystemRead).is_some());
    }

    #[test]
    fn ledger_registers_and_tracks_revocation() {
        let ledger = DelegationLedger::new();
        let parent = parent_lease();
        ledger.register_parent(&parent);

        let child = ledger
            .derive_child(
                &parent,
                child_request(RequirementScope::Selectors(
                    vec!["permit-only:/workspace/a".to_string()],
                )),
                t(1_100),
            )
            .expect("a narrower child under an active parent must derive");
        assert_eq!(
            child
                .provenance()
                .expect("derived child always carries provenance")
                .parent_generation,
            0
        );

        ledger.revoke(parent.id(), 1, "operator revoked");
        let after_revoke = ledger.derive_child(
            &parent,
            child_request(RequirementScope::Selectors(
                vec!["permit-only:/workspace/b".to_string()],
            )),
            t(1_200),
        );
        assert_eq!(after_revoke, Err(DelegationDenied::ParentRevoked));
    }
}
