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
//! * [`DelegationLedger`] serializes the shared mutable state a concurrent
//!   derivation touches — each lease's revocation state and the parent edge
//!   it was derived through — so that a revocation racing a derivation can
//!   never be observed as "never happened" by the child it produces, and so
//!   that revoking a lease reaches every descendant, not only its direct
//!   children (AAASM-6307). [`ParentAuthority`] carries the live ledger so
//!   the gate can re-read it instead of trusting a snapshot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
///
/// It also carries the live [`DelegationLedger`] its leases were issued
/// through (AAASM-6307). The lease value captured here is a snapshot, so on
/// its own it cannot show a revocation recorded after it was taken;
/// `authority_gate` therefore re-reads the ledger for the parent lease and
/// every ancestor above it each time it gates a child against this value.
#[derive(Debug, Clone)]
pub struct ParentAuthority {
    identity: IdentityRef,
    authority: EffectiveAuthority,
    credentials: CredentialPosture,
    ledger: Arc<DelegationLedger>,
}

impl ParentAuthority {
    /// Build the parent authority record from a spec that has already passed
    /// [`crate::authority::authority_gate`], proven by `witness`, together
    /// with the `ledger` its leases are tracked in.
    ///
    /// `witness` is never inspected — its only role is that a caller cannot
    /// have one without having called the gate, which is the whole proof
    /// this method needs. Because the gate only returns a witness once
    /// `EffectiveAuthority::from_spec` has already succeeded against `spec`,
    /// rebuilding it here cannot fail in practice; a hypothetical `Err` would
    /// mean `spec` was mutated between gating and this call, which no caller
    /// in this codebase does.
    ///
    /// A parent lease the `ledger` does not know, or whose chain it cannot
    /// verify, is not an error here: it makes every child gated against this
    /// value fail closed instead (see
    /// [`AuthorityRefusal::LedgerUnverifiable`](crate::authority::AuthorityRefusal::LedgerUnverifiable)).
    pub fn from_gated_spec(spec: &ExecutionSpec, _witness: &AuthorityWitness, ledger: Arc<DelegationLedger>) -> Self {
        Self {
            identity: spec.identity().clone(),
            authority: crate::authority::effective_authority_for_report(spec),
            credentials: spec.credentials().clone(),
            ledger,
        }
    }

    /// The live ledger the gate re-reads revocation state from.
    pub(crate) fn ledger(&self) -> &DelegationLedger {
        &self.ledger
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

/// How a ledger entry is attached to the delegation tree.
///
/// Recorded by the ledger itself, never read from a lease value: a lease's own
/// `provenance` is data a caller can hold or clone, whereas the edge below is
/// written only inside [`DelegationLedger::derive_child`] under the ledger
/// lock, so it cannot be re-pointed afterwards.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Link {
    /// A provenance-free lease registered as the top of a chain.
    Root,
    /// Derived through the ledger from this lease.
    Parent(LeaseId),
    /// Known only because it was revoked before it was ever registered or
    /// derived. Carries no ancestry, so nothing that depends on walking *up*
    /// from it can be verified.
    Unlinked,
}

/// Why a chain walk could not confirm every hop active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainFault {
    /// `lease` — the lease asked about or one of its ancestors — is revoked.
    Revoked {
        /// The revoked lease.
        lease: LeaseId,
        /// The recorded reason.
        reason: String,
    },
    /// `lease` is unknown to the ledger or has no recorded parent edge.
    Unverifiable {
        /// The lease that could not be verified.
        lease: LeaseId,
    },
}

#[derive(Debug, Clone)]
struct LedgerEntry {
    state: RevocationState,
    link: Link,
    /// The lease as registered or derived (AAASM-6312). `None` only for an
    /// entry created by revoking an id the ledger never saw, which can never
    /// pass a content check.
    content: Option<CapabilityLease>,
}

/// Serializes the shared mutable state a lease derivation depends on — each
/// lease's revocation state and its parent edge — behind one lock.
///
/// [`CapabilityLease`] values are otherwise immutable and travel by clone —
/// there is no shared mutable lease object for two derivations to race over.
/// The one exception is revocation: an issuer can revoke a lease at any time,
/// and two racing calls to [`derive_child`](Self::derive_child) must agree on
/// whether that revocation had already taken effect before either of them
/// produced a child. This type is that single point of agreement.
///
/// Revocation is transitive (AAASM-6307): the ledger records which lease each
/// child was derived from, and a lease is honored only while it **and every
/// ancestor above it** are active. A revocation is never undone and an id is
/// never re-linked, so a lease cannot be resurrected by re-registering or
/// re-deriving it.
#[derive(Debug, Default)]
pub struct DelegationLedger {
    entries: Mutex<HashMap<LeaseId, LedgerEntry>>,
    /// When set, only a root whose own claimed issuer is this agent id may be
    /// registered (AAASM-6312). Asserted-only, not authentication.
    trusted_issuer: Option<String>,
}

impl DelegationLedger {
    /// A ledger tracking no leases yet and trusting ANY root issuer.
    ///
    /// Unrestricted on purpose for in-process and test use; no production path
    /// builds a ledger today (AAASM-6273 will). Anything that seeds a chain from
    /// outside this process must use [`with_trusted_issuer`](Self::with_trusted_issuer).
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            trusted_issuer: None,
        }
    }

    /// A ledger that accepts a root only from `issuer` (an agent id).
    ///
    /// Without it any caller can register any provenance-free lease as a root.
    /// The comparison is on the lease's own CLAIMED issuer: it narrows who may
    /// seed a chain but is not authentication of that issuer (AAASM-5533 owns
    /// identity). Use this for any ledger a production path builds.
    #[must_use]
    pub fn with_trusted_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.trusted_issuer = Some(issuer.into());
        self
    }

    /// Start tracking `lease` as the root of a delegation chain.
    ///
    /// # Errors
    ///
    /// * [`DelegationDenied::DuplicateLeaseId`] when the ledger already knows
    ///   the id. The ledger's own state is authoritative from the first moment
    ///   it knows an id; re-seeding it from a possibly-stale clone would let a
    ///   caller resurrect a revoked lease with an older snapshot.
    /// * [`DelegationDenied::AncestryUnverifiable`] when `lease` carries
    ///   delegation provenance. Only a provenance-free lease can be a root —
    ///   registering a mid-chain lease as one would sever its link to the
    ///   ancestors above it, so revoking those ancestors would no longer
    ///   reach it.
    pub fn register_parent(&self, lease: &CapabilityLease) -> Result<(), DelegationDenied> {
        let mut entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        if entries.contains_key(lease.id()) {
            return Err(DelegationDenied::DuplicateLeaseId);
        }
        if lease.provenance().is_some() {
            return Err(DelegationDenied::AncestryUnverifiable);
        }
        if let Some(trusted) = &self.trusted_issuer {
            if &lease.basis().issuer.agent_id != trusted {
                return Err(DelegationDenied::UntrustedIssuer);
            }
        }
        entries.insert(
            lease.id().clone(),
            LedgerEntry {
                state: lease.revocation().clone(),
                link: Link::Root,
                content: Some(lease.clone()),
            },
        );
        Ok(())
    }

    /// Record that `lease` is revoked as of `generation`.
    ///
    /// Changes the lease's state only and keeps its parent edge, so a revoked
    /// lease still sits in its chain and everything below it stays refused.
    /// An id the ledger does not know yet is inserted as unlinked: the
    /// revocation is honored (nothing can later register or derive that id),
    /// but no chain through it can be verified.
    pub fn revoke(&self, lease: &LeaseId, generation: u64, reason: impl Into<String>) {
        let mut entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        let state = RevocationState::Revoked {
            generation,
            reason: reason.into(),
        };
        entries
            .entry(lease.clone())
            .and_modify(|entry| entry.state = state.clone())
            .or_insert(LedgerEntry {
                state,
                link: Link::Unlinked,
                content: None,
            });
    }

    /// Whether `lease` and every ancestor above it are known, linked and
    /// active, observed under the ledger lock at the moment of the call.
    ///
    /// Observation only: nothing here claims a revocation recorded a moment
    /// later is seen, and this crate makes no revocation-latency claim.
    pub(crate) fn verify_chain(&self, lease: &LeaseId) -> Result<(), ChainFault> {
        let entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        Self::verify_chain_locked(&entries, lease)
    }

    /// Whether the ledger tracks `lease` with exactly this content
    /// (AAASM-6312). A lease the ledger does not track, or tracks only as an
    /// unlinked revocation, does not match: absence of a record is never
    /// agreement.
    pub(crate) fn content_matches(&self, lease: &CapabilityLease) -> bool {
        let entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        entries
            .get(lease.id())
            .and_then(|e| e.content.as_ref())
            .is_some_and(|recorded| recorded.same_content(lease))
    }

    /// Whether the ledger tracks `id` at all.
    pub(crate) fn knows(&self, id: &LeaseId) -> bool {
        self.entries
            .lock()
            .expect("DelegationLedger mutex poisoned")
            .contains_key(id)
    }

    /// The recorded reason when `lease` itself — not its ancestors — is
    /// revoked in this ledger; `None` for an unknown or active lease.
    pub(crate) fn revoked_reason(&self, lease: &LeaseId) -> Option<String> {
        let entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        match &entries.get(lease)?.state {
            RevocationState::Revoked { reason, .. } => Some(reason.clone()),
            RevocationState::Active { .. } => None,
        }
    }

    /// Walk from `start` to its root, requiring every hop to be known,
    /// active and linked.
    ///
    /// Fails closed on anything it cannot positively verify: an id the ledger
    /// does not know, an [`Link::Unlinked`] entry, or a walk longer than the
    /// ledger has entries (a cycle is impossible by construction — edges are
    /// written once, to an already-known parent, for an id that was not
    /// known — but the bound keeps a corrupted map from looping forever).
    fn verify_chain_locked(entries: &HashMap<LeaseId, LedgerEntry>, start: &LeaseId) -> Result<(), ChainFault> {
        let mut current = start;
        for _ in 0..=entries.len() {
            let Some(entry) = entries.get(current) else {
                return Err(ChainFault::Unverifiable { lease: current.clone() });
            };
            if let RevocationState::Revoked { reason, .. } = &entry.state {
                return Err(ChainFault::Revoked {
                    lease: current.clone(),
                    reason: reason.clone(),
                });
            }
            match &entry.link {
                Link::Root => return Ok(()),
                Link::Parent(parent) => current = parent,
                Link::Unlinked => return Err(ChainFault::Unverifiable { lease: current.clone() }),
            }
        }
        Err(ChainFault::Unverifiable { lease: start.clone() })
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
    /// the revoking call returned. The child is recorded in the ledger with
    /// an edge to `parent`.
    ///
    /// # Errors
    ///
    /// Besides the [`CapabilityLease::derive_child`] refusals:
    /// [`DelegationDenied::AncestryUnverifiable`] for a parent that carries
    /// provenance but is unknown to this ledger, and
    /// [`DelegationDenied::DuplicateLeaseId`] when `request.child_id` is
    /// already known — a known id is never re-derived or re-linked.
    pub fn derive_child(
        &self,
        parent: &CapabilityLease,
        request: ChildLeaseRequest,
        issued_at: SystemTime,
    ) -> Result<CapabilityLease, DelegationDenied> {
        let mut entries = self.entries.lock().expect("DelegationLedger mutex poisoned");
        // AAASM-6312: a parent the ledger was never told about is NOT a root —
        // registering it here would let any caller launder authority by handing
        // in a forged provenance-free lease. Roots enter only through
        // `register_parent`, which applies the trusted-issuer rule.
        match entries.get(parent.id()) {
            None => return Err(DelegationDenied::AncestryUnverifiable),
            Some(entry) => {
                if !entry.content.as_ref().is_some_and(|c| c.same_content(parent)) {
                    return Err(DelegationDenied::ContentMismatch);
                }
            }
        }
        Self::verify_chain_locked(&entries, parent.id()).map_err(|fault| match fault {
            ChainFault::Revoked { .. } => DelegationDenied::ParentRevoked,
            ChainFault::Unverifiable { .. } => DelegationDenied::AncestryUnverifiable,
        })?;
        if entries.contains_key(&request.child_id) {
            return Err(DelegationDenied::DuplicateLeaseId);
        }
        let generation = revocation_generation(&entries[parent.id()].state);
        // The scope order lives in `crate::scope_order` (AAASM-6161's real
        // comparators) rather than being threaded in by the caller — this is
        // the one call site that replaces `UndefinedScopeOrder` with a real
        // per-domain comparator, per ADR 0038 §4's promise that AAASM-6161
        // could plug one in without a `derive_child` signature change.
        let order = crate::scope_order::order_for(parent.domain());
        let child = parent
            .derive_child(request, order, issued_at)?
            .with_provenance_generation(generation);
        entries.insert(
            child.id().clone(),
            LedgerEntry {
                state: child.revocation().clone(),
                link: Link::Parent(parent.id().clone()),
                content: Some(child.clone()),
            },
        );
        Ok(child)
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

    /// A fresh lease id per request: the ledger refuses an id it already
    /// knows, so requests that must all succeed cannot share one.
    fn child_request(scope: RequirementScope) -> ChildLeaseRequest {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ChildLeaseRequest {
            child_id: LId::new(format!("child-lease-{n}")),
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
        let ledger = Arc::new(DelegationLedger::new());
        let parent = ParentAuthority::from_gated_spec(&spec, &witness, ledger);
        assert_eq!(parent.identity().agent_id, "parent-agent");
        assert!(parent.lease_for(CapabilityDomain::FilesystemRead).is_some());
    }

    #[test]
    fn ledger_registers_and_tracks_revocation() {
        let ledger = DelegationLedger::new();
        let parent = parent_lease();
        ledger
            .register_parent(&parent)
            .expect("a provenance-free lease registers as a root");

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

    fn request_with_id(id: &str, path: &str, delegation: DelegationRule) -> ChildLeaseRequest {
        ChildLeaseRequest {
            child_id: LId::new(id),
            child_subject: IdentityRef::root("child-agent").with_ancestor("parent-agent"),
            child_scope: RequirementScope::Selectors(vec![format!("permit-only:{path}")]),
            child_expires_at: t(4_000),
            mode: InheritanceMode::Narrower,
            child_delegation: delegation,
            child_limits: None,
        }
    }

    /// AAASM-6307: revoking the root must stop derivation at every depth, not
    /// only directly under the revoked lease.
    #[test]
    fn revoking_the_root_refuses_a_fresh_grandchild_derivation() {
        let ledger = DelegationLedger::new();
        let root = parent_lease();
        ledger.register_parent(&root).unwrap();
        let child = ledger
            .derive_child(
                &root,
                request_with_id("c", "/workspace/a", DelegationRule::DelegableWithNarrowerScope),
                t(1_100),
            )
            .unwrap();
        // Positive control: the grandchild derives while the root is active.
        ledger
            .derive_child(
                &child,
                request_with_id("g0", "/workspace/a/x", DelegationRule::NotDelegable),
                t(1_200),
            )
            .expect("a grandchild derives under an all-active chain");

        ledger.revoke(root.id(), 1, "operator revoked the root");
        assert_eq!(
            ledger.derive_child(
                &child,
                request_with_id("g1", "/workspace/a/y", DelegationRule::NotDelegable),
                t(1_300),
            ),
            Err(DelegationDenied::ParentRevoked)
        );
    }

    #[test]
    fn a_known_child_id_is_never_re_derived_and_an_unknown_provenanced_parent_is_unverifiable() {
        let ledger = DelegationLedger::new();
        let root = parent_lease();
        ledger.register_parent(&root).unwrap();
        let child = ledger
            .derive_child(
                &root,
                request_with_id("c", "/workspace/a", DelegationRule::DelegableWithNarrowerScope),
                t(1_100),
            )
            .unwrap();
        assert_eq!(
            ledger.derive_child(
                &root,
                request_with_id("c", "/workspace/b", DelegationRule::NotDelegable),
                t(1_100),
            ),
            Err(DelegationDenied::DuplicateLeaseId)
        );
        // `child` carries provenance; a ledger that never saw it cannot verify
        // what is above it.
        let other = DelegationLedger::new();
        assert_eq!(
            other.derive_child(
                &child,
                request_with_id("g", "/workspace/a/x", DelegationRule::NotDelegable),
                t(1_200),
            ),
            Err(DelegationDenied::AncestryUnverifiable)
        );
    }

    /// AAASM-6312: a parent nobody registered is not a root. Before the fix
    /// `derive_child` registered any unknown provenance-free parent itself, so a
    /// forged lease handed in from outside seeded its own authority chain.
    #[test]
    fn a_forged_unregistered_root_cannot_seed_a_chain() {
        let ledger = DelegationLedger::new();
        let forged = parent_lease();
        assert_eq!(
            ledger.derive_child(
                &forged,
                request_with_id("c", "/workspace/a", DelegationRule::NotDelegable),
                t(1_100),
            ),
            Err(DelegationDenied::AncestryUnverifiable)
        );
        assert!(
            !ledger.knows(forged.id()),
            "a refused derivation must not register the parent"
        );
        // positive control: the same lease, registered, derives
        ledger.register_parent(&forged).unwrap();
        assert!(ledger
            .derive_child(
                &forged,
                request_with_id("c", "/workspace/a", DelegationRule::NotDelegable),
                t(1_100),
            )
            .is_ok());
    }

    /// AAASM-6312: same id, different content. A wider snapshot reusing a
    /// tracked id must not derive, and must not satisfy the content check.
    #[test]
    fn a_snapshot_with_a_tracked_id_but_different_content_is_refused() {
        let ledger = DelegationLedger::new();
        let genuine = parent_lease();
        ledger.register_parent(&genuine).unwrap();
        assert!(
            ledger.content_matches(&genuine),
            "positive control: identical content matches"
        );

        let wider_scope = CapabilityLease::new(
            LId::new("parent-lease"),
            IdentityRef::root("parent-agent"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/".to_string()]),
            t(1_000),
            t(5_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope);
        let later_expiry = CapabilityLease::new(
            LId::new("parent-lease"),
            IdentityRef::root("parent-agent"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            t(1_000),
            t(9_999_999),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope);
        let other_issuer = CapabilityLease::new(
            LId::new("parent-lease"),
            IdentityRef::root("parent-agent"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            t(1_000),
            t(5_000),
            LeaseBasis::new(IdentityRef::root("someone-else"), "test fixture"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope);
        let other_delegation = parent_lease().with_delegation(DelegationRule::NotDelegable);
        for (name, forged) in [
            ("wider scope", wider_scope),
            ("later expiry", later_expiry),
            ("different issuer", other_issuer),
            ("different delegation rights", other_delegation),
        ] {
            assert!(
                !ledger.content_matches(&forged),
                "{name} must not match the recorded content"
            );
            assert_eq!(
                ledger.derive_child(
                    &forged,
                    request_with_id("c", "/workspace/a", DelegationRule::NotDelegable),
                    t(1_100),
                ),
                Err(DelegationDenied::ContentMismatch),
                "{name}"
            );
        }
        // a revocation recorded for the genuine lease is NOT a content change
        ledger.revoke(genuine.id(), 1, "x");
        assert!(ledger.content_matches(&genuine));
    }

    /// AAASM-6312: every content field is bound, not just the obvious ones. A
    /// variant differing from the recorded lease in exactly ONE field must be
    /// refused; ignoring any single field in `same_content` turns one row red.
    /// (`id` is the lookup key, so it is bound by construction.)
    #[test]
    fn each_content_field_is_bound_individually() {
        let ledger = DelegationLedger::new();
        let genuine = parent_lease();
        ledger.register_parent(&genuine).unwrap();
        let rebuild = |subject: IdentityRef, domain: CapabilityDomain, issued: u64| {
            CapabilityLease::new(
                LId::new("parent-lease"),
                subject,
                domain,
                RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
                t(issued),
                t(5_000),
                LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
            )
            .with_delegation(DelegationRule::DelegableWithNarrowerScope)
        };
        let variants: Vec<(&str, CapabilityLease)> = vec![
            (
                "subject",
                rebuild(
                    IdentityRef::root("other-agent"),
                    CapabilityDomain::FilesystemRead,
                    1_000,
                ),
            ),
            (
                "domain",
                rebuild(
                    IdentityRef::root("parent-agent"),
                    CapabilityDomain::FilesystemWrite,
                    1_000,
                ),
            ),
            // issued_at moves while not_before is pinned back, so only issued_at differs.
            (
                "issued_at",
                rebuild(IdentityRef::root("parent-agent"), CapabilityDomain::FilesystemRead, 999)
                    .with_not_before(t(1_000)),
            ),
            ("not_before", parent_lease().with_not_before(t(1))),
            (
                "limits",
                parent_lease().with_limits(crate::spec::ResourceLimits::default()),
            ),
            ("schema_version", parent_lease().with_schema_version(99)),
        ];
        for (name, forged) in variants {
            assert!(
                !ledger.content_matches(&forged),
                "{name} must not match the recorded content"
            );
            assert_eq!(
                ledger.derive_child(
                    &forged,
                    request_with_id("c", "/workspace/a", DelegationRule::NotDelegable),
                    t(1_100),
                ),
                Err(DelegationDenied::ContentMismatch),
                "{name}"
            );
        }
    }

    /// AAASM-6312: provenance is content. A copy of the recorded child that
    /// differs ONLY in its recorded parent generation is not the recorded lease.
    #[test]
    fn a_child_with_different_provenance_is_not_the_recorded_child() {
        let ledger = DelegationLedger::new();
        let genuine_parent = parent_lease();
        ledger.register_parent(&genuine_parent).unwrap();
        let recorded = ledger
            .derive_child(
                &genuine_parent,
                request_with_id("c", "/workspace/a", DelegationRule::DelegableWithNarrowerScope),
                t(1_100),
            )
            .unwrap();
        assert!(ledger.content_matches(&recorded), "positive control");
        // Identical in every field but the recorded parent generation.
        let lookalike = recorded.clone().with_provenance_generation(7);
        assert_ne!(recorded.provenance(), lookalike.provenance());
        assert!(!ledger.content_matches(&lookalike));
    }

    /// AAASM-6312: a ledger built with a trusted issuer takes roots from that
    /// issuer only.
    #[test]
    fn a_root_from_an_untrusted_issuer_is_refused() {
        let ledger = DelegationLedger::new().with_trusted_issuer("issuer");
        assert!(
            ledger.register_parent(&parent_lease()).is_ok(),
            "the trusted issuer's root registers"
        );
        let rogue = CapabilityLease::new(
            LId::new("rogue-root"),
            IdentityRef::root("parent-agent"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/".to_string()]),
            t(1_000),
            t(5_000),
            LeaseBasis::new(IdentityRef::root("rogue"), "forged"),
        );
        assert_eq!(ledger.register_parent(&rogue), Err(DelegationDenied::UntrustedIssuer));
        assert!(!ledger.knows(rogue.id()));
    }

    /// §4.6: concurrent creation does not race around revocation.
    ///
    /// A pure lock-acquisition race at microsecond granularity cannot be made
    /// deterministic without instrumenting the lock itself, and an
    /// undeterministic test that only *sometimes* opens the race window is
    /// worse than one that reliably does — so this test proves the property
    /// with real concurrency at both ends of a controlled boundary: 16 real
    /// threads derive concurrently against each other while the parent is
    /// still active (group A), the revocation is then recorded, and 16 more
    /// real threads derive concurrently against each other afterward (group
    /// B). The mutex inside `DelegationLedger` is the only thing serializing
    /// either group internally; what this test pins is the *boundary*
    /// between them, which is the property AAASM-6161 actually needs to
    /// hold.
    #[test]
    fn concurrent_child_derivation_never_issues_a_child_after_the_revocation_is_recorded() {
        use std::sync::{Arc, Barrier};

        const GROUP_SIZE: usize = 16;
        let ledger = Arc::new(DelegationLedger::new());
        let parent = Arc::new(parent_lease());
        ledger
            .register_parent(&parent)
            .expect("a provenance-free lease registers as a root");

        fn spawn_group(
            ledger: &Arc<DelegationLedger>,
            parent: &Arc<CapabilityLease>,
            prefix: &'static str,
        ) -> Vec<std::thread::JoinHandle<Result<CapabilityLease, DelegationDenied>>> {
            let barrier = Arc::new(Barrier::new(GROUP_SIZE));
            (0..GROUP_SIZE)
                .map(|i| {
                    let ledger = Arc::clone(ledger);
                    let parent = Arc::clone(parent);
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        ledger.derive_child(
                            &parent,
                            child_request(RequirementScope::Selectors(vec![format!(
                                "permit-only:/workspace/{prefix}{i}"
                            )])),
                            t(1_100),
                        )
                    })
                })
                .collect()
        }

        let group_a = spawn_group(&ledger, &parent, "a");
        let group_a_results: Vec<_> = group_a
            .into_iter()
            .map(|h| h.join().expect("group A thread panicked"))
            .collect();

        ledger.revoke(parent.id(), 1, "operator revoked mid-flight");

        let group_b = spawn_group(&ledger, &parent, "b");
        let group_b_results: Vec<_> = group_b
            .into_iter()
            .map(|h| h.join().expect("group B thread panicked"))
            .collect();

        let oks: Vec<&CapabilityLease> = group_a_results.iter().filter_map(|r| r.as_ref().ok()).collect();
        let revoked_errs = group_b_results
            .iter()
            .filter(|r| matches!(r, Err(DelegationDenied::ParentRevoked)))
            .count();

        assert_eq!(
            oks.len(),
            GROUP_SIZE,
            "every concurrent derivation before the revocation must succeed, or this test proves \
             nothing about the boundary: {group_a_results:?}"
        );
        assert_eq!(
            revoked_errs, GROUP_SIZE,
            "every concurrent derivation after the revocation must observe it, or this test proves \
             nothing about the boundary: {group_b_results:?}"
        );

        // (a) every returned `Ok` child carries the pre-revocation generation.
        for child in &oks {
            let provenance = child.provenance().expect("derived child always carries provenance");
            assert_eq!(
                provenance.parent_generation, 0,
                "an admitted child recorded a post-revocation generation"
            );
        }

        // Every pre-revocation child is refused by `authority_gate` once the
        // parent is revoked. AAASM-6281/D2 made this a direct observation —
        // `check_attenuation` now validates the parent's own lease snapshot
        // at `now` and catches the revocation itself
        // (`AuthorityRefusal::LeaseInvalid`) before ever reaching the
        // provenance-generation comparison. Before D2 landed, the
        // generation mismatch (`StaleParentGeneration`) was the *only*
        // mechanism that caught this case; it remains correct as a
        // fallback for a parent lease that is still itself valid but whose
        // recorded generation has moved on without an accompanying
        // revocation being observable in this snapshot.
        let revoked_parent_lease = (*parent).clone().with_revocation(RevocationState::Revoked {
            generation: 1,
            reason: "operator revoked mid-flight".to_string(),
        });
        let parent_spec =
            ExecutionSpec::new("echo", IdentityRef::root("parent-agent")).with_lease(revoked_parent_lease);
        let parent_witness =
            authority_gate(&parent_spec, &Ancestry::Root, t(1_500)).expect("an empty-requirement spec always gates");
        let stale_ancestry = Ancestry::Parent(Box::new(ParentAuthority::from_gated_spec(
            &parent_spec,
            &parent_witness,
            Arc::clone(&ledger),
        )));

        for child in &oks {
            let child_identity = child.subject().clone();
            let child_spec = ExecutionSpec::new("echo", child_identity)
                .with_requirement(
                    crate::spec::ControlRequirement::observe(CapabilityDomain::FilesystemRead)
                        .with_scope(child.scope().clone()),
                )
                .with_lease((*child).clone());
            assert!(
                matches!(
                    authority_gate(&child_spec, &stale_ancestry, t(1_500)),
                    Err(crate::authority::AuthorityRefusal::LeaseInvalid {
                        domain,
                        reason: crate::lease::LeaseInvalid::Revoked { .. }
                    }) if domain == CapabilityDomain::FilesystemRead
                ),
                "a child derived before the revocation was not refused once the parent was revoked"
            );
        }
    }

    /// Documented, pinned gap: quantitative limits are enforced as per-child
    /// ceilings, not an aggregate budget divided among siblings —
    /// `aa-isolation` measures no live resource consumption, so an aggregate
    /// claim would be a claim about runtime this crate cannot make. Two
    /// sibling children may therefore each hold the parent's full ceiling
    /// simultaneously. This is a deliberate disclosure, in the same shape as
    /// `descendant.rs`'s own
    /// `a_wider_selector_set_is_not_detected_and_this_is_the_known_gap`: if
    /// this test ever starts failing because aggregate accounting was added,
    /// the documentation and residual-risk list must be revisited
    /// deliberately, not silently.
    #[test]
    fn sibling_children_may_each_hold_the_parents_full_ceiling_and_this_is_the_known_gap() {
        let parent = parent_lease().with_limits(crate::spec::ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });

        let mut sibling_a_request =
            child_request(RequirementScope::Selectors(
                vec!["permit-only:/workspace/a".to_string()],
            ));
        sibling_a_request.child_limits = Some(crate::spec::ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });
        let sibling_a = parent
            .derive_child(sibling_a_request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .expect("a ceiling equal to the parent's own must derive");

        let mut sibling_b_request =
            child_request(RequirementScope::Selectors(
                vec!["permit-only:/workspace/b".to_string()],
            ));
        sibling_b_request.child_limits = Some(crate::spec::ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });
        let sibling_b = parent
            .derive_child(sibling_b_request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .expect("a ceiling equal to the parent's own must derive");

        // Each sibling independently holds the parent's full 1_000-byte
        // ceiling — nothing here divides it between them, and nothing in
        // this crate could, since no live consumption is measured.
        assert_eq!(sibling_a.limits().unwrap().max_memory_bytes, Some(1_000));
        assert_eq!(sibling_b.limits().unwrap().max_memory_bytes, Some(1_000));
    }
}
