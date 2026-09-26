//! Capability leases: the versioned, backend-neutral grant a [`CapabilityDomain`]
//! is exercised under (AAASM-6160, ADR 0038).
//!
//! # Why a lease is not another [`ControlRequirement`]
//!
//! A [`ControlRequirement`] states what policy asks the execution boundary to
//! *do* about a domain — deny it, or watch it. It says nothing about *who*
//! authorized the run to touch that domain at all, for how long, how much, or
//! whether a child launch may inherit the authorization. Those are the
//! questions a [`CapabilityLease`] answers, and `crate::authority` is where the
//! two are joined: [`crate::authority::authority_gate`] runs before
//! [`crate::plan::negotiate`] specifically because "can the backend mechanically
//! do this" and "was this run ever authorized to ask" are independent
//! questions, and a spec that only answers the first has never actually been
//! checked against the second.
//!
//! # Why this reuses [`RequirementScope`] rather than a new scope type
//!
//! ADR 0030 §3.1 already settled the domain vocabulary
//! ([`CapabilityDomain`]) as the single axis names get reused against, not
//! duplicated under a new name. [`RequirementScope`] is the corresponding
//! settled answer for "what within the domain" — paths, destinations, numeric
//! ceilings — and it is already opaque-to-this-crate by its own contract. A
//! lease's scope is the same question asked with a lifetime and an issuer
//! attached, so it reuses the type rather than inventing a second one a
//! backend would have to reconcile against the first.
//!
//! # What does not live here
//!
//! No backend mechanism name, no cryptographic identity binding (AAASM-5533
//! owns that and has not started — [`IdentityRef`] stays asserted-only here,
//! exactly as it already is on [`crate::spec::ExecutionSpec`]), and no secret
//! material. [`LeaseBasis`] carries *why* a lease was issued in words an
//! operator can act on, never a credential value — the same "names, never
//! values" discipline [`crate::spec::CredentialPosture`] already holds itself
//! to.

use std::time::SystemTime;

use crate::capability::CapabilityDomain;
use crate::spec::{IdentityRef, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The schema version every [`CapabilityLease`] is checked against.
///
/// [`CapabilityLease::validate_at`] fails closed on a mismatch — see that
/// method's documentation for why a version mismatch on a security capability
/// must never be read as "close enough".
pub const LEASE_SCHEMA_VERSION: u32 = 1;

/// A stable, caller-assigned identifier for one issued lease.
///
/// Opaque: this crate never parses or generates one, so a caller's own
/// issuance scheme (sequence number, UUID, ticket-derived string) travels
/// through unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaseId(String);

impl LeaseId {
    /// Wrap a caller-supplied identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier, as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for LeaseId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether a lease's authorization may pass to a child launch, and how
/// narrowly.
///
/// Deliberately a closed two-way choice rather than a numeric "max depth":
/// AAASM-6161 owns the real per-domain narrowing comparators
/// ([`ScopeOrder`]), and until that lands the only safe default is "not
/// delegable" — a caller that wants delegation must say so explicitly through
/// [`DelegableWithNarrowerScope`](Self::DelegableWithNarrowerScope), and
/// [`CapabilityLease::derive_child`] still refuses unless the supplied
/// [`ScopeOrder`] can actually prove the child's scope is no wider than the
/// parent's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum DelegationRule {
    /// No child launch may inherit this lease's authorization, regardless of
    /// scope.
    NotDelegable,
    /// A child launch may inherit this lease's authorization, provided the
    /// child's requested scope is proven no wider than this lease's own scope.
    DelegableWithNarrowerScope,
}

/// Whether a lease is currently honored, with the generation counter revocation
/// is tracked against.
///
/// The generation is a monotonically increasing counter a lease issuer bumps
/// on every revocation decision for a subject/domain pair — it exists so a
/// consumer that cached an older [`CapabilityLease`] value can tell "this is
/// stale" from "this was never revoked" without needing a live channel back to
/// the issuer. It is **not** a claim about revocation latency: nothing here
/// measures or bounds how quickly a revocation propagates to every holder of a
/// cached lease, and no doc comment in this module may claim otherwise (the
/// ticket's own "out of scope" list rules that out explicitly).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RevocationState {
    /// The lease is honored as of the stated generation.
    Active {
        /// The generation this lease was issued or last reaffirmed at.
        generation: u64,
    },
    /// The lease has been revoked and must never be treated as a grant again,
    /// however far from its stated `expires_at` it still is.
    Revoked {
        /// The generation the revocation took effect at.
        generation: u64,
        /// Why, in words an operator can act on. Never a credential value.
        reason: String,
    },
}

impl RevocationState {
    /// Whether the lease is currently honored.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

/// Who issued a lease, and under what policy authority.
///
/// Kept apart from [`CapabilityLease::subject`] on purpose: the subject is
/// *who the authorization is for*, the basis is *who granted it and why*, and
/// collapsing the two would make it impossible to tell a self-asserted
/// capability from one an operator actually approved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LeaseBasis {
    /// The identity that issued this lease. Asserted, not verified — see
    /// [`IdentityRef`].
    pub issuer: IdentityRef,
    /// The policy rule this lease was derived from, when it was derived from
    /// one rather than issued ad hoc.
    pub policy_rule: Option<String>,
    /// A reference to a recorded human or automated approval, when this
    /// lease's issuance required one.
    pub approval_ref: Option<String>,
    /// Why this lease was issued, in words an operator can act on. Never a
    /// credential value or other secret material — this field is rendered
    /// into reports and audit records unmodified.
    pub reason: String,
}

impl LeaseBasis {
    /// A basis carrying only the required reason, issued by `issuer`.
    pub fn new(issuer: IdentityRef, reason: impl Into<String>) -> Self {
        Self {
            issuer,
            policy_rule: None,
            approval_ref: None,
            reason: reason.into(),
        }
    }

    /// Attach the policy rule this lease was derived from.
    pub fn with_policy_rule(mut self, rule: impl Into<String>) -> Self {
        self.policy_rule = Some(rule.into());
        self
    }

    /// Attach a reference to a recorded approval.
    pub fn with_approval_ref(mut self, approval_ref: impl Into<String>) -> Self {
        self.approval_ref = Some(approval_ref.into());
        self
    }
}

/// Why a [`CapabilityLease`] is not honored at a given instant.
///
/// Every variant is a fail-closed reason: [`crate::authority::authority_gate`]
/// never treats any of these as "close enough to a grant". See that module's
/// documentation for the security requirement this enum exists to make
/// checkable — "expired/revoked/invalid leases never silently become allow".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum LeaseInvalid {
    /// The lease's schema version does not match [`LEASE_SCHEMA_VERSION`].
    ///
    /// A required security capability's lease is parsed and checked against
    /// exactly one schema version at a time; a caller migrating a lease format
    /// must upgrade the value, not the check.
    SchemaVersionMismatch {
        /// The version the lease carried.
        found: u32,
        /// The version this crate checks against.
        expected: u32,
    },
    /// `now` is earlier than the lease's `not_before`.
    NotYetValid {
        /// When the lease starts being honored.
        not_before: SystemTime,
    },
    /// `now` is at or past the lease's `expires_at`.
    Expired {
        /// When the lease stopped being honored.
        expires_at: SystemTime,
    },
    /// The lease's [`RevocationState`] is [`RevocationState::Revoked`].
    Revoked {
        /// Why, in words an operator can act on.
        reason: String,
    },
}

/// Why [`CapabilityLease::derive_child`] refused to produce a child lease.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DelegationDenied {
    /// The parent lease's [`DelegationRule`] is
    /// [`DelegationRule::NotDelegable`].
    NotDelegable,
    /// The supplied [`ScopeOrder`] could not compare the parent and child
    /// scopes.
    ///
    /// Fails closed by design: an incomparable scope pair is treated
    /// identically to a wider one. [`UndefinedScopeOrder`] — the only
    /// [`ScopeOrder`] this ticket ships — returns
    /// [`ScopeOrdering::Incomparable`] for every pair, which is why no spec in
    /// this crate can delegate a lease today; AAASM-6161 is the ticket that
    /// gives a real comparator the chance to return
    /// [`ScopeOrdering::Narrower`] or [`ScopeOrdering::Equal`] instead.
    Incomparable,
    /// The child's scope was proven [`ScopeOrdering::Wider`] than the
    /// parent's.
    Wider,
}

/// A backend-neutral, versioned grant of one [`CapabilityDomain`] to one
/// subject, for a bounded lifetime.
///
/// Constructed only through [`CapabilityLease::new`] plus the `with_*`
/// builders, mirroring [`crate::capability::CapabilityReport::new`]'s reason
/// for the same discipline: the security-relevant fields —
/// [`expires_at`](Self::expires_at) most of all — must never be reachable at a
/// default that reads stronger than the caller meant. `expires_at` is
/// therefore a required constructor argument rather than an optional builder
/// call: ADR 0038 requires every lease to have a bounded lifetime, and a
/// caller cannot forget to bound one because there is no path that omits it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CapabilityLease {
    id: LeaseId,
    schema_version: u32,
    subject: IdentityRef,
    domain: CapabilityDomain,
    scope: RequirementScope,
    issued_at: SystemTime,
    not_before: SystemTime,
    expires_at: SystemTime,
    limits: Option<crate::spec::ResourceLimits>,
    delegation: DelegationRule,
    revocation: RevocationState,
    basis: LeaseBasis,
}

impl CapabilityLease {
    /// A lease for `domain`, covering `scope`, honored from `issued_at` until
    /// `expires_at`.
    ///
    /// `not_before` defaults to `issued_at` — set
    /// [`with_not_before`](Self::with_not_before) explicitly for a lease that
    /// should not take effect immediately. `delegation` defaults to
    /// [`DelegationRule::NotDelegable`] and `revocation` defaults to
    /// [`RevocationState::Active`] at generation `0` — the safe defaults a
    /// caller must opt *out* of rather than opt into.
    pub fn new(
        id: LeaseId,
        subject: IdentityRef,
        domain: CapabilityDomain,
        scope: RequirementScope,
        issued_at: SystemTime,
        expires_at: SystemTime,
        basis: LeaseBasis,
    ) -> Self {
        Self {
            id,
            schema_version: LEASE_SCHEMA_VERSION,
            subject,
            domain,
            scope,
            issued_at,
            not_before: issued_at,
            expires_at,
            limits: None,
            delegation: DelegationRule::NotDelegable,
            revocation: RevocationState::Active { generation: 0 },
            basis,
        }
    }

    /// Set the schema version this lease claims to be written against.
    ///
    /// Exists only so a test, or a caller reading a persisted lease from a
    /// future format, can construct a lease that deliberately does not match
    /// [`LEASE_SCHEMA_VERSION`] and observe [`validate_at`](Self::validate_at)
    /// fail closed on it. Ordinary issuance never calls this — [`Self::new`]
    /// already sets the current version.
    pub fn with_schema_version(mut self, version: u32) -> Self {
        self.schema_version = version;
        self
    }

    /// Set when the lease starts being honored, ahead of or behind
    /// `issued_at`.
    pub fn with_not_before(mut self, not_before: SystemTime) -> Self {
        self.not_before = not_before;
        self
    }

    /// Attach quantitative limits, for domains where a ceiling is meaningful
    /// (mirrors [`crate::spec::ResourceLimits`]).
    pub fn with_limits(mut self, limits: crate::spec::ResourceLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Set whether a child launch may inherit this lease's authorization.
    pub fn with_delegation(mut self, delegation: DelegationRule) -> Self {
        self.delegation = delegation;
        self
    }

    /// Set the revocation state directly — used to construct an
    /// already-revoked lease for tests and for an issuer replaying a stored
    /// revocation.
    pub fn with_revocation(mut self, revocation: RevocationState) -> Self {
        self.revocation = revocation;
        self
    }

    /// This lease's identifier.
    pub fn id(&self) -> &LeaseId {
        &self.id
    }

    /// The schema version this lease claims.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Who this lease authorizes. Asserted, not verified — see [`IdentityRef`].
    pub fn subject(&self) -> &IdentityRef {
        &self.subject
    }

    /// The capability domain this lease grants.
    pub fn domain(&self) -> CapabilityDomain {
        self.domain
    }

    /// What within the domain this lease covers.
    pub fn scope(&self) -> &RequirementScope {
        &self.scope
    }

    /// When this lease was issued.
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// When this lease starts being honored.
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// When this lease stops being honored.
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Quantitative limits this lease carries, when the domain has them.
    pub fn limits(&self) -> Option<&crate::spec::ResourceLimits> {
        self.limits.as_ref()
    }

    /// Whether a child launch may inherit this lease.
    pub fn delegation(&self) -> DelegationRule {
        self.delegation
    }

    /// The current revocation state.
    pub fn revocation(&self) -> &RevocationState {
        &self.revocation
    }

    /// Who issued this lease, and why.
    pub fn basis(&self) -> &LeaseBasis {
        &self.basis
    }

    /// Check this lease against `now`, without inspecting what it is being
    /// checked *for*.
    ///
    /// This is the fail-closed core [`crate::authority::authority_gate`]
    /// builds on: every branch is a rejection, and there is no branch that
    /// reads "unknown" as "fine". `now` is a parameter rather than
    /// [`SystemTime::now()`] read internally so a caller — and every test in
    /// this crate — can make an expiry or not-yet-valid decision deterministic
    /// instead of racing the wall clock; see this module's falsification
    /// tests for why that matters for a security decision.
    ///
    /// # Errors
    ///
    /// [`LeaseInvalid`] naming the first reason found, checked in the order:
    /// schema version, revocation, not-yet-valid, expiry.
    pub fn validate_at(&self, now: SystemTime) -> Result<(), LeaseInvalid> {
        if self.schema_version != LEASE_SCHEMA_VERSION {
            return Err(LeaseInvalid::SchemaVersionMismatch {
                found: self.schema_version,
                expected: LEASE_SCHEMA_VERSION,
            });
        }
        if let RevocationState::Revoked { reason, .. } = &self.revocation {
            return Err(LeaseInvalid::Revoked { reason: reason.clone() });
        }
        if now < self.not_before {
            return Err(LeaseInvalid::NotYetValid {
                not_before: self.not_before,
            });
        }
        if now >= self.expires_at {
            return Err(LeaseInvalid::Expired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    /// Whether this lease's scope covers `requested`.
    ///
    /// Deliberately coarse, matching [`RequirementScope`]'s own "opaque to
    /// this crate" contract: [`RequirementScope::Whole`] covers only
    /// `RequirementScope::Whole`, and [`RequirementScope::Selectors`] covers
    /// another selector list only when every requested selector is present,
    /// verbatim, in this lease's own list. Interpreting a path glob or a CIDR
    /// block as "covering" a narrower one is exactly the per-domain comparator
    /// work AAASM-6161 owns — see [`ScopeOrder`] — and this method must not
    /// pre-empt it with a guess.
    pub fn covers(&self, requested: &RequirementScope) -> bool {
        match (&self.scope, requested) {
            (RequirementScope::Whole, RequirementScope::Whole) => true,
            (RequirementScope::Selectors(granted), RequirementScope::Selectors(wanted)) => {
                wanted.iter().all(|w| granted.contains(w))
            }
            (RequirementScope::Limits(granted), RequirementScope::Limits(wanted)) => limits_cover(granted, wanted),
            _ => false,
        }
    }

    /// Derive a putative lease for a child launch, narrowed by `child_scope`.
    ///
    /// This is the delegation *hook*, not the delegation *policy* — AAASM-6161
    /// is the ticket that supplies a [`ScopeOrder`] able to return anything
    /// other than [`ScopeOrdering::Incomparable`] for a real domain. Passing
    /// [`UndefinedScopeOrder`] here (the only implementation this ticket
    /// ships) means every call fails with
    /// [`DelegationDenied::Incomparable`], by design: a hook that already knew
    /// how to compare scopes would not need a follow-up ticket to plug real
    /// comparators into.
    ///
    /// The child's `expires_at` is capped at this lease's own `expires_at` —
    /// delegation can only narrow a lifetime, never extend it, independent of
    /// whatever `child_expires_at` a caller asks for.
    ///
    /// # Errors
    ///
    /// [`DelegationDenied`] when this lease forbids delegation, or when `order`
    /// cannot prove the child's scope is no wider than this lease's own.
    pub fn derive_child(
        &self,
        child_id: LeaseId,
        child_subject: IdentityRef,
        child_scope: RequirementScope,
        child_expires_at: SystemTime,
        order: &dyn ScopeOrder,
        issued_at: SystemTime,
    ) -> Result<CapabilityLease, DelegationDenied> {
        if self.delegation != DelegationRule::DelegableWithNarrowerScope {
            return Err(DelegationDenied::NotDelegable);
        }
        match order.compare(&self.scope, &child_scope) {
            ScopeOrdering::Narrower | ScopeOrdering::Equal => {}
            ScopeOrdering::Wider => return Err(DelegationDenied::Wider),
            ScopeOrdering::Incomparable => return Err(DelegationDenied::Incomparable),
        }
        let capped_expiry = core::cmp::min(child_expires_at, self.expires_at);
        Ok(CapabilityLease::new(
            child_id,
            child_subject,
            self.domain,
            child_scope,
            issued_at,
            capped_expiry,
            LeaseBasis::new(
                self.basis.issuer.clone(),
                format!("delegated from lease `{}`: {}", self.id, self.basis.reason),
            ),
        ))
    }
}

/// Whether two limit sets could ever meaningfully be compared as
/// covering/covered.
///
/// Field-wise: every ceiling the requester states must be present in the
/// lease and no looser. A ceiling the lease leaves unset is read as
/// unbounded for that one field, matching [`crate::spec::ResourceLimits`]'s
/// own "`None` means policy stated no ceiling" reading.
fn limits_cover(granted: &crate::spec::ResourceLimits, wanted: &crate::spec::ResourceLimits) -> bool {
    fn field_covers(granted: Option<u64>, wanted: Option<u64>) -> bool {
        match (granted, wanted) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(g), Some(w)) => w <= g,
        }
    }
    fn field_covers32(granted: Option<u32>, wanted: Option<u32>) -> bool {
        match (granted, wanted) {
            (_, None) => true,
            (None, Some(_)) => false,
            (Some(g), Some(w)) => w <= g,
        }
    }
    field_covers(granted.max_memory_bytes, wanted.max_memory_bytes)
        && field_covers(granted.max_cpu_seconds, wanted.max_cpu_seconds)
        && field_covers32(granted.max_pids, wanted.max_pids)
        && field_covers(granted.max_wall_clock_seconds, wanted.max_wall_clock_seconds)
        && field_covers(granted.max_file_size_bytes, wanted.max_file_size_bytes)
        && field_covers32(granted.max_open_files, wanted.max_open_files)
}

/// The result of comparing a parent lease's scope against a candidate child
/// scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeOrdering {
    /// The child's scope is strictly inside the parent's.
    Narrower,
    /// The child's scope is identical to the parent's.
    Equal,
    /// The child's scope reaches outside the parent's.
    Wider,
    /// Nothing here can tell which of the above holds.
    Incomparable,
}

/// A swappable per-domain comparator for lease-scope narrowing.
///
/// This trait is the whole of what AAASM-6160 delivers for delegation: the
/// hook a real comparator plugs into, not the comparator itself.
/// [`CapabilityLease::derive_child`] takes `&dyn ScopeOrder` specifically so
/// AAASM-6161 can supply per-domain implementations (a path-prefix order for
/// filesystem domains, a CIDR-containment order for network domains, ...)
/// without changing this trait or the delegation call site.
pub trait ScopeOrder {
    /// Compare `parent` against `child`, from the parent's point of view.
    fn compare(&self, parent: &RequirementScope, child: &RequirementScope) -> ScopeOrdering;
}

/// The only [`ScopeOrder`] this ticket ships: everything is incomparable.
///
/// Fails closed by construction. Using this comparator, no lease in this crate
/// can ever be delegated — [`CapabilityLease::derive_child`] always returns
/// [`DelegationDenied::Incomparable`] — which is the correct, honest answer
/// until AAASM-6161 supplies a comparator that can actually reason about a
/// domain's own scope semantics. Naming it after what it provably is (rather
/// than, say, "default") is deliberate: a reader must not mistake this for a
/// permissive placeholder.
#[derive(Debug, Clone, Copy, Default)]
pub struct UndefinedScopeOrder;

impl ScopeOrder for UndefinedScopeOrder {
    fn compare(&self, _parent: &RequirementScope, _child: &RequirementScope) -> ScopeOrdering {
        ScopeOrdering::Incomparable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn lease() -> CapabilityLease {
        CapabilityLease::new(
            LeaseId::new("lease-1"),
            IdentityRef::root("agent-a"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["/workspace".to_string()]),
            t(1_000),
            t(2_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
    }

    /// Falsification: a lease that has not reached its `expires_at` yet must
    /// validate. If this ever failed, every other "expired" test in this
    /// module would be meaningless — there would be no way to tell an expiry
    /// check from a check that always rejects.
    #[test]
    fn valid_lease_within_its_window_validates() {
        assert_eq!(lease().validate_at(t(1_500)), Ok(()));
    }

    /// Falsification target for AC "invalid/expired/revoked required leases
    /// fail closed". Spot-checked by temporarily changing `t(2_000)` to
    /// `t(9_999)` above and confirming this test then fails — it does.
    #[test]
    fn expired_lease_fails_closed() {
        assert_eq!(
            lease().validate_at(t(2_000)),
            Err(LeaseInvalid::Expired { expires_at: t(2_000) })
        );
        assert!(lease().validate_at(t(5_000)).is_err());
    }

    #[test]
    fn not_yet_valid_lease_fails_closed() {
        assert_eq!(
            lease().validate_at(t(500)),
            Err(LeaseInvalid::NotYetValid { not_before: t(1_000) })
        );
    }

    #[test]
    fn revoked_lease_fails_closed_even_within_its_time_window() {
        let revoked = lease().with_revocation(RevocationState::Revoked {
            generation: 1,
            reason: "compromised subject".to_string(),
        });
        assert_eq!(
            revoked.validate_at(t(1_500)),
            Err(LeaseInvalid::Revoked {
                reason: "compromised subject".to_string()
            })
        );
    }

    /// Falsification target for "lease parsing/version mismatch is
    /// fail-closed for a required security capability".
    #[test]
    fn schema_version_mismatch_fails_closed() {
        let stale = lease().with_schema_version(LEASE_SCHEMA_VERSION + 1);
        assert_eq!(
            stale.validate_at(t(1_500)),
            Err(LeaseInvalid::SchemaVersionMismatch {
                found: LEASE_SCHEMA_VERSION + 1,
                expected: LEASE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn covers_matches_exact_and_subset_selectors() {
        let l = lease();
        assert!(l.covers(&RequirementScope::Selectors(vec!["/workspace".to_string()])));
        assert!(!l.covers(&RequirementScope::Selectors(vec!["/etc".to_string()])));
        assert!(!l.covers(&RequirementScope::Whole));
    }

    /// The default comparator ships fully closed: delegation must never
    /// succeed until AAASM-6161 supplies a real one.
    #[test]
    fn undefined_scope_order_refuses_every_delegation() {
        let parent = lease().with_delegation(DelegationRule::DelegableWithNarrowerScope);
        let result = parent.derive_child(
            LeaseId::new("lease-1-child"),
            IdentityRef::root("agent-a").with_ancestor("agent-a"),
            RequirementScope::Selectors(vec!["/workspace/sub".to_string()]),
            t(1_800),
            &UndefinedScopeOrder,
            t(1_100),
        );
        assert_eq!(result, Err(DelegationDenied::Incomparable));
    }

    #[test]
    fn not_delegable_lease_refuses_before_consulting_the_scope_order() {
        let parent = lease(); // default NotDelegable
        let result = parent.derive_child(
            LeaseId::new("lease-1-child"),
            IdentityRef::root("agent-a").with_ancestor("agent-a"),
            RequirementScope::Selectors(vec!["/workspace".to_string()]),
            t(1_800),
            &UndefinedScopeOrder,
            t(1_100),
        );
        assert_eq!(result, Err(DelegationDenied::NotDelegable));
    }
}
