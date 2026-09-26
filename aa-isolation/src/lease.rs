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
use crate::spec::{IdentityRef, RequirementScope, ResourceLimits};

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
    /// [`ScopeOrder`] AAASM-6160 shipped — returns
    /// [`ScopeOrdering::Incomparable`] for every pair; AAASM-6161's
    /// `crate::scope_order` module supplies real comparators that can return
    /// [`ScopeOrdering::Narrower`] or [`ScopeOrdering::Equal`] instead.
    Incomparable,
    /// The child's scope was proven [`ScopeOrdering::Wider`] than the
    /// parent's.
    Wider,
    /// [`InheritanceMode::None`] was requested — a caller asking for no
    /// inheritance should not call `derive_child` at all, but the request is
    /// still refused explicitly rather than silently producing a lease.
    ModeForbidsInheritance,
    /// [`InheritanceMode::IndependentlyApproved`] was requested from
    /// `derive_child` itself. That mode names an independently *issued*
    /// lease, not something a *derivation* can produce — see
    /// `crate::attenuation::ParentAuthority` and the escalation check in
    /// `crate::authority::authority_gate` for where that path is validated
    /// instead.
    NotADerivation,
    /// [`InheritanceMode::Same`] was requested, but the scope comparator did
    /// not return [`ScopeOrdering::Equal`].
    ModeRequiresEqualScope,
    /// The requested child [`DelegationRule`] exceeds the parent's own —
    /// a child cannot be granted the right to delegate more freely than the
    /// lease it was derived from.
    DelegationRightsExceedParent,
    /// A requested quantitative ceiling exceeds the parent lease's own
    /// ceiling for that field.
    LimitsExceedParent {
        /// The `ResourceLimits` field name that exceeded its parent's ceiling.
        field: String,
    },
    /// The parent lease's tracked [`RevocationState`] was not active at the
    /// instant a [`crate::attenuation::DelegationLedger`] attempted the
    /// derivation — the concurrent-revocation race's losing outcome.
    ParentRevoked,
}

/// How a child lease relates to its parent's authority — the four modes
/// AAASM-6161's acceptance criteria name, as a closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum InheritanceMode {
    /// The child inherits nothing from this parent lease.
    None,
    /// The child's scope must be proven identical to the parent's.
    Same,
    /// The child's scope must be proven strictly narrower than, or equal to,
    /// the parent's.
    Narrower,
    /// The child's authority for this domain did not come from narrowing the
    /// parent's lease at all — it was independently issued and approved. Not
    /// a valid `mode` for [`CapabilityLease::derive_child`] itself; see that
    /// method's documentation.
    IndependentlyApproved,
}

/// Where a child capability came from — the machine-readable half of the
/// "evidence can explain every child capability's provenance" acceptance
/// criterion.
///
/// Kept apart from [`LeaseBasis::reason`]: `reason` is prose for an operator,
/// and overloading it to also be the thing `authority_gate` parses would make
/// a wording change into a security regression. This struct is the
/// grep-able, structurally-checked path instead.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DelegationProvenance {
    /// The parent lease this child was derived from.
    pub parent_lease: LeaseId,
    /// The parent lease's own subject, at derivation time.
    pub parent_subject: IdentityRef,
    /// How this child relates to the parent's scope.
    pub inheritance_mode: InheritanceMode,
    /// The [`DelegationRule`] this child lease was actually issued with, at
    /// derivation time — recorded separately from
    /// [`CapabilityLease::delegation`] precisely so a later, out-of-band
    /// `with_delegation` call on the returned value can be caught:
    /// `crate::authority::authority_gate`'s provenance-integrity check
    /// compares this recorded value against the child's *current*
    /// `delegation()`, and the two can only differ if something widened the
    /// field after `derive_child` returned it.
    pub parent_delegation: DelegationRule,
    /// The parent's [`RevocationState`] generation observed at derivation
    /// time — the field a concurrent revocation is checked against.
    pub parent_generation: u64,
}

/// Everything a caller supplies to derive a child lease from a parent one.
///
/// A struct rather than positional arguments: `derive_child`'s previous
/// 7-positional-argument shape made it easy to pass two `SystemTime`s or two
/// `LeaseId`s in the wrong order, and every field here is security-relevant.
pub struct ChildLeaseRequest {
    /// The child lease's own identifier.
    pub child_id: LeaseId,
    /// Who the child lease is for.
    pub child_subject: IdentityRef,
    /// What within the domain the child lease covers.
    pub child_scope: RequirementScope,
    /// When the child lease should stop being honored, before capping.
    pub child_expires_at: SystemTime,
    /// How the child's scope should relate to the parent's.
    pub mode: InheritanceMode,
    /// Whether the child lease may itself be further delegated.
    pub child_delegation: DelegationRule,
    /// Quantitative ceilings the child lease should carry, when the domain
    /// has them.
    pub child_limits: Option<ResourceLimits>,
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
    provenance: Option<DelegationProvenance>,
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
            provenance: None,
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

    /// Where this lease's capability came from, when it was derived from a
    /// parent lease rather than issued at the root. `None` for a root-issued
    /// lease.
    pub fn provenance(&self) -> Option<&DelegationProvenance> {
        self.provenance.as_ref()
    }

    /// Overwrite the recorded provenance generation with the value a
    /// [`crate::attenuation::DelegationLedger`] observed under its own lock at
    /// derivation time.
    ///
    /// `derive_child` stamps `provenance.parent_generation` from the `parent`
    /// argument's own [`RevocationState`], which is a snapshot that can be
    /// stale by the time a concurrent revocation lands. The ledger is the
    /// authoritative live view of a parent's generation, so it corrects the
    /// snapshot after derivation succeeds, inside the same critical section
    /// that read it — never outside this crate, which is why this stays
    /// `pub(crate)` rather than a public builder a caller could use to
    /// forge provenance.
    pub(crate) fn with_provenance_generation(mut self, generation: u64) -> Self {
        if let Some(provenance) = self.provenance.as_mut() {
            provenance.parent_generation = generation;
        }
        self
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

    /// Derive a putative lease for a child launch, narrowed per `request`.
    ///
    /// This is where AAASM-6160's delegation *hook* becomes a real delegation
    /// *check* (AAASM-6161): `order` decides whether `request.child_scope` is
    /// provably no wider than this lease's own scope, and every other field on
    /// `request` is checked for its own monotonicity property before a child
    /// lease is produced at all. Checked in order:
    ///
    /// 1. This lease's own [`DelegationRule`] permits delegation at all.
    /// 2. `request.mode` is not [`InheritanceMode::None`] (nothing to derive)
    ///    or [`InheritanceMode::IndependentlyApproved`] (that mode names a
    ///    lease this method cannot produce — see
    ///    `crate::attenuation::ParentAuthority` instead).
    /// 3. `order.compare` proves the scope relationship `request.mode` claims.
    /// 4. `request.child_delegation` does not exceed this lease's own
    ///    [`DelegationRule`] — a child can never be granted broader delegation
    ///    rights than the lease it was derived from carries.
    /// 5. `request.child_limits`, when present, does not exceed this lease's
    ///    own limits on any field (see [`limits_narrower_or_equal`]).
    ///
    /// The child's `expires_at` is capped at this lease's own `expires_at`,
    /// and its `not_before` is floored at `max(issued_at, self.not_before)` —
    /// delegation can only narrow a lifetime on both ends, never extend it in
    /// either direction, independent of whatever `request.child_expires_at` or
    /// `issued_at` a caller asks for.
    ///
    /// # Errors
    ///
    /// [`DelegationDenied`] naming the first check above that failed.
    pub fn derive_child(
        &self,
        request: ChildLeaseRequest,
        order: &dyn ScopeOrder,
        issued_at: SystemTime,
    ) -> Result<CapabilityLease, DelegationDenied> {
        if self.delegation != DelegationRule::DelegableWithNarrowerScope {
            return Err(DelegationDenied::NotDelegable);
        }
        if request.mode == InheritanceMode::None {
            return Err(DelegationDenied::ModeForbidsInheritance);
        }
        if request.mode == InheritanceMode::IndependentlyApproved {
            return Err(DelegationDenied::NotADerivation);
        }

        let ordering = order.compare(&self.scope, &request.child_scope);
        match ordering {
            ScopeOrdering::Wider => return Err(DelegationDenied::Wider),
            ScopeOrdering::Incomparable => return Err(DelegationDenied::Incomparable),
            ScopeOrdering::Equal => {}
            ScopeOrdering::Narrower => {
                if request.mode == InheritanceMode::Same {
                    return Err(DelegationDenied::ModeRequiresEqualScope);
                }
            }
        }

        if request.child_delegation == DelegationRule::DelegableWithNarrowerScope
            && self.delegation != DelegationRule::DelegableWithNarrowerScope
        {
            return Err(DelegationDenied::DelegationRightsExceedParent);
        }

        if let Some(child_limits) = &request.child_limits {
            let parent_limits = self.limits.unwrap_or_default();
            if !limits_narrower_or_equal(&parent_limits, child_limits) {
                let field = first_exceeding_limit_field(&parent_limits, child_limits)
                    .unwrap_or("unknown")
                    .to_string();
                return Err(DelegationDenied::LimitsExceedParent { field });
            }
        }

        let capped_expiry = core::cmp::min(request.child_expires_at, self.expires_at);
        let floored_not_before = core::cmp::max(issued_at, self.not_before);

        Ok(CapabilityLease {
            id: request.child_id,
            schema_version: LEASE_SCHEMA_VERSION,
            subject: request.child_subject,
            domain: self.domain,
            scope: request.child_scope,
            issued_at,
            not_before: floored_not_before,
            expires_at: capped_expiry,
            limits: request.child_limits,
            delegation: request.child_delegation,
            revocation: RevocationState::Active { generation: 0 },
            basis: LeaseBasis::new(
                self.basis.issuer.clone(),
                format!("delegated from lease `{}`: {}", self.id, self.basis.reason),
            ),
            provenance: Some(DelegationProvenance {
                parent_lease: self.id.clone(),
                parent_subject: self.subject.clone(),
                inheritance_mode: request.mode,
                parent_delegation: request.child_delegation,
                parent_generation: revocation_generation(&self.revocation),
            }),
        })
    }
}

/// The generation number carried by either [`RevocationState`] variant.
pub(crate) fn revocation_generation(state: &RevocationState) -> u64 {
    match state {
        RevocationState::Active { generation } | RevocationState::Revoked { generation, .. } => *generation,
    }
}

/// Whether two limit sets could ever meaningfully be compared as
/// covering/covered.
///
/// Field-wise: every ceiling the requester states must be present in the
/// lease and no looser. A ceiling the lease leaves unset is read as
/// unbounded for that one field, matching [`crate::spec::ResourceLimits`]'s
/// own "`None` means policy stated no ceiling" reading.
pub(crate) fn limits_cover(granted: &crate::spec::ResourceLimits, wanted: &crate::spec::ResourceLimits) -> bool {
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

/// Whether every ceiling `child` states is within `parent`'s — the
/// delegation-narrowing question, which is **not** the same question
/// [`limits_cover`] answers.
///
/// [`limits_cover`] exists for `covers()`: "does a lease's own grant satisfy
/// what a *requirement* asked for", where a field the requirement never
/// mentions (`wanted: None`) is vacuously satisfied regardless of what the
/// lease states. Delegation narrowing asks the opposite question about the
/// *child*'s own field: a field the child leaves unbounded (`child: None`) is
/// not "the child didn't ask", it is "the child lease itself carries no
/// ceiling for this resource at all" — which is *wider* than any bounded
/// parent ceiling, not narrower. Reusing [`limits_cover`] here would silently
/// admit a child that removed a ceiling its parent enforced.
pub(crate) fn limits_narrower_or_equal(
    parent: &crate::spec::ResourceLimits,
    child: &crate::spec::ResourceLimits,
) -> bool {
    fn covers(parent: Option<u64>, child: Option<u64>) -> bool {
        match (parent, child) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(p), Some(c)) => c <= p,
        }
    }
    fn covers32(parent: Option<u32>, child: Option<u32>) -> bool {
        match (parent, child) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(p), Some(c)) => c <= p,
        }
    }
    covers(parent.max_memory_bytes, child.max_memory_bytes)
        && covers(parent.max_cpu_seconds, child.max_cpu_seconds)
        && covers32(parent.max_pids, child.max_pids)
        && covers(parent.max_wall_clock_seconds, child.max_wall_clock_seconds)
        && covers(parent.max_file_size_bytes, child.max_file_size_bytes)
        && covers32(parent.max_open_files, child.max_open_files)
}

/// The name of the first `ResourceLimits` field where `child` exceeds
/// `parent`, for [`DelegationDenied::LimitsExceedParent`]'s error detail.
fn first_exceeding_limit_field(
    parent: &crate::spec::ResourceLimits,
    child: &crate::spec::ResourceLimits,
) -> Option<&'static str> {
    fn exceeds(parent: Option<u64>, child: Option<u64>) -> bool {
        matches!((parent, child), (Some(_), None)) || matches!((parent, child), (Some(p), Some(c)) if c > p)
    }
    fn exceeds32(parent: Option<u32>, child: Option<u32>) -> bool {
        matches!((parent, child), (Some(_), None)) || matches!((parent, child), (Some(p), Some(c)) if c > p)
    }
    if exceeds(parent.max_memory_bytes, child.max_memory_bytes) {
        return Some("max_memory_bytes");
    }
    if exceeds(parent.max_cpu_seconds, child.max_cpu_seconds) {
        return Some("max_cpu_seconds");
    }
    if exceeds32(parent.max_pids, child.max_pids) {
        return Some("max_pids");
    }
    if exceeds(parent.max_wall_clock_seconds, child.max_wall_clock_seconds) {
        return Some("max_wall_clock_seconds");
    }
    if exceeds(parent.max_file_size_bytes, child.max_file_size_bytes) {
        return Some("max_file_size_bytes");
    }
    if exceeds32(parent.max_open_files, child.max_open_files) {
        return Some("max_open_files");
    }
    None
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
    fn base_request(child_scope: RequirementScope) -> ChildLeaseRequest {
        ChildLeaseRequest {
            child_id: LeaseId::new("lease-1-child"),
            child_subject: IdentityRef::root("agent-a").with_ancestor("agent-a"),
            child_scope,
            child_expires_at: t(1_800),
            mode: InheritanceMode::Narrower,
            child_delegation: DelegationRule::NotDelegable,
            child_limits: None,
        }
    }

    #[test]
    fn undefined_scope_order_refuses_every_delegation() {
        let parent = lease().with_delegation(DelegationRule::DelegableWithNarrowerScope);
        let result = parent.derive_child(
            base_request(RequirementScope::Selectors(vec!["/workspace/sub".to_string()])),
            &UndefinedScopeOrder,
            t(1_100),
        );
        assert_eq!(result, Err(DelegationDenied::Incomparable));
    }

    #[test]
    fn not_delegable_lease_refuses_before_consulting_the_scope_order() {
        let parent = lease(); // default NotDelegable
        let result = parent.derive_child(
            base_request(RequirementScope::Selectors(vec!["/workspace".to_string()])),
            &UndefinedScopeOrder,
            t(1_100),
        );
        assert_eq!(result, Err(DelegationDenied::NotDelegable));
    }

    fn delegable_path_lease() -> CapabilityLease {
        CapabilityLease::new(
            LeaseId::new("path-lease"),
            IdentityRef::root("agent-a"),
            CapabilityDomain::FilesystemRead,
            RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]),
            t(1_000),
            t(2_000),
            LeaseBasis::new(IdentityRef::root("issuer"), "test fixture"),
        )
        .with_delegation(DelegationRule::DelegableWithNarrowerScope)
    }

    /// AAASM-6161: `InheritanceMode::None` is refused explicitly rather than
    /// silently producing a lease — a caller with nothing to inherit should
    /// not call this method at all, and if it does, it gets a named reason.
    #[test]
    fn mode_none_is_refused_explicitly() {
        let parent = delegable_path_lease();
        let mut request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        request.mode = InheritanceMode::None;
        assert_eq!(
            parent.derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100)),
            Err(DelegationDenied::ModeForbidsInheritance)
        );
    }

    /// `InheritanceMode::IndependentlyApproved` names a lease this method
    /// cannot produce — it is validated at the gate instead.
    #[test]
    fn mode_independently_approved_is_not_a_derivation() {
        let parent = delegable_path_lease();
        let mut request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        request.mode = InheritanceMode::IndependentlyApproved;
        assert_eq!(
            parent.derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100)),
            Err(DelegationDenied::NotADerivation)
        );
    }

    /// `InheritanceMode::Same` demands an exactly-equal scope; a strictly
    /// narrower one is refused under that mode even though it would succeed
    /// under `Narrower`.
    #[test]
    fn mode_same_requires_an_equal_scope() {
        let parent = delegable_path_lease();
        let mut request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        request.mode = InheritanceMode::Same;
        assert_eq!(
            parent.derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100)),
            Err(DelegationDenied::ModeRequiresEqualScope)
        );

        let mut equal_request = base_request(RequirementScope::Selectors(vec!["permit-only:/workspace".to_string()]));
        equal_request.mode = InheritanceMode::Same;
        assert!(parent
            .derive_child(equal_request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .is_ok());
    }

    /// A child's `expires_at` is capped at the parent's, even when a caller
    /// asks for later.
    #[test]
    fn derive_child_caps_expiry_at_the_parents_own() {
        let parent = delegable_path_lease();
        let mut request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        request.child_expires_at = t(9_999);
        let child = parent
            .derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .expect("a narrower child must derive");
        assert_eq!(child.expires_at(), t(2_000));
    }

    /// AAASM-6161: a child's `not_before` is floored at
    /// `max(issued_at, parent.not_before)` — closing the gap where a child
    /// derived with an early `issued_at` could become valid before its
    /// parent does.
    #[test]
    fn derive_child_floors_not_before_at_the_parents_own() {
        let parent = delegable_path_lease().with_not_before(t(1_500));
        let request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        let child = parent
            .derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .expect("a narrower child must derive");
        assert_eq!(child.not_before(), t(1_500));
    }

    /// A requested quantitative ceiling that exceeds the parent's own is
    /// refused, naming the field that exceeded.
    #[test]
    fn derive_child_refuses_a_limit_exceeding_the_parents_own() {
        let parent = delegable_path_lease().with_limits(crate::spec::ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });
        let mut request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        request.child_limits = Some(crate::spec::ResourceLimits {
            max_memory_bytes: Some(2_000),
            ..Default::default()
        });
        assert_eq!(
            parent.derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100)),
            Err(DelegationDenied::LimitsExceedParent {
                field: "max_memory_bytes".to_string()
            })
        );
    }

    /// Every derived child carries [`DelegationProvenance`] naming the parent
    /// lease it came from — the "evidence can explain every child capability"
    /// acceptance criterion, pinned at the type that carries it.
    #[test]
    fn derive_child_records_provenance_naming_the_parent_lease() {
        let parent = delegable_path_lease();
        let request = base_request(RequirementScope::Selectors(vec![
            "permit-only:/workspace/sub".to_string()
        ]));
        let child = parent
            .derive_child(request, &crate::scope_order::PathPrefixOrder, t(1_100))
            .expect("a narrower child must derive");
        let provenance = child.provenance().expect("a derived child always carries provenance");
        assert_eq!(provenance.parent_lease, *parent.id());
        assert_eq!(provenance.inheritance_mode, InheritanceMode::Narrower);
    }
}
