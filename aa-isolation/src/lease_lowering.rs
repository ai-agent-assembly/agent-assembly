//! Lowering authored capability-lease policy intent into issued
//! [`CapabilityLease`]s (AAASM-6276, ADR 0038).
//!
//! # Why this is not `lowering::lower_policy`
//!
//! [`crate::lowering::lower_policy`] is documented as a pure, deterministic
//! mapping from the canonical restriction AST (`aa_security::policy::
//! PolicyDocument`) onto [`crate::spec::ControlRequirement`]s — "what must
//! not happen". A lease states a different kind of fact: who was authorized,
//! for how long, and whether a child launch may inherit the grant. Folding
//! lease lowering into `lower_policy` would put a lifetime- and
//! issuer-bearing grant on the same path `aa_security`'s canonical AST feeds
//! the eBPF kernel-map compiler — exactly the hazard `aa_policy::document::
//! LeaseDomain`'s own doc comment warns against, from the other side of the
//! crate boundary. So this is a second, independent entry point, reading a
//! source [`lower_policy`](crate::lowering::lower_policy) never reads.
//!
//! # Why the input is not `aa_policy`'s own type
//!
//! This crate's packaging contract (see the crate-level documentation,
//! "Policy lowering") forbids a dependency that brings in a platform, an
//! async runtime or a serialization format. `aa-policy` brings all three
//! (`serde_yaml`, `chrono`, `dirs`, …) through its own dependency graph, so
//! `aa-isolation` cannot depend on it the way it depends on the leaner
//! `aa-security`. [`AuthoredLease`] is this crate's side of the same
//! by-name mirroring `aa_policy::document::LeaseDomain` and `LeaseScope`
//! already use for [`CapabilityDomain`] and [`RequirementScope`] — the
//! caller (AAASM-6277's `aa-cli` integration) converts `aa_policy`'s
//! validated `CanonicalLeaseGrant` into an [`AuthoredLease`] with a trivial,
//! exhaustive match before calling [`lower_leases`], and that conversion
//! lives on the `aa-cli` side of the fence, never here.
//!
//! # What an authored grant does not carry, and why that is not a gap
//!
//! [`AuthoredLease`] mirrors `aa_policy::document::LeaseGrant` field for
//! field, and that type documents exactly why it carries no `LeaseId`, no
//! `issued_at`/`expires_at` instant and no subject: those are issuance-time
//! facts a policy author cannot predict. [`LeaseIssuance`] is where this
//! module collects them from the caller — once, for the whole batch, since
//! every lease issued from one lowering pass shares one subject and one
//! issuance instant.
//!
//! # Fail-closed decisions this module makes
//!
//! * **`max_count` has no home on [`CapabilityLease`].** The type has no
//!   use-count field, and [`crate::spec::ResourceLimits`] is a different
//!   dimension (memory/CPU/PID/wall-clock/file-size/descriptor ceilings, not
//!   a call count). Dropping an authored `max_count` would lower a grant
//!   that reads as narrower than it actually is once issued — the exact
//!   silent-loss defect AAASM-5753 records, applied to a grant instead of a
//!   restriction. [`lower_leases`] refuses instead:
//!   [`LeaseLoweringError::UnrepresentableMaxCount`]. Carrying a use count on
//!   [`CapabilityLease`] is a `aa-isolation` schema change for a future
//!   ticket, not something this lowering can paper over.
//! * **No `ttl_seconds` never means no expiry.** ADR 0038 requires every
//!   lease to have a bounded lifetime, and [`CapabilityLease::new`] enforces
//!   that by taking `expires_at` as a required constructor argument. An
//!   authored grant that states no `ttl_seconds` therefore falls back to
//!   [`LeaseIssuance::default_ttl_seconds`] — a value the *caller* must
//!   supply explicitly, never a constant hard-coded here, so "no ceiling
//!   stated" is never silently read as "no ceiling at all".
//! * **No `issuer` falls back to the caller's [`LeaseIssuance::default_issuer`],
//!   never a hard-coded identity.** `aa_policy::document::LeaseGrant::issuer`
//!   is validated as genuinely optional ("when the author wants to record
//!   one") — rejecting an unissuered grant here would refuse a document the
//!   validator already accepted. Falling back to an explicit, caller-supplied
//!   default is not the silent default the AC warns against; a
//!   module-constructed identity string would be.
//! * **[`RequirementScope::Limits`] and `Resource` + [`RequirementScope::Selectors`]
//!   are both ambiguous, not silently accepted.** The policy-authoring schema
//!   (`aa_policy::document::LeaseScope`) has no `Limits` variant at all — by
//!   that type's own doc comment, sourcing a numeric ceiling for
//!   [`CapabilityDomain::Resource`] is *this* ticket's decision, and the
//!   decision made here is that the schema cannot express one yet: a
//!   `Resource` grant may only be authored as [`RequirementScope::Whole`].
//!   A caller that nonetheless constructs an [`AuthoredLease`] with
//!   `Limits`, or a `Resource` grant scoped by selectors (a vocabulary with
//!   no meaning for that domain), gets
//!   [`LeaseLoweringError::AmbiguousScope`] rather than a lease that silently
//!   drops the scoping it claims to carry.
//!
//! # Determinism
//!
//! [`lower_leases`] is pure: the same grants and the same [`LeaseIssuance`]
//! always produce the same leases, in the same order the grants were
//! authored. `issued_at`, the subject, the default issuer and the default
//! TTL are all caller-supplied rather than read from the wall clock or any
//! ambient source, for the same reason [`crate::lease::CapabilityLease::validate_at`]
//! takes `now` as a parameter.

use std::time::{Duration, SystemTime};

use crate::capability::CapabilityDomain;
use crate::lease::{CapabilityLease, DelegationRule, LeaseBasis, LeaseId};
use crate::spec::{IdentityRef, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// One authored capability-lease grant, already translated into this crate's
/// own [`CapabilityDomain`]/[`RequirementScope`] vocabulary.
///
/// Mirrors `aa_policy::document::LeaseGrant` field for field. See the module
/// documentation for why this crate defines its own type rather than
/// depending on `aa-policy`'s.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuthoredLease {
    /// Which capability domain this lease grants authority over.
    pub domain: CapabilityDomain,
    /// What within the domain the lease covers. Only [`RequirementScope::Whole`]
    /// and [`RequirementScope::Selectors`] are representable here — see the
    /// module documentation for why [`RequirementScope::Limits`] is refused.
    pub scope: RequirementScope,
    /// Maximum number of times this lease may be exercised. Any `Some` value
    /// is refused by [`lower_leases`] — see the module documentation.
    pub max_count: Option<u64>,
    /// Seconds from issuance before this lease expires. `None` falls back to
    /// [`LeaseIssuance::default_ttl_seconds`].
    pub ttl_seconds: Option<u64>,
    /// Whether a child launch may inherit this lease, narrowed.
    pub delegable: bool,
    /// Free-text identity reference this lease is issued on behalf of.
    /// `None` falls back to [`LeaseIssuance::default_issuer`].
    pub issuer: Option<String>,
    /// The named policy rule this lease was authored under.
    pub policy_rule: Option<String>,
    /// A reference to a recorded approval, when issuance was gated on one.
    pub approval_ref: Option<String>,
    /// Why this lease is granted, in words an operator can act on. Never a
    /// credential value.
    pub reason: String,
}

/// Issuance-time facts [`lower_leases`] needs that no [`AuthoredLease`]
/// carries — see the module documentation for why these cannot come from the
/// policy document itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseIssuance {
    /// Who every lease produced by this batch authorizes. Every lease issued
    /// from one lowering pass shares one subject — the launch this policy is
    /// being lowered for.
    pub subject: IdentityRef,
    /// The identity recorded as a lease's issuer when the authored grant
    /// states none.
    pub default_issuer: IdentityRef,
    /// When this batch of leases is issued. Read once and applied to every
    /// lease, so a lowering pass is internally consistent even though
    /// computing it costs nothing to do per-lease.
    pub issued_at: SystemTime,
    /// The TTL, in seconds, applied when an authored grant states none.
    /// Required rather than optional: ADR 0038 requires every lease to have
    /// a bounded lifetime, and an `Option` here would let a caller omit the
    /// one thing standing between "no TTL stated" and "no TTL at all".
    pub default_ttl_seconds: u64,
    /// Prefix every issued [`LeaseId`] is built from, as `"{id_prefix}-{index}"`
    /// where `index` is the authored grant's position in the batch. Opaque
    /// to this module beyond that — the caller's own issuance scheme is
    /// expected to make it unique across lowering passes.
    pub id_prefix: String,
}

/// Why [`lower_leases`] refused to lower one [`AuthoredLease`].
///
/// Every variant names the authored grant's index in the batch, so a caller
/// can report exactly which `authority.leases[i]` entry to fix — the same
/// addressing `aa_policy`'s own validator uses for its `ValidationError`s.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseLoweringError {
    /// The grant at `index` states a `max_count`, which no field on
    /// [`CapabilityLease`] can carry today. See the module documentation for
    /// why this fails closed rather than silently dropping the ceiling.
    UnrepresentableMaxCount {
        /// The authored grant's position in the batch.
        index: usize,
        /// The `max_count` that could not be represented.
        max_count: u64,
    },
    /// The grant at `index` has a scope this lowering cannot interpret for
    /// `domain` — either [`RequirementScope::Limits`] (no authoring
    /// vocabulary sources one yet) or [`CapabilityDomain::Resource`] scoped
    /// by [`RequirementScope::Selectors`] (selectors have no meaning for a
    /// numeric-ceiling domain).
    AmbiguousScope {
        /// The authored grant's position in the batch.
        index: usize,
        /// The domain whose scope could not be interpreted.
        domain: CapabilityDomain,
    },
    /// Adding the grant at `index`'s TTL (authored or defaulted) to
    /// [`LeaseIssuance::issued_at`] overflowed [`SystemTime`]'s representable
    /// range.
    TtlOverflow {
        /// The authored grant's position in the batch.
        index: usize,
        /// The TTL, in seconds, that overflowed.
        ttl_seconds: u64,
    },
}

impl core::fmt::Display for LeaseLoweringError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnrepresentableMaxCount { index, max_count } => {
                write!(
                    f,
                    "authority.leases[{index}] states max_count {max_count}, which no field on a \
                     CapabilityLease can represent"
                )
            }
            Self::AmbiguousScope { index, domain } => {
                write!(
                    f,
                    "authority.leases[{index}] has a scope that cannot be interpreted for domain `{domain}`"
                )
            }
            Self::TtlOverflow { index, ttl_seconds } => {
                write!(
                    f,
                    "authority.leases[{index}]'s ttl_seconds ({ttl_seconds}) added to the issuance instant \
                     overflows the representable time range"
                )
            }
        }
    }
}

impl std::error::Error for LeaseLoweringError {}

/// Lower a batch of authored capability-lease grants into issued
/// [`CapabilityLease`]s.
///
/// Deliberately separate from [`crate::lowering::lower_policy`] — see the
/// module documentation for why. Deterministic: the same `grants` and
/// `issuance` always produce the same leases, in the same order `grants`
/// were authored.
///
/// # Errors
///
/// [`LeaseLoweringError`] naming the first grant that could not be lowered —
/// see that type's variants, and the module documentation's "Fail-closed
/// decisions" section, for exactly which authored shapes are refused rather
/// than silently narrowed or widened.
pub fn lower_leases(
    grants: &[AuthoredLease],
    issuance: &LeaseIssuance,
) -> Result<Vec<CapabilityLease>, LeaseLoweringError> {
    let mut leases = Vec::with_capacity(grants.len());

    for (index, grant) in grants.iter().enumerate() {
        if let Some(max_count) = grant.max_count {
            return Err(LeaseLoweringError::UnrepresentableMaxCount { index, max_count });
        }

        let scope_is_representable = !matches!(
            (&grant.scope, grant.domain),
            (RequirementScope::Limits(_), _) | (RequirementScope::Selectors(_), CapabilityDomain::Resource)
        );
        if !scope_is_representable {
            return Err(LeaseLoweringError::AmbiguousScope {
                index,
                domain: grant.domain,
            });
        }

        let ttl_seconds = grant.ttl_seconds.unwrap_or(issuance.default_ttl_seconds);
        let expires_at = issuance
            .issued_at
            .checked_add(Duration::from_secs(ttl_seconds))
            .ok_or(LeaseLoweringError::TtlOverflow { index, ttl_seconds })?;

        let issuer = match &grant.issuer {
            Some(name) => IdentityRef::root(name.clone()),
            None => issuance.default_issuer.clone(),
        };
        let mut basis = LeaseBasis::new(issuer, grant.reason.clone());
        if let Some(policy_rule) = &grant.policy_rule {
            basis = basis.with_policy_rule(policy_rule.clone());
        }
        if let Some(approval_ref) = &grant.approval_ref {
            basis = basis.with_approval_ref(approval_ref.clone());
        }

        let delegation = if grant.delegable {
            DelegationRule::DelegableWithNarrowerScope
        } else {
            DelegationRule::NotDelegable
        };

        let lease = CapabilityLease::new(
            LeaseId::new(format!("{}-{index}", issuance.id_prefix)),
            issuance.subject.clone(),
            grant.domain,
            grant.scope.clone(),
            issuance.issued_at,
            expires_at,
            basis,
        )
        .with_delegation(delegation);

        leases.push(lease);
    }

    Ok(leases)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuance() -> LeaseIssuance {
        LeaseIssuance {
            subject: IdentityRef::root("agent-a"),
            default_issuer: IdentityRef::root("policy-engine"),
            issued_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            default_ttl_seconds: 3_600,
            id_prefix: "lowering-pass-1".to_string(),
        }
    }

    fn whole_grant(domain: CapabilityDomain) -> AuthoredLease {
        AuthoredLease {
            domain,
            scope: RequirementScope::Whole,
            max_count: None,
            ttl_seconds: None,
            delegable: false,
            issuer: None,
            policy_rule: None,
            approval_ref: None,
            reason: "test fixture".to_string(),
        }
    }

    /// AC: a canonical policy document carrying `authority.leases` lowers to
    /// the equivalent `Vec<CapabilityLease>` — the core happy path, checked
    /// field by field against what was authored.
    #[test]
    fn an_authored_grant_lowers_to_the_equivalent_capability_lease() {
        let grant = AuthoredLease {
            domain: CapabilityDomain::NetworkEgress,
            scope: RequirementScope::Selectors(vec!["api.example.com".to_string()]),
            max_count: None,
            ttl_seconds: Some(60),
            delegable: true,
            issuer: Some("security-team".to_string()),
            policy_rule: Some("egress-allowlist".to_string()),
            approval_ref: Some("APPROVAL-42".to_string()),
            reason: "outbound calls to the billing API".to_string(),
        };
        let issuance = issuance();

        let leases = lower_leases(&[grant], &issuance).expect("lowering must succeed");
        assert_eq!(leases.len(), 1);
        let lease = &leases[0];

        assert_eq!(lease.id(), &LeaseId::new("lowering-pass-1-0"));
        assert_eq!(lease.subject(), &issuance.subject);
        assert_eq!(lease.domain(), CapabilityDomain::NetworkEgress);
        assert_eq!(
            lease.scope(),
            &RequirementScope::Selectors(vec!["api.example.com".to_string()])
        );
        assert_eq!(lease.issued_at(), issuance.issued_at);
        assert_eq!(lease.expires_at(), issuance.issued_at + Duration::from_secs(60));
        assert_eq!(lease.delegation(), DelegationRule::DelegableWithNarrowerScope);
        assert_eq!(lease.basis().issuer, IdentityRef::root("security-team"));
        assert_eq!(lease.basis().policy_rule, Some("egress-allowlist".to_string()));
        assert_eq!(lease.basis().approval_ref, Some("APPROVAL-42".to_string()));
        assert_eq!(lease.basis().reason, "outbound calls to the billing API");

        // The lease this module produced for a selector it was explicitly
        // authored with must cover that exact selector under its own
        // `covers()` contract — otherwise the lowering would be internally
        // inconsistent with the grant it claims to represent.
        assert!(lease.covers(&RequirementScope::Selectors(vec!["api.example.com".to_string()])));
    }

    /// A grant that states no `ttl_seconds` falls back to
    /// [`LeaseIssuance::default_ttl_seconds`] — never an unbounded lease.
    #[test]
    fn absent_ttl_falls_back_to_the_issuance_default() {
        let issuance = issuance();
        let leases = lower_leases(&[whole_grant(CapabilityDomain::FilesystemRead)], &issuance).unwrap();
        assert_eq!(
            leases[0].expires_at(),
            issuance.issued_at + Duration::from_secs(issuance.default_ttl_seconds)
        );
    }

    /// A grant that states no `issuer` falls back to
    /// [`LeaseIssuance::default_issuer`] — the validator accepts an
    /// unissuered grant, so lowering must not refuse one either.
    #[test]
    fn absent_issuer_falls_back_to_the_issuance_default() {
        let issuance = issuance();
        let leases = lower_leases(&[whole_grant(CapabilityDomain::FilesystemRead)], &issuance).unwrap();
        assert_eq!(leases[0].basis().issuer, issuance.default_issuer);
    }

    /// `delegable: false` must never produce a delegable lease.
    #[test]
    fn non_delegable_grant_lowers_to_not_delegable() {
        let issuance = issuance();
        let leases = lower_leases(&[whole_grant(CapabilityDomain::FilesystemRead)], &issuance).unwrap();
        assert_eq!(leases[0].delegation(), DelegationRule::NotDelegable);
    }

    /// Falsification: AAASM-5753's exact failure mode, applied to a grant
    /// instead of a restriction. If this ever returned `Ok` with `max_count`
    /// silently dropped, the issued lease would read as unlimited-use when
    /// the policy author explicitly capped it.
    #[test]
    fn a_max_count_is_refused_rather_than_silently_dropped() {
        let mut grant = whole_grant(CapabilityDomain::FilesystemRead);
        grant.max_count = Some(3);
        let issuance = issuance();

        let err = lower_leases(&[grant], &issuance).unwrap_err();
        assert_eq!(
            err,
            LeaseLoweringError::UnrepresentableMaxCount { index: 0, max_count: 3 }
        );
    }

    /// The policy-authoring schema has no `Limits` scope at all; a caller
    /// that nonetheless constructs one must be refused, not silently
    /// collapsed to `Whole`.
    #[test]
    fn a_limits_scope_is_refused_as_ambiguous() {
        let mut grant = whole_grant(CapabilityDomain::Resource);
        grant.scope = RequirementScope::Limits(crate::spec::ResourceLimits::default());
        let issuance = issuance();

        let err = lower_leases(&[grant], &issuance).unwrap_err();
        assert_eq!(
            err,
            LeaseLoweringError::AmbiguousScope {
                index: 0,
                domain: CapabilityDomain::Resource,
            }
        );
    }

    /// Selectors have no meaning for a numeric-ceiling domain; this must be
    /// refused rather than lowered to a lease whose selector strings nothing
    /// will ever interpret.
    #[test]
    fn resource_domain_scoped_by_selectors_is_refused_as_ambiguous() {
        let mut grant = whole_grant(CapabilityDomain::Resource);
        grant.scope = RequirementScope::Selectors(vec!["anything".to_string()]);
        let issuance = issuance();

        let err = lower_leases(&[grant], &issuance).unwrap_err();
        assert_eq!(
            err,
            LeaseLoweringError::AmbiguousScope {
                index: 0,
                domain: CapabilityDomain::Resource,
            }
        );
    }

    /// `Resource` scoped `Whole` is the one representable shape for that
    /// domain today — it must lower cleanly, with no spurious limits
    /// attached.
    #[test]
    fn resource_domain_scoped_whole_lowers_cleanly() {
        let issuance = issuance();
        let leases = lower_leases(&[whole_grant(CapabilityDomain::Resource)], &issuance).unwrap();
        assert_eq!(leases[0].scope(), &RequirementScope::Whole);
        assert_eq!(leases[0].limits(), None);
    }

    /// A TTL that overflows `SystemTime`'s representable range must be an
    /// explicit error, never a panic or a silently clamped expiry.
    #[test]
    fn a_ttl_that_overflows_system_time_is_refused() {
        let mut grant = whole_grant(CapabilityDomain::FilesystemRead);
        grant.ttl_seconds = Some(u64::MAX);
        let issuance = issuance();

        let err = lower_leases(&[grant], &issuance).unwrap_err();
        assert_eq!(
            err,
            LeaseLoweringError::TtlOverflow {
                index: 0,
                ttl_seconds: u64::MAX,
            }
        );
    }

    /// Determinism: the same grants and issuance context lower to
    /// structurally identical leases every time.
    #[test]
    fn lowering_is_deterministic() {
        let grant = AuthoredLease {
            domain: CapabilityDomain::Syscall,
            scope: RequirementScope::Selectors(vec!["read".to_string()]),
            max_count: None,
            ttl_seconds: Some(120),
            delegable: false,
            issuer: Some("ops".to_string()),
            policy_rule: None,
            approval_ref: None,
            reason: "read-only syscalls".to_string(),
        };
        let issuance = issuance();

        let first = lower_leases(std::slice::from_ref(&grant), &issuance).unwrap();
        let second = lower_leases(&[grant], &issuance).unwrap();
        assert_eq!(first, second);
    }

    /// Multiple grants lower in authored order, each keyed to its own index
    /// in `authority.leases` for error addressing.
    #[test]
    fn multiple_grants_lower_in_authored_order_with_distinct_ids() {
        let grants = vec![
            whole_grant(CapabilityDomain::FilesystemRead),
            whole_grant(CapabilityDomain::NetworkEgress),
        ];
        let issuance = issuance();

        let leases = lower_leases(&grants, &issuance).unwrap();
        assert_eq!(leases[0].domain(), CapabilityDomain::FilesystemRead);
        assert_eq!(leases[1].domain(), CapabilityDomain::NetworkEgress);
        assert_eq!(leases[0].id(), &LeaseId::new("lowering-pass-1-0"));
        assert_eq!(leases[1].id(), &LeaseId::new("lowering-pass-1-1"));
    }

    /// A batch error names the index of the grant that actually failed, not
    /// just "something failed" — the same addressing the validator uses for
    /// `ValidationError`.
    #[test]
    fn an_error_names_the_index_of_the_failing_grant_in_a_batch() {
        let mut bad = whole_grant(CapabilityDomain::FilesystemRead);
        bad.max_count = Some(1);
        let grants = vec![whole_grant(CapabilityDomain::NetworkEgress), bad];
        let issuance = issuance();

        let err = lower_leases(&grants, &issuance).unwrap_err();
        assert_eq!(
            err,
            LeaseLoweringError::UnrepresentableMaxCount { index: 1, max_count: 1 }
        );
    }
}
