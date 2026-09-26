//! The identity-bound, policy-governed egress contract (AAASM-6163, Core ADR
//! 0038 amendment).
//!
//! # What already exists, and what this module adds
//!
//! `aa-proxy` already mediates egress at CONNECT time — an SSRF literal guard,
//! an operator denylist, a gateway-authoritative allow/deny check, an in-tunnel
//! re-check that defeats a `Host`-header bypass, and DNS-rebinding defense that
//! re-validates every resolved answer, not just the first. That mechanism is
//! not rebuilt here, and no vendor or transport name from it (or from any other
//! mechanism) appears anywhere in this file — this crate's own invariant, see
//! the crate documentation's "No mechanism vocabulary" section.
//!
//! What did not exist before this ticket: a backend-neutral statement of *what
//! egress properties a launch requires* ([`EgressContract`]), a truthful
//! statement of *what a mediating component actually provides*
//! ([`EgressBrokerReport`]), and a witness-gated tie from both to *this run's
//! explicit authority* ([`EgressAuthority`]/[`EgressWitness`]) — so that a
//! launch requiring brokered egress can be refused before any backend is
//! consulted, rather than silently falling back to direct network access.
//!
//! # The discriminator this module exists to keep visible
//!
//! [`crate::capability::CapabilityReport::can_prevent`] reads only mediation,
//! timing and synchrony — it has no axis for *how much of the request* a
//! control examined. A destination-only guard that refuses before dialling is
//! `Enforce`/`Pre`/`Sync` exactly like a payload-aware one, so a report built
//! from either reads identically strong to a caller that only reads
//! `can_prevent`/`claim_ceiling`. [`MediationDepth`] is the axis that keeps
//! those two truths apart, and
//! [`EgressBrokerReport::supports_payload_aware_claim`] is the one place a
//! caller must check before treating a destination-only prevention as evidence
//! of application-semantic control.
//!
//! # Two-value posture, deliberately
//!
//! [`EgressPosture`] has exactly two values. A third ("broker preferred, direct
//! egress acceptable as a fallback") would *be* the silent direct-egress
//! fallback this ticket exists to forbid — see the acceptance criterion
//! "required brokered egress cannot silently fall back to direct network".
//!
//! # What this module defers
//!
//! * Threading a real credentialed agent identity into `aa-proxy`'s own
//!   per-connection decision — `aa-proxy/src/network_enforce.rs` already
//!   states that every decision there is still evaluated under the synthetic
//!   `PROXY_AGENT_ID` at Global policy tier, and names that as a materially
//!   new trust boundary out of scope for this ticket. [`EgressAuthority`] is a
//!   pre-launch decision in this crate ("is this run authorized for brokered
//!   egress at this scope"), not a per-connection identity on the proxy path.
//! * Quantitative connection/byte/rate *enforcement*. No accounting exists in
//!   `aa-proxy` today; [`EgressCeilings`] states a ceiling and
//!   [`check_ceilings`] refuses when one is stated but the broker reports no
//!   support for it — it does not enforce a number.
//! * Credential material of any kind — no type here holds or names one.

use std::net::IpAddr;

use aa_core::attestation::ClaimTerm;

use crate::authority::{AuthorityState, AuthorityWitness, EffectiveAuthority};
use crate::capability::{CapabilityDomain, FailurePosture, SupportLevel};
use crate::evidence::{EvidenceKind, EvidenceRecord};
use crate::lease::CapabilityLease;
use crate::lowering::permitted_selector;
use crate::spec::{ExecutionSpec, IdentityRef, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The schema token this contract's wire shape is versioned under. Mirrors
/// [`crate::report::REPORT_SCHEMA`]'s own convention: bumped on a meaning
/// change, not on an additive field.
pub const EGRESS_CONTRACT_SCHEMA: &str = "aasm.isolation.egress_contract/1";

/// How much of a request a mediating component actually examines.
///
/// The discriminator that keeps a destination-only refusal from reading as an
/// application-semantic (L7) one — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum MediationDepth {
    /// L3/L4 only: address, host and port. No request payload is parsed.
    DestinationOnly,
    /// L7: the request is parsed, so its content can be inspected or
    /// transformed. `protocols` names what was parsed (e.g. `"http/1.1"`,
    /// `"mcp"`) — opaque labels this type carries and never interprets.
    PayloadAware {
        /// The protocols this depth actually parses.
        protocols: Vec<String>,
    },
}

impl MediationDepth {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DestinationOnly => "destination_only",
            Self::PayloadAware { .. } => "payload_aware",
        }
    }

    /// Whether this depth parses request content at all.
    pub fn is_payload_aware(&self) -> bool {
        matches!(self, Self::PayloadAware { .. })
    }
}

/// Which destinations a [`MediationDepth::PayloadAware`] depth actually
/// reaches.
///
/// The `llm_only`-shaped fact, as data: a broker can be payload-aware for a
/// named set of destinations (e.g. the built-in LLM hosts) and destination-only
/// for everything else. A required payload-aware depth is only satisfied for a
/// destination the broker's own scope actually covers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MediationDepthScope {
    /// Every destination is reached at the reported [`MediationDepth`].
    EveryDestination,
    /// Only destinations matching one of these host patterns (the same
    /// grammar `aa_core::policy::is_host_allowed_by_egress_allowlist`
    /// understands) are reached at the reported [`MediationDepth`].
    /// Everything else falls back to [`MediationDepth::DestinationOnly`].
    NamedDestinationsOnly {
        /// The covered host patterns.
        patterns: Vec<String>,
    },
}

/// Whether a launch requires brokered egress at all.
///
/// Exactly two values — see the module documentation for why a third,
/// "broker preferred", value would itself be the silent fallback this
/// contract exists to forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EgressPosture {
    /// No egress-mediation property is required. Every launch reads this way
    /// until a policy source actually issues an [`EgressContract`] — the
    /// rc.7-compatible default.
    NotRequired,
    /// Egress must be mediated by a component satisfying this contract's
    /// stated properties, or the launch must be refused.
    BrokerRequired,
}

/// How a launch treats destinations in a restricted range (loopback,
/// RFC-1918/CGNAT, link-local, cloud metadata — see
/// [`aa_core::net::is_blocked_ip`]).
///
/// `Default` is [`Self::RefuseAll`] — explicit reachability, never accidental.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RangePolicy {
    /// No restricted-range destination may be reached.
    #[default]
    RefuseAll,
    /// No restricted-range destination may be reached except the named IP
    /// literals — an explicit, narrow exception, never a pattern.
    RefuseAllExcept {
        /// The exact IP literals (as they render via [`IpAddr::to_string`])
        /// permitted despite being in a restricted range.
        permitted_literals: Vec<String>,
    },
}

/// Quantitative egress ceilings a contract states.
///
/// Stating a ceiling here does not enforce it — no accounting mechanism exists
/// in `aa-proxy` today. [`check_ceilings`] refuses a launch that states one
/// against a broker that cannot account for it, rather than silently ignoring
/// the statement (the AC's "enforced where claimed, or reported unsupported"
/// arm).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EgressCeilings {
    /// Maximum simultaneously open egress connections.
    pub max_concurrent_connections: Option<u32>,
    /// Maximum total egress connections for the run's lifetime.
    pub max_connections_total: Option<u64>,
    /// Maximum total egress bytes for the run's lifetime.
    pub max_egress_bytes: Option<u64>,
    /// Maximum new connections per second.
    pub max_connections_per_second: Option<u32>,
}

impl EgressCeilings {
    /// Whether no ceiling was stated at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The stated fields' names, for an actionable refusal message.
    pub fn stated_fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        if self.max_concurrent_connections.is_some() {
            fields.push("max_concurrent_connections");
        }
        if self.max_connections_total.is_some() {
            fields.push("max_connections_total");
        }
        if self.max_egress_bytes.is_some() {
            fields.push("max_egress_bytes");
        }
        if self.max_connections_per_second.is_some() {
            fields.push("max_connections_per_second");
        }
        fields
    }
}

/// What a launch requires of its egress mediation, backend-neutral and
/// lease/identity-bound (via [`EgressAuthority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EgressContract {
    schema_version: u32,
    posture: EgressPosture,
    required_depth: MediationDepth,
    range_policy: RangePolicy,
    ceilings: EgressCeilings,
}

impl EgressContract {
    /// The inert, rc.7-compatible default: no egress-mediation property is
    /// required, so [`egress_gate`] admits without consulting a broker at
    /// all. Every real launch carries this today — no policy source issues a
    /// stronger contract yet.
    pub fn not_required() -> Self {
        Self {
            schema_version: 1,
            posture: EgressPosture::NotRequired,
            required_depth: MediationDepth::DestinationOnly,
            range_policy: RangePolicy::RefuseAll,
            ceilings: EgressCeilings::default(),
        }
    }

    /// A contract requiring brokered egress with the weakest properties a
    /// broker must still meet: destination-level mediation, restricted ranges
    /// refused, no ceiling.
    pub fn broker_required() -> Self {
        Self {
            schema_version: 1,
            posture: EgressPosture::BrokerRequired,
            required_depth: MediationDepth::DestinationOnly,
            range_policy: RangePolicy::RefuseAll,
            ceilings: EgressCeilings::default(),
        }
    }

    /// Require at least this [`MediationDepth`].
    pub fn with_required_depth(mut self, depth: MediationDepth) -> Self {
        self.required_depth = depth;
        self
    }

    /// State the restricted-range policy this contract requires.
    pub fn with_range_policy(mut self, policy: RangePolicy) -> Self {
        self.range_policy = policy;
        self
    }

    /// State the quantitative ceilings this contract requires.
    pub fn with_ceilings(mut self, ceilings: EgressCeilings) -> Self {
        self.ceilings = ceilings;
        self
    }

    /// Whether brokered egress is required at all.
    pub fn posture(&self) -> EgressPosture {
        self.posture
    }

    /// The minimum [`MediationDepth`] this contract requires.
    pub fn required_depth(&self) -> &MediationDepth {
        &self.required_depth
    }

    /// The restricted-range policy this contract requires.
    pub fn range_policy(&self) -> &RangePolicy {
        &self.range_policy
    }

    /// The quantitative ceilings this contract states.
    pub fn ceilings(&self) -> &EgressCeilings {
        &self.ceilings
    }

    /// This contract's schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Default for EgressContract {
    /// [`Self::not_required`] — every launch that does not construct a
    /// contract explicitly gets the rc.7-compatible default, never
    /// [`EgressPosture::BrokerRequired`] by omission.
    fn default() -> Self {
        Self::not_required()
    }
}

/// Whether a mediating component is available to this launch at all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BrokerAvailability {
    /// A mediating component is available.
    Available,
    /// None is, for the stated reason.
    Unavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
}

/// A truthful statement of what a mediating component actually provides for
/// this launch — never more than can be verified against real facts.
///
/// [`Self::new`] defaults [`Self::ceiling_support`] to
/// [`SupportLevel::Unsupported`] and restricted-range handling to *not*
/// refusing — the weakest honest values, mirroring
/// [`crate::capability::CapabilityReport::new`]'s own discipline: a caller
/// that forgets to state a stronger property gets the floor, never a ceiling
/// it did not earn.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EgressBrokerReport {
    availability: BrokerAvailability,
    depth: MediationDepth,
    depth_scope: MediationDepthScope,
    failure_posture: FailurePosture,
    refuses_restricted_ranges: bool,
    range_handling_detail: String,
    ceiling_support: SupportLevel,
}

impl EgressBrokerReport {
    /// No mediating component is available, for the stated reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: BrokerAvailability::Unavailable { reason: reason.into() },
            depth: MediationDepth::DestinationOnly,
            depth_scope: MediationDepthScope::EveryDestination,
            failure_posture: FailurePosture::NotApplicable,
            refuses_restricted_ranges: false,
            range_handling_detail: String::new(),
            ceiling_support: SupportLevel::Unsupported {
                reason: "no mediating component is available".to_string(),
            },
        }
    }

    /// An available broker, reporting the properties it actually has,
    /// starting from the weakest honest values for everything not stated
    /// here — see the type documentation.
    pub fn new(depth: MediationDepth, scope: MediationDepthScope, failure_posture: FailurePosture) -> Self {
        Self {
            availability: BrokerAvailability::Available,
            depth,
            depth_scope: scope,
            failure_posture,
            refuses_restricted_ranges: false,
            range_handling_detail: "not stated".to_string(),
            ceiling_support: SupportLevel::Unsupported {
                reason: "no quantitative egress accounting exists in this deployment".to_string(),
            },
        }
    }

    /// State how this broker treats restricted-range destinations.
    pub fn with_range_handling(mut self, refuses_restricted_ranges: bool, detail: impl Into<String>) -> Self {
        self.refuses_restricted_ranges = refuses_restricted_ranges;
        self.range_handling_detail = detail.into();
        self
    }

    /// State this broker's support for quantitative ceilings.
    pub fn with_ceiling_support(mut self, support: SupportLevel) -> Self {
        self.ceiling_support = support;
        self
    }

    /// Whether a mediating component is available.
    pub fn availability(&self) -> &BrokerAvailability {
        &self.availability
    }

    /// The mediation depth this broker reports.
    pub fn depth(&self) -> &MediationDepth {
        &self.depth
    }

    /// Which destinations [`Self::depth`] actually reaches, when it is
    /// [`MediationDepth::PayloadAware`].
    pub fn depth_scope(&self) -> &MediationDepthScope {
        &self.depth_scope
    }

    /// What this broker does when it itself fails.
    pub fn failure_posture(&self) -> FailurePosture {
        self.failure_posture
    }

    /// Whether this broker refuses restricted-range destinations.
    pub fn refuses_restricted_ranges(&self) -> bool {
        self.refuses_restricted_ranges
    }

    /// In words, how this broker treats restricted-range destinations.
    pub fn range_handling_detail(&self) -> &str {
        &self.range_handling_detail
    }

    /// This broker's support for quantitative ceilings.
    pub fn ceiling_support(&self) -> &SupportLevel {
        &self.ceiling_support
    }

    /// Whether this report can support a payload-aware (L7, application-
    /// semantic) claim.
    ///
    /// **False for every [`MediationDepth::DestinationOnly`] report,
    /// regardless of anything else** — the predicate that keeps a
    /// destination-only prevention (which
    /// [`crate::capability::CapabilityReport::can_prevent`]/`claim_ceiling`
    /// would happily read as [`ClaimTerm::DeniedBeforeExecution`], correctly,
    /// for the destination) from being read as evidence of payload-aware
    /// mediation, which it is not. See the module documentation.
    pub fn supports_payload_aware_claim(&self) -> bool {
        self.depth.is_payload_aware()
    }
}

/// What a destination is, after [`aa_core::net::strip_host_port`]/
/// [`aa_core::net::canonical_host`] normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationClass {
    /// A routable IP literal.
    RoutableAddress(IpAddr),
    /// An IP literal in a restricted range (see [`aa_core::net::is_blocked_ip`]).
    RestrictedAddress {
        /// The address.
        addr: IpAddr,
        /// The cloud-metadata endpoint this literal matches, if any — see
        /// [`metadata_endpoint_match`].
        known_metadata_endpoint: Option<&'static str>,
    },
    /// A name that must be resolved before it can be dialed.
    Name(String),
}

/// Classify a normalized destination host.
///
/// `host` must already be [`aa_core::net::strip_host_port`]ed — this function
/// does not itself strip a port, so a caller comparing against a raw CONNECT
/// authority must normalize first, exactly as `aa-proxy`'s own CONNECT guard
/// does before consulting `aa_core::net::is_blocked_ip`.
pub fn classify_destination(host: &str) -> DestinationClass {
    match host.parse::<IpAddr>() {
        Ok(addr) if aa_core::net::is_blocked_ip(addr) => DestinationClass::RestrictedAddress {
            addr,
            known_metadata_endpoint: metadata_endpoint_match(host),
        },
        Ok(addr) => DestinationClass::RoutableAddress(addr),
        Err(_) => DestinationClass::Name(host.to_string()),
    }
}

/// The canonical implementation of the [`crate::ambient::CLOUD_METADATA_ENDPOINTS`]
/// anchoring rule: `destination` matches an endpoint exactly, or as a prefix
/// immediately followed by `:` (a port) or `/` (a path) — never as a bare
/// numeric prefix (`169.254.169.2540` must not match `169.254.169.254`).
///
/// This is the one implementation of that rule. `aa-isolation-sandlock`'s
/// `reachable_metadata_endpoints` delegates here rather than keeping its own
/// copy (AAASM-6163) — see that function's own documentation for the residual
/// gap this anchoring does *not* close (a CIDR block or a hostname that
/// resolves into the range).
pub fn metadata_endpoint_match(destination: &str) -> Option<&'static str> {
    crate::CLOUD_METADATA_ENDPOINTS.iter().copied().find(|endpoint| {
        destination == *endpoint
            || destination
                .strip_prefix(endpoint)
                .is_some_and(|rest| rest.starts_with(':') || rest.starts_with('/'))
    })
}

/// Whether `host` is permitted by a lowered `permit-only:` grant scope.
///
/// Routes through
/// [`aa_core::policy::is_host_allowed_by_egress_allowlist_fail_closed`] — an
/// empty scope refuses (fail-closed), never reads as "no restriction".
///
/// # Errors
///
/// [`EgressRefusal::SelectorGrammarUninterpretable`] the moment any selector
/// in `scope` is not a `permit-only:` selector — the same fail-closed
/// contract `crate::scope_order`'s comparators hold for grammar they don't
/// recognize.
pub fn destination_permitted_by_scope(host: &str, scope: &RequirementScope) -> Result<(), EgressRefusal> {
    match scope {
        RequirementScope::Whole => Ok(()),
        RequirementScope::Selectors(selectors) => {
            let mut allowlist = Vec::with_capacity(selectors.len());
            for raw in selectors {
                match permitted_selector(raw) {
                    Some(name) => allowlist.push(name.to_string()),
                    None => return Err(EgressRefusal::SelectorGrammarUninterpretable),
                }
            }
            if aa_core::policy::is_host_allowed_by_egress_allowlist_fail_closed(host, &allowlist) {
                Ok(())
            } else {
                Err(EgressRefusal::EgressScopeNotCoveredByGrant)
            }
        }
        RequirementScope::Limits(_) => Err(EgressRefusal::SelectorGrammarUninterpretable),
    }
}

/// Partition resolved answers into (routable, restricted) — mirrors
/// `aa-proxy`'s `connect_revalidated`, which filters every resolved answer
/// rather than checking only the first (DNS-rebinding defense).
pub fn partition_resolved_answers(answers: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut routable = Vec::new();
    let mut restricted = Vec::new();
    for &addr in answers {
        if aa_core::net::is_blocked_ip(addr) {
            restricted.push(addr);
        } else {
            routable.push(addr);
        }
    }
    (routable, restricted)
}

/// Refuse only when resolution yielded **no** routable answer at all —
/// matching `connect_revalidated`'s actual behavior of dialling the safe
/// subset, not a stricter "every answer must be routable" rule the mechanism
/// does not implement.
pub fn check_resolved_answers(answers: &[IpAddr]) -> Result<(), EgressRefusal> {
    let (routable, _) = partition_resolved_answers(answers);
    if routable.is_empty() {
        Err(EgressRefusal::ResolutionYieldedNoRoutableAnswer)
    } else {
        Ok(())
    }
}

/// This run's authority for [`CapabilityDomain::NetworkEgress`] and
/// [`CapabilityDomain::NameResolution`] — constructible only from a spec plus
/// an [`AuthorityWitness`], whose only producer is
/// [`crate::authority::authority_gate`].
///
/// Mirrors [`crate::attenuation::ParentAuthority::from_gated_spec`]'s own
/// witness-gated mechanism: a call site that requires an `EgressAuthority`
/// cannot be satisfied by a direct socket that never went through
/// `authority_gate`, because nothing outside this crate can produce the
/// witness this constructor requires.
#[derive(Debug, Clone)]
pub struct EgressAuthority {
    identity: IdentityRef,
    egress_state: AuthorityState,
    name_resolution_state: AuthorityState,
}

impl EgressAuthority {
    /// Build this run's egress authority from a spec [`crate::authority::authority_gate`]
    /// has already validated.
    ///
    /// `_witness` is not read — its role is entirely at the type level: the
    /// only way to obtain one is to have called `authority_gate` and
    /// succeeded, so a caller cannot reach this constructor by any other
    /// path.
    pub fn from_gated_spec(spec: &ExecutionSpec, _witness: &AuthorityWitness) -> Self {
        let authority = EffectiveAuthority::from_spec(spec).unwrap_or_else(|_| EffectiveAuthority::deny_all());
        Self {
            identity: spec.identity().clone(),
            egress_state: authority.state(CapabilityDomain::NetworkEgress).clone(),
            name_resolution_state: authority.state(CapabilityDomain::NameResolution).clone(),
        }
    }

    /// Who this authority was built for. Asserted, not verified — see
    /// [`IdentityRef`].
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// This run's authority state for [`CapabilityDomain::NetworkEgress`].
    pub fn egress_state(&self) -> &AuthorityState {
        &self.egress_state
    }

    /// This run's authority state for [`CapabilityDomain::NameResolution`].
    pub fn name_resolution_state(&self) -> &AuthorityState {
        &self.name_resolution_state
    }

    /// The validated [`CapabilityLease`] backing [`Self::egress_state`], when
    /// authority is [`AuthorityState::Leased`]. `None` for
    /// [`AuthorityState::Denied`] and [`AuthorityState::CompatibilityResidual`]
    /// alike — the latter has no lease to read, only a residual grant.
    pub fn egress_lease(&self) -> Option<&CapabilityLease> {
        match &self.egress_state {
            AuthorityState::Leased(lease) => Some(lease.as_ref()),
            _ => None,
        }
    }

    /// The validated [`CapabilityLease`] backing [`Self::name_resolution_state`],
    /// under the same rule as [`Self::egress_lease`].
    pub fn name_resolution_lease(&self) -> Option<&CapabilityLease> {
        match &self.name_resolution_state {
            AuthorityState::Leased(lease) => Some(lease.as_ref()),
            _ => None,
        }
    }
}

/// Unforgeable-by-construction proof that [`egress_gate`] ran and admitted the
/// launch. The single private field and the absence of any public constructor
/// other than [`egress_gate`] are the whole mechanism — mirrors
/// [`AuthorityWitness`] and [`crate::authority::AuthorityWitness`] exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressWitness(());

/// Why [`egress_gate`] (or one of the checks it composes) refused a launch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressRefusal {
    /// [`EgressPosture::BrokerRequired`] but no mediating component is
    /// available.
    BrokerRequiredButUnavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// A broker is available but fails open — which does not satisfy a
    /// *required* brokered path (the "no silent fallback" property).
    BrokerRequiredButFailsOpen {
        /// The broker's actual failure posture.
        posture: FailurePosture,
    },
    /// The broker's [`MediationDepth`] does not meet what the contract
    /// requires.
    MediationDepthInsufficient {
        /// What the contract requires.
        required: MediationDepth,
        /// What the broker actually reports.
        reported: MediationDepth,
    },
    /// The broker's payload-aware depth does not reach the requested
    /// destinations (the `llm_only`-shaped case).
    MediationDepthOutOfScope {
        /// The broker's actual depth scope.
        scope: MediationDepthScope,
    },
    /// The contract requires restricted ranges be refused, and the broker
    /// does not refuse them.
    RestrictedRangesNotRefused {
        /// The broker's own stated range-handling detail.
        detail: String,
    },
    /// A requested destination is itself in a restricted range this
    /// contract's [`RangePolicy`] does not except.
    RestrictedDestination {
        /// Why, in words.
        detail: String,
        /// The cloud-metadata endpoint this destination matches, if any.
        known_metadata_endpoint: Option<&'static str>,
    },
    /// No explicit grant authorizes [`CapabilityDomain::NetworkEgress`] for
    /// this run.
    NoEgressGrant,
    /// A name in the requested scope needs resolution, and no explicit grant
    /// authorizes [`CapabilityDomain::NameResolution`] for this run.
    NoNameResolutionGrant,
    /// A grant exists for [`CapabilityDomain::NetworkEgress`] but does not
    /// cover the requested scope.
    EgressScopeNotCoveredByGrant,
    /// A selector in the requested scope is not a grammar this crate
    /// understands.
    SelectorGrammarUninterpretable,
    /// Every answer DNS resolution returned for a name is itself restricted.
    ResolutionYieldedNoRoutableAnswer,
    /// [`EgressCeilings`] stated a field the broker reports no accounting
    /// for.
    CeilingStatedButUnsupported {
        /// The stated field's name.
        field: &'static str,
        /// Why the broker cannot account for it.
        reason: String,
    },
}

impl EgressRefusal {
    /// Which [`CapabilityDomain`] this refusal concerns, when it concerns
    /// exactly one.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::NoNameResolutionGrant => Some(CapabilityDomain::NameResolution),
            Self::BrokerRequiredButUnavailable { .. }
            | Self::BrokerRequiredButFailsOpen { .. }
            | Self::MediationDepthInsufficient { .. }
            | Self::MediationDepthOutOfScope { .. }
            | Self::RestrictedRangesNotRefused { .. }
            | Self::RestrictedDestination { .. }
            | Self::NoEgressGrant
            | Self::EgressScopeNotCoveredByGrant
            | Self::SelectorGrammarUninterpretable
            | Self::ResolutionYieldedNoRoutableAnswer
            | Self::CeilingStatedButUnsupported { .. } => Some(CapabilityDomain::NetworkEgress),
        }
    }
}

impl core::fmt::Display for EgressRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BrokerRequiredButUnavailable { reason } => {
                write!(
                    f,
                    "brokered egress is required but no mediating component is available: {reason}"
                )
            }
            Self::BrokerRequiredButFailsOpen { posture } => write!(
                f,
                "brokered egress is required but the available broker fails open on its own failure \
                 (posture: {}), which does not satisfy a required path",
                posture.as_manifest_str()
            ),
            Self::MediationDepthInsufficient { required, reported } => write!(
                f,
                "the contract requires {} mediation but the broker reports only {}",
                required.as_str(),
                reported.as_str()
            ),
            Self::MediationDepthOutOfScope { .. } => write!(
                f,
                "the contract requires payload-aware mediation for this destination, but the broker's \
                 payload-aware depth does not reach it"
            ),
            Self::RestrictedRangesNotRefused { detail } => {
                write!(
                    f,
                    "the contract requires restricted ranges be refused, but the broker does not: {detail}"
                )
            }
            Self::RestrictedDestination { detail, .. } => write!(f, "{detail}"),
            Self::NoEgressGrant => write!(f, "no explicit grant authorizes network egress for this run"),
            Self::NoNameResolutionGrant => {
                write!(
                    f,
                    "a requested destination needs name resolution, and no explicit grant authorizes it"
                )
            }
            Self::EgressScopeNotCoveredByGrant => {
                write!(
                    f,
                    "an egress grant exists for this run but does not cover the requested destination"
                )
            }
            Self::SelectorGrammarUninterpretable => {
                write!(f, "a requested selector is not a grammar this crate understands")
            }
            Self::ResolutionYieldedNoRoutableAnswer => {
                write!(
                    f,
                    "every address resolution returned for this destination is itself restricted"
                )
            }
            Self::CeilingStatedButUnsupported { field, reason } => {
                write!(
                    f,
                    "the contract states `{field}` but the broker cannot account for it: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for EgressRefusal {}

/// Whether [`EgressPosture::BrokerRequired`] is actually satisfiable by
/// `broker` — availability and failure posture only; see
/// [`check_mediation_depth`] and [`check_range_policy`] for the other two
/// broker-facing checks.
///
/// A no-op (always `Ok`) when `contract`'s posture is
/// [`EgressPosture::NotRequired`] — the rc.7 compatibility path.
pub fn check_broker_available(contract: &EgressContract, broker: &EgressBrokerReport) -> Result<(), EgressRefusal> {
    if contract.posture() == EgressPosture::NotRequired {
        return Ok(());
    }
    match broker.availability() {
        BrokerAvailability::Unavailable { reason } => {
            Err(EgressRefusal::BrokerRequiredButUnavailable { reason: reason.clone() })
        }
        BrokerAvailability::Available => match broker.failure_posture() {
            FailurePosture::FailOpen | FailurePosture::FailOpenSilent => {
                Err(EgressRefusal::BrokerRequiredButFailsOpen {
                    posture: broker.failure_posture(),
                })
            }
            FailurePosture::FailClosed | FailurePosture::SilentTruncation | FailurePosture::NotApplicable => Ok(()),
        },
    }
}

/// Whether `broker`'s [`MediationDepth`] meets what `contract` requires.
/// A no-op under [`EgressPosture::NotRequired`].
pub fn check_mediation_depth(contract: &EgressContract, broker: &EgressBrokerReport) -> Result<(), EgressRefusal> {
    if contract.posture() == EgressPosture::NotRequired {
        return Ok(());
    }
    match (contract.required_depth(), broker.depth()) {
        (MediationDepth::DestinationOnly, _) => Ok(()),
        (MediationDepth::PayloadAware { .. }, MediationDepth::PayloadAware { .. }) => Ok(()),
        (MediationDepth::PayloadAware { .. }, MediationDepth::DestinationOnly) => {
            Err(EgressRefusal::MediationDepthInsufficient {
                required: contract.required_depth().clone(),
                reported: broker.depth().clone(),
            })
        }
    }
}

/// Whether `broker`'s payload-aware [`MediationDepthScope`] actually reaches
/// `requested_scope`, when `contract` requires payload-aware mediation (the
/// `llm_only` reuse case). A no-op when payload-aware depth is not required,
/// or when the broker's scope is [`MediationDepthScope::EveryDestination`].
///
/// [`RequirementScope::Whole`] cannot be checked against a
/// [`MediationDepthScope::NamedDestinationsOnly`] scope — there is nothing
/// enumerated to compare — and is refused rather than assumed covered.
pub fn check_mediation_depth_scope(
    contract: &EgressContract,
    broker: &EgressBrokerReport,
    requested_scope: &RequirementScope,
) -> Result<(), EgressRefusal> {
    if contract.posture() == EgressPosture::NotRequired || !contract.required_depth().is_payload_aware() {
        return Ok(());
    }
    match broker.depth_scope() {
        MediationDepthScope::EveryDestination => Ok(()),
        MediationDepthScope::NamedDestinationsOnly { patterns } => {
            let covers = match requested_scope {
                RequirementScope::Selectors(selectors) => selectors.iter().all(|raw| {
                    let host = permitted_selector(raw).unwrap_or(raw);
                    aa_core::policy::is_host_allowed_by_egress_allowlist(host, patterns)
                }),
                RequirementScope::Whole | RequirementScope::Limits(_) => false,
            };
            if covers {
                Ok(())
            } else {
                Err(EgressRefusal::MediationDepthOutOfScope {
                    scope: broker.depth_scope().clone(),
                })
            }
        }
    }
}

/// Whether `broker` satisfies `contract`'s [`RangePolicy`]. A no-op under
/// [`EgressPosture::NotRequired`].
///
/// Deliberately does not check *which* literals a [`RangePolicy::RefuseAllExcept`]
/// names — that is [`egress_gate`]'s job once it has an actual destination to
/// compare; this check only asks whether the broker refuses restricted ranges
/// at all.
pub fn check_range_policy(contract: &EgressContract, broker: &EgressBrokerReport) -> Result<(), EgressRefusal> {
    if contract.posture() == EgressPosture::NotRequired {
        return Ok(());
    }
    if broker.refuses_restricted_ranges() {
        Ok(())
    } else {
        Err(EgressRefusal::RestrictedRangesNotRefused {
            detail: broker.range_handling_detail().to_string(),
        })
    }
}

/// Whether `authority` grants [`CapabilityDomain::NetworkEgress`] for
/// `requested_scope`.
pub fn check_egress_grant(
    authority: &EgressAuthority,
    requested_scope: &RequirementScope,
) -> Result<(), EgressRefusal> {
    match authority.egress_state() {
        AuthorityState::Denied => Err(EgressRefusal::NoEgressGrant),
        AuthorityState::CompatibilityResidual => Ok(()),
        AuthorityState::Leased(lease) => {
            if lease.covers(requested_scope) {
                Ok(())
            } else {
                Err(EgressRefusal::EgressScopeNotCoveredByGrant)
            }
        }
    }
}

/// Whether `authority` grants [`CapabilityDomain::NameResolution`], when
/// `needs_resolution` is true. A no-op (`Ok`) when it is false — a literal
/// destination needs no name-resolution grant at all.
pub fn check_name_resolution_grant(authority: &EgressAuthority, needs_resolution: bool) -> Result<(), EgressRefusal> {
    if !needs_resolution {
        return Ok(());
    }
    match authority.name_resolution_state() {
        AuthorityState::Denied => Err(EgressRefusal::NoNameResolutionGrant),
        AuthorityState::CompatibilityResidual | AuthorityState::Leased(_) => Ok(()),
    }
}

/// Whether `broker` can account for every ceiling `ceilings` states. A no-op
/// when `ceilings` states nothing.
pub fn check_ceilings(ceilings: &EgressCeilings, broker: &EgressBrokerReport) -> Result<(), EgressRefusal> {
    if ceilings.is_empty() {
        return Ok(());
    }
    if let SupportLevel::Unsupported { reason } = broker.ceiling_support() {
        let field = ceilings.stated_fields().into_iter().next().unwrap_or("egress_ceiling");
        Err(EgressRefusal::CeilingStatedButUnsupported {
            field,
            reason: reason.clone(),
        })
    } else {
        Ok(())
    }
}

/// Refuse a launch whose requested egress properties the available mediating
/// component and this run's explicit authority cannot together satisfy —
/// before any backend is consulted.
///
/// Stops at the first refusal, in this order: broker availability and failure
/// posture, mediation depth (and its destination scope), restricted-range
/// policy, the egress grant, per-destination restricted-range/metadata
/// literals (respecting [`RangePolicy::RefuseAllExcept`]), the
/// name-resolution grant (asked only when a requested selector is a name —
/// a lookup alone can exfiltrate with no egress connection at all, so this
/// must not be skipped just because [`RequirementScope::Whole`] is opaque),
/// then quantitative ceilings. This mirrors
/// [`crate::authority::authority_gate`]'s own "answers 'may this proceed',
/// not 'list every fix'" rule.
///
/// [`RequirementScope::Whole`] has no enumerated selectors to classify, so
/// per-destination restricted-range/name checks are skipped for it — a
/// broker-required contract with a `Whole` scope is still gated by broker
/// availability, mediation depth and the domain-level egress grant.
pub fn egress_gate(
    contract: &EgressContract,
    broker: &EgressBrokerReport,
    authority: &EgressAuthority,
    requested_scope: &RequirementScope,
) -> Result<EgressWitness, EgressRefusal> {
    // rc.7 compatibility: `NotRequired` admits unconditionally, without
    // consulting the broker OR this run's egress/name-resolution authority —
    // every launch that predates this contract carries no `EgressAuthority`
    // grant for either domain, and this contract must not newly refuse it.
    if contract.posture() == EgressPosture::NotRequired {
        return Ok(EgressWitness(()));
    }

    check_broker_available(contract, broker)?;
    check_mediation_depth(contract, broker)?;
    check_mediation_depth_scope(contract, broker, requested_scope)?;
    check_range_policy(contract, broker)?;
    check_egress_grant(authority, requested_scope)?;

    let mut needs_resolution = false;
    if let RequirementScope::Selectors(selectors) = requested_scope {
        for raw in selectors {
            let host = permitted_selector(raw).unwrap_or(raw);
            match classify_destination(host) {
                DestinationClass::RestrictedAddress {
                    addr,
                    known_metadata_endpoint,
                } => {
                    let literal = addr.to_string();
                    let excepted = matches!(
                        contract.range_policy(),
                        RangePolicy::RefuseAllExcept { permitted_literals } if permitted_literals.iter().any(|p| p == &literal)
                    );
                    if !excepted {
                        return Err(EgressRefusal::RestrictedDestination {
                            detail: format!("destination `{literal}` is in a range this contract requires be refused"),
                            known_metadata_endpoint,
                        });
                    }
                }
                DestinationClass::Name(_) => needs_resolution = true,
                DestinationClass::RoutableAddress(_) => {}
            }
        }
    }
    check_name_resolution_grant(authority, needs_resolution)?;
    check_ceilings(contract.ceilings(), broker)?;

    Ok(EgressWitness(()))
}

/// A destination was refused at address/port level, before any request
/// payload existed to parse.
///
/// Always [`EvidenceKind::Decision`] + [`ClaimTerm::DeniedBeforeExecution`].
/// `detail`'s sentence is derived from `depth` rather than hand-written at the
/// call site, so a caller cannot drop the L3/L4-vs-L7 distinction by omission
/// — see [`EgressBrokerReport::supports_payload_aware_claim`] for the
/// property this exists to keep visible.
pub fn destination_prevention_record(depth: &MediationDepth, detail: impl Into<String>) -> EvidenceRecord {
    let detail = detail.into();
    let sentence = match depth {
        MediationDepth::DestinationOnly => {
            format!("{detail} (destination-level refusal; no request payload was parsed)")
        }
        MediationDepth::PayloadAware { .. } => format!("{detail} (payload-aware refusal)"),
    };
    EvidenceRecord::new(
        EvidenceKind::Decision,
        CapabilityDomain::NetworkEgress,
        ClaimTerm::DeniedBeforeExecution,
        sentence,
    )
}

/// The mediation depth this run actually had, recorded once per run.
///
/// [`EvidenceKind::Installed`] + [`ClaimTerm::Planned`] — a fact about setup,
/// never a runtime fact, so it can never itself support
/// [`crate::evidence::EnforcementEvidence::claim_for`].
pub fn mediation_depth_record(report: &EgressBrokerReport) -> EvidenceRecord {
    EvidenceRecord::new(
        EvidenceKind::Installed,
        CapabilityDomain::NetworkEgress,
        ClaimTerm::Planned,
        format!("this run's egress mediation depth: {}", report.depth().as_str()),
    )
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::attenuation::Ancestry;
    use crate::authority::authority_gate;
    use crate::lease::{CapabilityLease, LeaseBasis, LeaseId};
    use crate::lowering::permit_only_selector;
    use crate::spec::ControlRequirement;

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

    /// Builds an [`EgressAuthority`] from a spec, going through the real
    /// `authority_gate` — the only production path to a witness.
    fn egress_authority_for(spec: &ExecutionSpec) -> EgressAuthority {
        let witness = authority_gate(spec, &Ancestry::Root, t(1_500)).expect("spec authorized in this fixture");
        EgressAuthority::from_gated_spec(spec, &witness)
    }

    fn selectors(names: &[&str]) -> RequirementScope {
        RequirementScope::Selectors(names.iter().map(|n| permit_only_selector(n)).collect())
    }

    fn available_broker() -> EgressBrokerReport {
        EgressBrokerReport::new(
            MediationDepth::DestinationOnly,
            MediationDepthScope::EveryDestination,
            FailurePosture::FailClosed,
        )
        .with_range_handling(true, "test fixture refuses restricted ranges")
    }

    // ---- Positive controls -------------------------------------------------

    #[test]
    fn not_required_admits_with_no_broker_at_all() {
        // rc.7 compatibility: `NotRequired` never consults the broker.
        let contract = EgressContract::not_required();
        let broker = EgressBrokerReport::unavailable("no broker in this deployment");
        let spec = base_spec();
        let authority = egress_authority_for(&spec);
        assert!(egress_gate(&contract, &broker, &authority, &RequirementScope::Whole).is_ok());
    }

    #[test]
    fn routable_destination_with_covering_grant_and_available_broker_is_admitted() {
        let scope = selectors(&["api.example.com"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority = egress_authority_for(&spec);
        let contract = EgressContract::broker_required();
        let broker = available_broker();
        assert!(egress_gate(&contract, &broker, &authority, &scope).is_ok());
    }

    #[test]
    fn a_literal_destination_needs_no_name_resolution_grant() {
        let scope = selectors(&["93.184.216.34"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(scope.clone()));
        let spec = spec.with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()));
        // No NameResolution lease attached at all — this must still succeed.
        let authority = egress_authority_for(&spec);
        let contract = EgressContract::broker_required();
        let broker = available_broker();
        assert!(egress_gate(&contract, &broker, &authority, &scope).is_ok());
    }

    // ---- Allowed vs denied host, paired ------------------------------------

    #[test]
    fn uncovered_destination_is_refused_covered_is_admitted() {
        let granted = selectors(&["api.example.com"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(granted.clone()))
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, granted.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority = egress_authority_for(&spec);
        let contract = EgressContract::broker_required();
        let broker = available_broker();

        let uncovered = selectors(&["evil.example.com"]);
        assert_eq!(
            egress_gate(&contract, &broker, &authority, &uncovered),
            Err(EgressRefusal::EgressScopeNotCoveredByGrant)
        );
        // Control: the exact granted scope is admitted.
        assert!(egress_gate(&contract, &broker, &authority, &granted).is_ok());
    }

    #[test]
    fn destination_permitted_by_scope_bare_suffix_vs_leftmost_wildcard() {
        let wildcard = RequirementScope::Selectors(vec![permit_only_selector("*.example.com")]);
        assert!(destination_permitted_by_scope("api.example.com", &wildcard).is_ok());
        // The bare suffix itself is not covered by a leftmost wildcard.
        assert!(destination_permitted_by_scope("example.com", &wildcard).is_err());
    }

    #[test]
    fn destination_permitted_by_scope_rejects_attacker_crafted_suffix() {
        let wildcard = RequirementScope::Selectors(vec![permit_only_selector("*.example.com")]);
        assert!(destination_permitted_by_scope("evilexample.com", &wildcard).is_err());
        assert!(destination_permitted_by_scope("api.evil-example.com", &wildcard).is_err());
    }

    #[test]
    fn destination_permitted_by_scope_empty_scope_refuses_fail_closed() {
        let empty = RequirementScope::Selectors(Vec::new());
        assert_eq!(
            destination_permitted_by_scope("api.example.com", &empty),
            Err(EgressRefusal::EgressScopeNotCoveredByGrant)
        );
    }

    #[test]
    fn destination_permitted_by_scope_non_permit_only_selector_refuses() {
        let bad = RequirementScope::Selectors(vec!["api.example.com".to_string()]);
        assert_eq!(
            destination_permitted_by_scope("api.example.com", &bad),
            Err(EgressRefusal::SelectorGrammarUninterpretable)
        );
    }

    // ---- Restricted ranges --------------------------------------------------

    #[test]
    fn loopback_destination_is_refused_routable_control_is_admitted() {
        let loopback = selectors(&["127.0.0.1"]);
        let spec = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(loopback.clone()),
        );
        let spec = spec.with_lease(lease_for(CapabilityDomain::NetworkEgress, loopback.clone()));
        let authority = egress_authority_for(&spec);
        let contract = EgressContract::broker_required();
        let broker = available_broker();
        assert!(matches!(
            egress_gate(&contract, &broker, &authority, &loopback),
            Err(EgressRefusal::RestrictedDestination { .. })
        ));

        // Control: the same shape with a routable literal is admitted.
        let routable = selectors(&["93.184.216.34"]);
        let spec2 = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(routable.clone()),
        );
        let spec2 = spec2.with_lease(lease_for(CapabilityDomain::NetworkEgress, routable.clone()));
        let authority2 = egress_authority_for(&spec2);
        assert!(egress_gate(&contract, &broker, &authority2, &routable).is_ok());
    }

    #[test]
    fn rfc1918_cgnat_and_link_local_are_restricted() {
        for literal in ["10.0.0.5", "100.64.0.1", "169.254.1.1"] {
            match classify_destination(literal) {
                DestinationClass::RestrictedAddress { .. } => {}
                other => panic!("{literal} should classify as restricted, got {other:?}"),
            }
        }
    }

    #[test]
    fn metadata_endpoint_destination_reports_the_specific_endpoint() {
        match classify_destination("169.254.169.254") {
            DestinationClass::RestrictedAddress {
                known_metadata_endpoint,
                ..
            } => assert_eq!(known_metadata_endpoint, Some("169.254.169.254")),
            other => panic!("expected a restricted metadata address, got {other:?}"),
        }
    }

    #[test]
    fn metadata_endpoint_match_anchors_and_does_not_match_a_longer_numeric_prefix() {
        assert_eq!(metadata_endpoint_match("169.254.169.254"), Some("169.254.169.254"));
        assert_eq!(metadata_endpoint_match("169.254.169.254:80"), Some("169.254.169.254"));
        assert_eq!(
            metadata_endpoint_match("169.254.169.254/latest"),
            Some("169.254.169.254")
        );
        // Anchoring edge case: a longer numeric prefix must not match.
        assert_eq!(metadata_endpoint_match("169.254.169.2540"), None);
        assert_eq!(metadata_endpoint_match("10.0.0.1"), None);
    }

    #[test]
    fn refuse_all_except_admits_only_the_named_literal() {
        let metadata = selectors(&["169.254.169.254"]);
        let spec = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(metadata.clone()),
        );
        let spec = spec.with_lease(lease_for(CapabilityDomain::NetworkEgress, metadata.clone()));
        let authority = egress_authority_for(&spec);
        let broker = available_broker();

        let refuse_all = EgressContract::broker_required();
        assert!(matches!(
            egress_gate(&refuse_all, &broker, &authority, &metadata),
            Err(EgressRefusal::RestrictedDestination { .. })
        ));

        let excepted = EgressContract::broker_required().with_range_policy(RangePolicy::RefuseAllExcept {
            permitted_literals: vec!["169.254.169.254".to_string()],
        });
        assert!(egress_gate(&excepted, &broker, &authority, &metadata).is_ok());

        // Control: a *different* restricted literal is still refused under
        // the same exception list.
        let other_restricted = selectors(&["127.0.0.1"]);
        let spec2 = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(other_restricted.clone()),
        );
        let spec2 = spec2.with_lease(lease_for(CapabilityDomain::NetworkEgress, other_restricted.clone()));
        let authority2 = egress_authority_for(&spec2);
        assert!(matches!(
            egress_gate(&excepted, &broker, &authority2, &other_restricted),
            Err(EgressRefusal::RestrictedDestination { .. })
        ));
    }

    // ---- IPv6 / normalization ------------------------------------------------

    #[test]
    fn ipv4_mapped_v6_loopback_is_restricted() {
        assert!(matches!(
            classify_destination("::ffff:127.0.0.1"),
            DestinationClass::RestrictedAddress { .. }
        ));
    }

    #[test]
    fn nat64_and_6to4_encodings_are_restricted() {
        // NAT64 well-known prefix embedding a private v4 address.
        assert!(matches!(
            classify_destination("64:ff9b::a00:1"),
            DestinationClass::RestrictedAddress { .. }
        ));
    }

    #[test]
    fn bracketed_ipv6_with_port_normalizes_before_classification() {
        let normalized = aa_core::net::strip_host_port("[::1]:443");
        assert!(matches!(
            classify_destination(normalized),
            DestinationClass::RestrictedAddress { .. }
        ));
    }

    #[test]
    fn trailing_dot_and_uppercase_host_normalizes_to_a_name() {
        let normalized = aa_core::net::canonical_host("EVIL.COM.");
        assert_eq!(normalized, "evil.com");
        assert!(matches!(classify_destination(&normalized), DestinationClass::Name(_)));
    }

    // ---- Direct-IP bypass ----------------------------------------------------

    #[test]
    fn hostname_only_grant_does_not_admit_the_same_destinations_raw_ip() {
        let hostname_scope = selectors(&["api.example.com"]);
        assert!(destination_permitted_by_scope("api.example.com", &hostname_scope).is_ok());
        // The raw IP literal for the same destination is not admitted by a
        // hostname-only grant.
        assert!(destination_permitted_by_scope("93.184.216.34", &hostname_scope).is_err());
    }

    // ---- DNS / multi-answer / rebinding ---------------------------------------

    #[test]
    fn egress_grant_without_name_resolution_grant_refuses_a_name() {
        let scope = selectors(&["api.example.com"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(scope.clone()));
        // Only a NetworkEgress lease, no NameResolution lease.
        let spec = spec.with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()));
        let authority = egress_authority_for(&spec);
        let contract = EgressContract::broker_required();
        let broker = available_broker();
        assert_eq!(
            egress_gate(&contract, &broker, &authority, &scope),
            Err(EgressRefusal::NoNameResolutionGrant)
        );

        // Control: adding the NameResolution grant admits, changing nothing else.
        let spec2 = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority2 = egress_authority_for(&spec2);
        assert!(egress_gate(&contract, &broker, &authority2, &scope).is_ok());
    }

    #[test]
    fn multi_answer_resolution_keeps_only_routable_answers() {
        let answers: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let (routable, restricted) = partition_resolved_answers(&answers);
        assert_eq!(routable.len(), 1);
        assert_eq!(restricted.len(), 1);
        assert!(check_resolved_answers(&answers).is_ok());
    }

    #[test]
    fn all_restricted_answers_refuses() {
        let answers: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap()];
        assert_eq!(
            check_resolved_answers(&answers),
            Err(EgressRefusal::ResolutionYieldedNoRoutableAnswer)
        );
    }

    #[test]
    fn a_rebinding_shaped_answer_flip_is_caught_independently_of_the_initial_grant() {
        // The first resolution is all-routable; a later resolution for the
        // same name returns only restricted answers (a rebinding attempt).
        // Each call is independent — the initial grant check does not cache
        // the first result and skip re-checking the second.
        let first: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
        let second: Vec<IpAddr> = vec!["169.254.169.254".parse().unwrap()];
        assert!(check_resolved_answers(&first).is_ok());
        assert_eq!(
            check_resolved_answers(&second),
            Err(EgressRefusal::ResolutionYieldedNoRoutableAnswer)
        );
    }

    // ---- Broker availability / fail-open ---------------------------------------

    #[test]
    fn unavailable_broker_refuses_and_names_the_reason() {
        let contract = EgressContract::broker_required();
        let broker = EgressBrokerReport::unavailable("no dedicated proxy is bound for this launch");
        let spec = base_spec();
        let authority = egress_authority_for(&spec);
        assert_eq!(
            egress_gate(&contract, &broker, &authority, &RequirementScope::Whole),
            Err(EgressRefusal::BrokerRequiredButUnavailable {
                reason: "no dedicated proxy is bound for this launch".to_string(),
            })
        );
    }

    #[test]
    fn a_fail_open_broker_is_refused_for_a_required_path_control_fail_closed_admits() {
        let contract = EgressContract::broker_required();
        // A compatibility-residual grant (a requirement, no lease) so the
        // control admits on the egress-grant check too — this test is about
        // failure posture, not the grant.
        let spec = base_spec().with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress));
        let authority = egress_authority_for(&spec);

        let fail_open = EgressBrokerReport::new(
            MediationDepth::DestinationOnly,
            MediationDepthScope::EveryDestination,
            FailurePosture::FailOpen,
        )
        .with_range_handling(true, "refuses restricted ranges");
        assert_eq!(
            egress_gate(&contract, &fail_open, &authority, &RequirementScope::Whole),
            Err(EgressRefusal::BrokerRequiredButFailsOpen {
                posture: FailurePosture::FailOpen,
            })
        );

        // Control: identical report except FailClosed is admitted — the core
        // "no silent fallback" property.
        let fail_closed = EgressBrokerReport::new(
            MediationDepth::DestinationOnly,
            MediationDepthScope::EveryDestination,
            FailurePosture::FailClosed,
        )
        .with_range_handling(true, "refuses restricted ranges");
        assert!(egress_gate(&contract, &fail_closed, &authority, &RequirementScope::Whole).is_ok());
    }

    #[test]
    fn a_broker_that_does_not_refuse_restricted_ranges_is_refused() {
        let contract = EgressContract::broker_required();
        let broker = EgressBrokerReport::new(
            MediationDepth::DestinationOnly,
            MediationDepthScope::EveryDestination,
            FailurePosture::FailClosed,
        ); // default: does not refuse restricted ranges
        let spec = base_spec();
        let authority = egress_authority_for(&spec);
        assert!(matches!(
            egress_gate(&contract, &broker, &authority, &RequirementScope::Whole),
            Err(EgressRefusal::RestrictedRangesNotRefused { .. })
        ));
    }

    // ---- Mediation depth / L7 reuse ---------------------------------------------

    #[test]
    fn payload_aware_required_against_destination_only_broker_is_refused() {
        let contract = EgressContract::broker_required().with_required_depth(MediationDepth::PayloadAware {
            protocols: vec!["http/1.1".to_string()],
        });
        let broker = available_broker(); // DestinationOnly
        let spec = base_spec();
        let authority = egress_authority_for(&spec);
        assert!(matches!(
            egress_gate(&contract, &broker, &authority, &RequirementScope::Whole),
            Err(EgressRefusal::MediationDepthInsufficient { .. })
        ));
    }

    #[test]
    fn payload_aware_required_against_out_of_scope_broker_is_refused_named_destination_is_admitted() {
        let contract = EgressContract::broker_required().with_required_depth(MediationDepth::PayloadAware {
            protocols: vec!["http/1.1".to_string()],
        });
        let broker = EgressBrokerReport::new(
            MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string()],
            },
            MediationDepthScope::NamedDestinationsOnly {
                patterns: vec!["api.openai.com".to_string()],
            },
            FailurePosture::FailClosed,
        )
        .with_range_handling(true, "refuses restricted ranges");

        let out_of_scope = selectors(&["evil.example.com"]);
        let spec = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(out_of_scope.clone()),
        );
        let spec = spec
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, out_of_scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority = egress_authority_for(&spec);
        assert_eq!(
            egress_gate(&contract, &broker, &authority, &out_of_scope),
            Err(EgressRefusal::MediationDepthOutOfScope {
                scope: broker.depth_scope().clone(),
            })
        );

        // Control: a destination inside the named scope is admitted.
        let in_scope = selectors(&["api.openai.com"]);
        let spec2 = base_spec().with_requirement(
            ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(in_scope.clone()),
        );
        let spec2 = spec2
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, in_scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority2 = egress_authority_for(&spec2);
        assert!(egress_gate(&contract, &broker, &authority2, &in_scope).is_ok());
    }

    #[test]
    fn destination_only_broker_never_supports_a_payload_aware_claim_even_when_it_can_prevent() {
        let report = crate::capability::CapabilityReport::new(
            CapabilityDomain::NetworkEgress,
            crate::capability::Mediation::Enforce,
            crate::capability::DecisionTiming::Pre,
            crate::capability::Synchrony::Sync,
        );
        assert!(report.can_prevent());
        assert_eq!(
            report.claim_ceiling(),
            aa_core::attestation::ClaimTerm::DeniedBeforeExecution
        );

        let destination_only = available_broker();
        assert!(!destination_only.supports_payload_aware_claim());

        let payload_aware = EgressBrokerReport::new(
            MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string()],
            },
            MediationDepthScope::EveryDestination,
            FailurePosture::FailClosed,
        );
        assert!(payload_aware.supports_payload_aware_claim());
    }

    #[test]
    fn prevention_evidence_sentence_is_derived_from_depth() {
        let destination_only = destination_prevention_record(&MediationDepth::DestinationOnly, "refused 10.0.0.1");
        assert!(destination_only.detail.contains("no request payload was parsed"));

        let payload_aware = destination_prevention_record(
            &MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string()],
            },
            "refused evil.example.com",
        );
        assert!(!payload_aware.detail.contains("no request payload was parsed"));
    }

    // ---- Ceilings ------------------------------------------------------------

    #[test]
    fn stated_ceiling_against_unsupported_broker_refuses_and_names_the_field() {
        let ceilings = EgressCeilings {
            max_egress_bytes: Some(1_000_000),
            ..EgressCeilings::default()
        };
        let broker = available_broker();
        assert_eq!(
            check_ceilings(&ceilings, &broker),
            Err(EgressRefusal::CeilingStatedButUnsupported {
                field: "max_egress_bytes",
                reason: "no quantitative egress accounting exists in this deployment".to_string(),
            })
        );
    }

    #[test]
    fn no_stated_ceiling_admits_a_broker_with_no_ceiling_support() {
        let broker = available_broker();
        assert!(check_ceilings(&EgressCeilings::default(), &broker).is_ok());
    }

    // ---- Identity / lease binding ---------------------------------------------

    #[test]
    fn egress_authority_reads_network_egress_and_name_resolution_leases_separately() {
        let scope = selectors(&["api.example.com"]);
        let spec = base_spec()
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority = egress_authority_for(&spec);
        assert!(authority.egress_lease().is_some());
        assert!(authority.name_resolution_lease().is_some());
        assert_ne!(
            authority.egress_lease().unwrap().scope(),
            authority.name_resolution_lease().unwrap().scope()
        );
    }

    #[test]
    fn a_lease_scoped_to_one_host_does_not_authorize_another() {
        let scoped = selectors(&["api.example.com"]);
        let spec = base_spec().with_lease(lease_for(CapabilityDomain::NetworkEgress, scoped.clone()));
        let authority = egress_authority_for(&spec);
        let other = selectors(&["other.example.com"]);
        assert_eq!(
            check_egress_grant(&authority, &other),
            Err(EgressRefusal::EgressScopeNotCoveredByGrant)
        );
        assert!(check_egress_grant(&authority, &scoped).is_ok());
    }

    #[test]
    fn compatibility_residual_spec_still_grants_the_domain() {
        // No leases at all, but a requirement names the domain — the rc.7
        // compatibility residual.
        let scope = selectors(&["api.example.com"]);
        let spec = base_spec()
            .with_requirement(ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(scope.clone()));
        let authority = egress_authority_for(&spec);
        assert!(check_egress_grant(&authority, &scope).is_ok());
    }

    /// Every `EgressRefusal` variant is reachable from the composer — an
    /// exhaustive sweep so no variant becomes dead code nothing can produce.
    #[test]
    fn every_egress_refusal_variant_is_reachable_from_the_composer() {
        let mut seen = std::collections::BTreeSet::new();
        let mut record = |label: &'static str, result: Result<EgressWitness, EgressRefusal>| {
            if result.is_err() {
                seen.insert(label);
            }
        };

        let scope = selectors(&["api.example.com"]);
        let spec_with_grant = base_spec()
            .with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()))
            .with_lease(lease_for(CapabilityDomain::NameResolution, RequirementScope::Whole));
        let authority_with_grant = egress_authority_for(&spec_with_grant);
        let no_grant_authority = egress_authority_for(&base_spec());

        let contract = EgressContract::broker_required();
        let available = available_broker();

        record(
            "BrokerRequiredButUnavailable",
            egress_gate(
                &contract,
                &EgressBrokerReport::unavailable("x"),
                &no_grant_authority,
                &RequirementScope::Whole,
            ),
        );
        record(
            "BrokerRequiredButFailsOpen",
            egress_gate(
                &contract,
                &EgressBrokerReport::new(
                    MediationDepth::DestinationOnly,
                    MediationDepthScope::EveryDestination,
                    FailurePosture::FailOpen,
                )
                .with_range_handling(true, "x"),
                &no_grant_authority,
                &RequirementScope::Whole,
            ),
        );
        let payload_required = EgressContract::broker_required().with_required_depth(MediationDepth::PayloadAware {
            protocols: vec!["http/1.1".to_string()],
        });
        record(
            "MediationDepthInsufficient",
            egress_gate(
                &payload_required,
                &available,
                &no_grant_authority,
                &RequirementScope::Whole,
            ),
        );
        let scoped_payload_broker = EgressBrokerReport::new(
            MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string()],
            },
            MediationDepthScope::NamedDestinationsOnly {
                patterns: vec!["api.openai.com".to_string()],
            },
            FailurePosture::FailClosed,
        )
        .with_range_handling(true, "x");
        record(
            "MediationDepthOutOfScope",
            egress_gate(&payload_required, &scoped_payload_broker, &authority_with_grant, &scope),
        );
        record(
            "RestrictedRangesNotRefused",
            egress_gate(
                &contract,
                &EgressBrokerReport::new(
                    MediationDepth::DestinationOnly,
                    MediationDepthScope::EveryDestination,
                    FailurePosture::FailClosed,
                ),
                &no_grant_authority,
                &RequirementScope::Whole,
            ),
        );
        let restricted_scope = selectors(&["127.0.0.1"]);
        let restricted_spec =
            base_spec().with_lease(lease_for(CapabilityDomain::NetworkEgress, restricted_scope.clone()));
        let restricted_authority = egress_authority_for(&restricted_spec);
        record(
            "RestrictedDestination",
            egress_gate(&contract, &available, &restricted_authority, &restricted_scope),
        );
        record(
            "NoEgressGrant",
            egress_gate(&contract, &available, &no_grant_authority, &scope),
        );
        let egress_only_spec = base_spec().with_lease(lease_for(CapabilityDomain::NetworkEgress, scope.clone()));
        let egress_only_authority = egress_authority_for(&egress_only_spec);
        let name_scope = selectors(&["api.example.com"]);
        record(
            "NoNameResolutionGrant",
            egress_gate(&contract, &available, &egress_only_authority, &name_scope),
        );
        record(
            "EgressScopeNotCoveredByGrant",
            egress_gate(
                &contract,
                &available,
                &authority_with_grant,
                &selectors(&["other.example.com"]),
            ),
        );
        record(
            "SelectorGrammarUninterpretable",
            egress_gate(
                &contract,
                &available,
                &authority_with_grant,
                &RequirementScope::Selectors(vec!["no-prefix".to_string()]),
            ),
        );
        // `ResolutionYieldedNoRoutableAnswer` is reachable via `check_resolved_answers`
        // directly, not through `egress_gate` (no DNS answer set is a parameter
        // of the composer) — recorded separately from the sweep below.
        assert_eq!(
            check_resolved_answers(&["127.0.0.1".parse().unwrap()]),
            Err(EgressRefusal::ResolutionYieldedNoRoutableAnswer)
        );
        let ceiling_contract = EgressContract::broker_required().with_ceilings(EgressCeilings {
            max_egress_bytes: Some(1),
            ..EgressCeilings::default()
        });
        record(
            "CeilingStatedButUnsupported",
            egress_gate(&ceiling_contract, &available, &authority_with_grant, &scope),
        );

        let expected: std::collections::BTreeSet<&'static str> = [
            "BrokerRequiredButUnavailable",
            "BrokerRequiredButFailsOpen",
            "MediationDepthInsufficient",
            "MediationDepthOutOfScope",
            "RestrictedRangesNotRefused",
            "RestrictedDestination",
            "NoEgressGrant",
            "NoNameResolutionGrant",
            "EgressScopeNotCoveredByGrant",
            "SelectorGrammarUninterpretable",
            "CeilingStatedButUnsupported",
        ]
        .into_iter()
        .collect();
        assert_eq!(
            seen, expected,
            "every EgressRefusal variant reachable via egress_gate must fire in this sweep"
        );
    }
}
