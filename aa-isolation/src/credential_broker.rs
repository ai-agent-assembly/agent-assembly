//! The identity-bound credential brokerage contract (AAASM-6164, Core ADR 0038
//! amendment).
//!
//! # What already exists, and what this module adds
//!
//! `aa-proxy` already performs Mode 1 brokerage end to end for at least one real
//! provider: it MitMs `api.anthropic.com`, strips the agent's own `Authorization`/
//! `x-api-key` header and appends the operator's real key at egress
//! (`aa-proxy/src/credentials.rs`, `aa-proxy/src/proxy/http.rs`,
//! AAASM-3578/AAASM-5926). That mechanism is not rebuilt here. The defect this
//! ticket closes is one layer up: `aasm run` hands the child the operator's own
//! provider key anyway, via ambient environment inheritance, so the strong
//! mechanism the proxy already provides is undermined by the launch path sitting
//! right next to it (`governance/capability-manifest.yaml` capability C2's own
//! `known_bypasses` already names this).
//!
//! What did not exist before this ticket: a backend-neutral statement of *what
//! credential-brokerage properties a launch requires* ([`CredentialContract`]), a
//! truthful statement of *what a mediating component actually provides for which
//! upstream services* ([`CredentialBrokerReport`]), and a witness-gated tie from
//! both to *this run's explicit authority* ([`CredentialAuthority`]/
//! [`CredentialWitness`]) — the same shape [`crate::egress`] already gave the
//! egress domain, applied here to [`CapabilityDomain::Credential`].
//!
//! # Two-value requirement axis, three-value achieved axis
//!
//! [`BrokeragePosture`] has exactly two values, for the same reason
//! [`crate::egress::EgressPosture`] does: a third ("broker preferred, raw
//! acceptable") would *be* the silent raw-credential fallback this contract
//! exists to forbid.
//!
//! [`BrokerageMode`], by contrast, has three values, and they are **not** ranked
//! against each other — they are three different mechanisms, not three
//! qualities of one mechanism. [`BrokerageMode::BrokerPerformsRequest`] means the
//! source secret never enters the child at all; [`BrokerageMode::EphemeralScopedCredential`]
//! means a different, run-bound, expiring value reaches the child;
//! [`BrokerageMode::RawInjectionFallback`] means the source secret itself
//! reaches the child. [`BrokerageMode::is_secretless`] is the one predicate that
//! collapses this axis for a caller that only needs "did the source secret
//! reach the child" — it is `false` for `RawInjectionFallback` regardless of
//! anything else.
//!
//! # Raw fallback: default Refuse
//!
//! [`RawFallbackPolicy::default`] is [`RawFallbackPolicy::Refuse`]. A launch
//! that never states otherwise cannot silently accept residual exposure — the
//! policy must be widened deliberately, the same discipline
//! [`crate::egress::RangePolicy::default`] already holds for restricted ranges.
//!
//! # Mode 2 has vocabulary, not a mechanism
//!
//! [`BrokerageMode::EphemeralScopedCredential`] and
//! [`RequiredMode::RunBoundEphemeralOnly`] exist so a future provider can be
//! *recorded* against this contract. Nothing in this repository mints an
//! ephemeral scoped credential today — there is no constructor that produces
//! this variant from a real fact, mirroring [`crate::lease::UndefinedScopeOrder`]'s
//! own "vocabulary for a case with no implementation yet" discipline.
//! [`check_required_mode`] refuses, rather than silently passing, when a
//! contract requires [`RequiredMode::RunBoundEphemeralOnly`] and no reported
//! service offers it.
//!
//! # What this module defers
//!
//! * A secrets-vault/storage backend of any kind — out of this ticket's scope
//!   by its own acceptance criteria. `aa_core::storage::CredentialStore` and its
//!   implementations are untouched.
//! * `SecretsService.DispatchTool` (`proto/secrets.proto`,
//!   `aa-api/src/routes/dispatch.rs`) stays dead code. Its fate is AAASM-5631's
//!   decision, not this ticket's — reviving it would *be* the plaintext-
//!   returning-to-arbitrary-callers surface this ticket's own acceptance
//!   criteria forbid.
//! * Per-request/per-connection proxy identity attribution.
//!   `aa-proxy/src/network_enforce.rs` still evaluates every decision under the
//!   synthetic `PROXY_AGENT_ID` at Global policy tier (already named as a
//!   residual by [`crate::egress`]'s own module documentation). Authority here
//!   is launch-level only: this run's own [`crate::spec::IdentityRef`] and lease
//!   subject.
//! * Quantitative use/byte-ceiling *enforcement*. [`CredentialCeilings`] states
//!   a ceiling and [`check_ceilings`] refuses when one is stated but the broker
//!   reports no support for it — it does not account for or enforce a number.
//! * Any revocation-*latency* claim. [`crate::lease::RevocationState`]'s own
//!   documentation already reserves that ground; nothing here adds to it.

use aa_core::attestation::ClaimTerm;

use crate::authority::{AuthorityState, AuthorityWitness, EffectiveAuthority};
use crate::capability::{CapabilityDomain, FailurePosture, SupportLevel};
use crate::evidence::{EvidenceKind, EvidenceRecord};
use crate::lease::CapabilityLease;
use crate::spec::{ExecutionSpec, IdentityRef, RequirementScope};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The schema token this contract's wire shape is versioned under. Mirrors
/// [`crate::egress::EGRESS_CONTRACT_SCHEMA`]'s own convention.
pub const CREDENTIAL_CONTRACT_SCHEMA: &str = "aasm.isolation.credential_contract/1";

/// Whether a launch requires credential brokerage at all.
///
/// Exactly two values — see the module documentation for why a third value
/// would itself be the silent fallback this contract exists to forbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum BrokeragePosture {
    /// No credential-brokerage property is required. Every launch reads this
    /// way until a policy source actually issues a [`CredentialContract`] —
    /// the rc.7/rc.8-compatible default.
    NotRequired,
    /// Credential brokerage must satisfy this contract's stated properties, or
    /// the launch must be refused.
    BrokerRequired,
}

/// How a mediating component actually handled one upstream service's
/// credential, as an achieved fact — three distinct mechanisms, not three
/// ranked qualities of one. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum BrokerageMode {
    /// The mediating component performs or authenticates the upstream request
    /// itself. The source secret never enters the child. This is what
    /// `aa-proxy`'s egress injection already does for a MitM'd provider host.
    BrokerPerformsRequest {
        /// How, in words an operator can act on (e.g. "x-api-key injected at
        /// CONNECT-mediated egress; agent's own header stripped").
        mechanism_detail: String,
    },
    /// A run-bound, expiring credential was minted for this run and handed to
    /// the child in place of the operator's own. **No constructor in this
    /// crate produces this variant from a real fact** — see the module
    /// documentation's "Mode 2 has vocabulary, not a mechanism".
    EphemeralScopedCredential {
        /// Who/what issued it, in words.
        issuer_detail: String,
        /// This credential's lifetime.
        expires_in_seconds: u64,
    },
    /// The source secret itself reaches the child. Residual exposure.
    RawInjectionFallback {
        /// Why this fallback is in effect, in words an operator can act on.
        /// An empty string means "no justification was given" and
        /// [`check_raw_fallback`] treats it as unjustified under
        /// [`RawFallbackPolicy::PermittedWhenJustified`].
        justification: String,
        /// A ticket or tracking reference for closing this residual, if one
        /// exists.
        tracked_by: Option<String>,
    },
}

impl BrokerageMode {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BrokerPerformsRequest { .. } => "broker_performs_request",
            Self::EphemeralScopedCredential { .. } => "ephemeral_scoped_credential",
            Self::RawInjectionFallback { .. } => "raw_injection_fallback",
        }
    }

    /// Whether the source secret never enters the child under this mode.
    ///
    /// **False for [`Self::RawInjectionFallback`] regardless of anything
    /// else** — the load-bearing predicate this type exists to keep truthful.
    pub fn is_secretless(&self) -> bool {
        !matches!(self, Self::RawInjectionFallback { .. })
    }
}

/// A floor on which [`BrokerageMode`] a contract will accept.
///
/// **Not** an ordering over [`BrokerageMode`] — [`Self::AnySecretlessMode`]
/// accepts either secretless mechanism, it does not rank them against each
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RequiredMode {
    /// Either [`BrokerageMode::BrokerPerformsRequest`] or
    /// [`BrokerageMode::EphemeralScopedCredential`] satisfies this floor.
    AnySecretlessMode,
    /// Only [`BrokerageMode::EphemeralScopedCredential`] satisfies this
    /// floor. No service in this repository reports this mode today — see
    /// the module documentation.
    RunBoundEphemeralOnly,
}

/// Whether a launch may fall back to [`BrokerageMode::RawInjectionFallback`]
/// at all.
///
/// `Default` is [`Self::Refuse`] — raw fallback is opt-in, never reached by
/// omission. Mirrors [`crate::egress::RangePolicy`]'s own discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RawFallbackPolicy {
    /// No service may report [`BrokerageMode::RawInjectionFallback`]; if one
    /// does, the launch is refused.
    #[default]
    Refuse,
    /// A service may report [`BrokerageMode::RawInjectionFallback`] provided
    /// its `justification` is non-empty.
    PermittedWhenJustified,
}

/// Quantitative credential-use ceilings a contract states.
///
/// Stating a ceiling here does not enforce it — no per-run use/byte accounting
/// mechanism exists in this deployment today. [`check_ceilings`] refuses a
/// launch that states one against a broker that cannot account for it, rather
/// than silently ignoring the statement — mirrors
/// [`crate::egress::EgressCeilings`] exactly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialCeilings {
    /// Maximum number of times a brokered credential may be used this run.
    pub max_uses: Option<u64>,
    /// Maximum bytes a brokered credential's requests may carry this run.
    pub max_bytes: Option<u64>,
}

impl CredentialCeilings {
    /// Whether no ceiling was stated at all.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// The stated fields' names, for an actionable refusal message.
    pub fn stated_fields(&self) -> Vec<&'static str> {
        let mut fields = Vec::new();
        if self.max_uses.is_some() {
            fields.push("max_uses");
        }
        if self.max_bytes.is_some() {
            fields.push("max_bytes");
        }
        fields
    }
}

/// What a launch requires of its credential brokerage, backend-neutral and
/// lease/identity-bound (via [`CredentialAuthority`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialContract {
    schema_version: u32,
    posture: BrokeragePosture,
    required_mode: RequiredMode,
    raw_fallback: RawFallbackPolicy,
    ceilings: CredentialCeilings,
}

impl CredentialContract {
    /// The inert, rc.7/rc.8-compatible default: no credential-brokerage
    /// property is required, so [`credential_gate`] admits without consulting
    /// a broker at all. Every real launch carries this today — no policy
    /// source issues a stronger contract yet.
    pub fn not_required() -> Self {
        Self {
            schema_version: 1,
            posture: BrokeragePosture::NotRequired,
            required_mode: RequiredMode::AnySecretlessMode,
            raw_fallback: RawFallbackPolicy::Refuse,
            ceilings: CredentialCeilings::default(),
        }
    }

    /// A contract requiring brokered credentials with the weakest properties a
    /// broker must still meet: any secretless mode, raw fallback refused, no
    /// ceiling.
    pub fn broker_required() -> Self {
        Self {
            schema_version: 1,
            posture: BrokeragePosture::BrokerRequired,
            required_mode: RequiredMode::AnySecretlessMode,
            raw_fallback: RawFallbackPolicy::Refuse,
            ceilings: CredentialCeilings::default(),
        }
    }

    /// Require at least this [`RequiredMode`].
    pub fn with_required_mode(mut self, mode: RequiredMode) -> Self {
        self.required_mode = mode;
        self
    }

    /// State the raw-fallback policy this contract requires.
    pub fn with_raw_fallback(mut self, policy: RawFallbackPolicy) -> Self {
        self.raw_fallback = policy;
        self
    }

    /// State the quantitative ceilings this contract requires.
    pub fn with_ceilings(mut self, ceilings: CredentialCeilings) -> Self {
        self.ceilings = ceilings;
        self
    }

    /// Whether credential brokerage is required at all.
    pub fn posture(&self) -> BrokeragePosture {
        self.posture
    }

    /// The minimum [`RequiredMode`] this contract requires.
    pub fn required_mode(&self) -> RequiredMode {
        self.required_mode
    }

    /// The raw-fallback policy this contract requires.
    pub fn raw_fallback(&self) -> &RawFallbackPolicy {
        &self.raw_fallback
    }

    /// The quantitative ceilings this contract states.
    pub fn ceilings(&self) -> &CredentialCeilings {
        &self.ceilings
    }

    /// This contract's schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

impl Default for CredentialContract {
    /// [`Self::not_required`] — every launch that does not construct a
    /// contract explicitly gets the rc.7/rc.8-compatible default, never
    /// [`BrokeragePosture::BrokerRequired`] by omission.
    fn default() -> Self {
        Self::not_required()
    }
}

/// One upstream service a credential broker covers, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BrokeredService {
    /// The upstream host this brokerage covers (opaque here — this type does
    /// not interpret it).
    pub service: String,
    /// The environment variable **names** this brokerage makes unnecessary in
    /// the child — names only, never values.
    pub env_names: Vec<String>,
    /// How this service's credential is actually handled.
    pub mode: BrokerageMode,
}

/// Whether a mediating component is available to this launch at all.
///
/// Reuses [`crate::egress::BrokerAvailability`] rather than a second copy of
/// the identical two-variant type — see [`CredentialBrokerReport::availability`].
pub use crate::egress::BrokerAvailability;

/// A truthful statement of what a mediating component actually provides for
/// this launch — never more than can be verified against real facts.
///
/// [`Self::new`] defaults [`Self::ceiling_support`] to
/// [`SupportLevel::Unsupported`] and reports no services — the weakest honest
/// values, mirroring [`crate::egress::EgressBrokerReport::new`]'s own
/// discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CredentialBrokerReport {
    availability: BrokerAvailability,
    failure_posture: FailurePosture,
    services: Vec<BrokeredService>,
    ceiling_support: SupportLevel,
}

impl CredentialBrokerReport {
    /// No mediating component is available, for the stated reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            availability: BrokerAvailability::Unavailable { reason: reason.into() },
            failure_posture: FailurePosture::NotApplicable,
            services: Vec::new(),
            ceiling_support: SupportLevel::Unsupported {
                reason: "no mediating component is available".to_string(),
            },
        }
    }

    /// An available broker, reporting no services and no ceiling support
    /// until [`Self::with_service`]/[`Self::with_ceiling_support`] state
    /// otherwise — see the type documentation.
    pub fn new(failure_posture: FailurePosture) -> Self {
        Self {
            availability: BrokerAvailability::Available,
            failure_posture,
            services: Vec::new(),
            ceiling_support: SupportLevel::Unsupported {
                reason: "no per-run credential use or byte accounting exists in this deployment".to_string(),
            },
        }
    }

    /// Add a covered upstream service.
    pub fn with_service(mut self, service: BrokeredService) -> Self {
        self.services.push(service);
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

    /// What this broker does when it itself fails.
    pub fn failure_posture(&self) -> FailurePosture {
        self.failure_posture
    }

    /// Every service this broker covers.
    pub fn services(&self) -> &[BrokeredService] {
        &self.services
    }

    /// This broker's support for quantitative ceilings.
    pub fn ceiling_support(&self) -> &SupportLevel {
        &self.ceiling_support
    }

    /// Every env name covered by a service whose [`BrokerageMode::is_secretless`]
    /// holds — the set [`check_posture_matches_brokerage`] requires be present
    /// in [`crate::spec::CredentialPosture::removed`] and absent from both
    /// `delegated` and `ambient_unremoved`.
    pub fn secretless_env_names(&self) -> Vec<&str> {
        self.services
            .iter()
            .filter(|s| s.mode.is_secretless())
            .flat_map(|s| s.env_names.iter().map(String::as_str))
            .collect()
    }

    /// Every env name covered only by a [`BrokerageMode::RawInjectionFallback`]
    /// service.
    pub fn residual_env_names(&self) -> Vec<&str> {
        self.services
            .iter()
            .filter(|s| !s.mode.is_secretless())
            .flat_map(|s| s.env_names.iter().map(String::as_str))
            .collect()
    }
}

/// This run's authority for [`CapabilityDomain::Credential`] — constructible
/// only from a spec plus an [`AuthorityWitness`], whose only producer is
/// [`crate::authority::authority_gate`]. Mirrors
/// [`crate::egress::EgressAuthority::from_gated_spec`] exactly.
#[derive(Debug, Clone)]
pub struct CredentialAuthority {
    identity: IdentityRef,
    credential_state: AuthorityState,
}

impl CredentialAuthority {
    /// Build this run's credential authority from a spec
    /// [`crate::authority::authority_gate`] has already validated.
    ///
    /// `_witness` is not read — see [`crate::egress::EgressAuthority::from_gated_spec`]'s
    /// own documentation for why that is the whole mechanism.
    pub fn from_gated_spec(spec: &ExecutionSpec, _witness: &AuthorityWitness) -> Self {
        let authority = EffectiveAuthority::from_spec(spec).unwrap_or_else(|_| EffectiveAuthority::deny_all());
        Self {
            identity: spec.identity().clone(),
            credential_state: authority.state(CapabilityDomain::Credential).clone(),
        }
    }

    /// Who this authority was built for. Asserted, not verified — see
    /// [`IdentityRef`].
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// This run's authority state for [`CapabilityDomain::Credential`].
    pub fn credential_state(&self) -> &AuthorityState {
        &self.credential_state
    }

    /// The validated [`CapabilityLease`] backing [`Self::credential_state`],
    /// when authority is [`AuthorityState::Leased`]. `None` for
    /// [`AuthorityState::Denied`] and [`AuthorityState::CompatibilityResidual`]
    /// alike.
    pub fn credential_lease(&self) -> Option<&CapabilityLease> {
        match &self.credential_state {
            AuthorityState::Leased(lease) => Some(lease.as_ref()),
            _ => None,
        }
    }
}

/// Unforgeable-by-construction proof that [`credential_gate`] ran and
/// admitted the launch. Mirrors [`crate::egress::EgressWitness`] exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialWitness(());

/// Why [`credential_gate`] (or one of the checks it composes) refused a
/// launch.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CredentialRefusal {
    /// [`BrokeragePosture::BrokerRequired`] but no mediating component is
    /// available.
    BrokerRequiredButUnavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// A broker is available but fails open — which does not satisfy a
    /// *required* brokered path.
    BrokerRequiredButFailsOpen {
        /// The broker's actual failure posture.
        posture: FailurePosture,
    },
    /// No service is brokered at all.
    NoServiceBrokered,
    /// A reported service's [`BrokerageMode`] does not meet what the
    /// contract requires.
    ModeInsufficient {
        /// The service whose mode fell short.
        service: String,
        /// What the contract requires.
        required: RequiredMode,
        /// What the broker actually reports for that service.
        reported: BrokerageMode,
    },
    /// A service the broker reports as secretless still has its source env
    /// name reaching the child — the property the negative-control test
    /// corroborates.
    BrokeredCredentialStillReachesChild {
        /// The env name that still reaches the child.
        name: String,
        /// The service that was supposed to make it unnecessary.
        service: String,
    },
    /// [`RawFallbackPolicy::Refuse`] but a service reports
    /// [`BrokerageMode::RawInjectionFallback`] anyway.
    RawFallbackNotPermitted {
        /// The offending service.
        service: String,
    },
    /// [`RawFallbackPolicy::PermittedWhenJustified`] but the reported
    /// fallback carries no justification.
    RawFallbackUnjustified {
        /// The offending service.
        service: String,
    },
    /// No explicit grant authorizes [`CapabilityDomain::Credential`] for this
    /// run.
    NoCredentialGrant,
    /// A grant exists for [`CapabilityDomain::Credential`] but does not cover
    /// the requested scope.
    CredentialScopeNotCoveredByGrant,
    /// [`CredentialCeilings`] stated a field the broker reports no
    /// accounting for.
    CeilingStatedButUnsupported {
        /// The stated field's name.
        field: &'static str,
        /// Why the broker cannot account for it.
        reason: String,
    },
}

impl CredentialRefusal {
    /// Every variant of this refusal concerns
    /// [`CapabilityDomain::Credential`].
    pub fn domain(&self) -> Option<CapabilityDomain> {
        Some(CapabilityDomain::Credential)
    }
}

impl core::fmt::Display for CredentialRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BrokerRequiredButUnavailable { reason } => write!(
                f,
                "brokered credentials are required but no mediating component is available: {reason}"
            ),
            Self::BrokerRequiredButFailsOpen { posture } => write!(
                f,
                "brokered credentials are required but the available broker fails open on its own \
                 failure (posture: {}), which does not satisfy a required path",
                posture.as_manifest_str()
            ),
            Self::NoServiceBrokered => write!(f, "no upstream service is covered by any credential brokerage"),
            Self::ModeInsufficient {
                service,
                required,
                reported,
            } => write!(
                f,
                "`{service}` requires {} but the broker reports {} for it",
                match required {
                    RequiredMode::AnySecretlessMode => "any secretless brokerage mode",
                    RequiredMode::RunBoundEphemeralOnly => "a run-bound ephemeral credential",
                },
                reported.as_str()
            ),
            Self::BrokeredCredentialStillReachesChild { name, service } => write!(
                f,
                "`{name}` is reported secretless by `{service}`'s brokerage but still reaches the child"
            ),
            Self::RawFallbackNotPermitted { service } => write!(
                f,
                "`{service}` reports a raw credential fallback, which this contract's policy refuses"
            ),
            Self::RawFallbackUnjustified { service } => write!(
                f,
                "`{service}` reports a raw credential fallback with no stated justification"
            ),
            Self::NoCredentialGrant => write!(f, "no explicit grant authorizes credential brokerage for this run"),
            Self::CredentialScopeNotCoveredByGrant => write!(
                f,
                "a credential grant exists for this run but does not cover the requested scope"
            ),
            Self::CeilingStatedButUnsupported { field, reason } => write!(
                f,
                "the contract states `{field}` but the broker cannot account for it: {reason}"
            ),
        }
    }
}

impl std::error::Error for CredentialRefusal {}

/// Whether [`BrokeragePosture::BrokerRequired`] is actually satisfiable by
/// `broker` — availability and failure posture only. A no-op under
/// [`BrokeragePosture::NotRequired`].
pub fn check_broker_available(
    contract: &CredentialContract,
    broker: &CredentialBrokerReport,
) -> Result<(), CredentialRefusal> {
    if contract.posture() == BrokeragePosture::NotRequired {
        return Ok(());
    }
    match broker.availability() {
        BrokerAvailability::Unavailable { reason } => {
            Err(CredentialRefusal::BrokerRequiredButUnavailable { reason: reason.clone() })
        }
        BrokerAvailability::Available => match broker.failure_posture() {
            FailurePosture::FailOpen | FailurePosture::FailOpenSilent => {
                Err(CredentialRefusal::BrokerRequiredButFailsOpen {
                    posture: broker.failure_posture(),
                })
            }
            FailurePosture::FailClosed | FailurePosture::SilentTruncation | FailurePosture::NotApplicable => Ok(()),
        },
    }
}

/// Whether at least one of `broker`'s services meets `contract`'s
/// [`RequiredMode`]. A no-op under [`BrokeragePosture::NotRequired`].
pub fn check_required_mode(
    contract: &CredentialContract,
    broker: &CredentialBrokerReport,
) -> Result<(), CredentialRefusal> {
    if contract.posture() == BrokeragePosture::NotRequired {
        return Ok(());
    }
    if broker.services().is_empty() {
        return Err(CredentialRefusal::NoServiceBrokered);
    }
    let satisfied = broker.services().iter().any(|s| match contract.required_mode() {
        RequiredMode::AnySecretlessMode => s.mode.is_secretless(),
        RequiredMode::RunBoundEphemeralOnly => matches!(s.mode, BrokerageMode::EphemeralScopedCredential { .. }),
    });
    if satisfied {
        Ok(())
    } else {
        let first = &broker.services()[0];
        Err(CredentialRefusal::ModeInsufficient {
            service: first.service.clone(),
            required: contract.required_mode(),
            reported: first.mode.clone(),
        })
    }
}

/// Whether `broker` satisfies `contract`'s [`RawFallbackPolicy`]. A no-op
/// under [`BrokeragePosture::NotRequired`].
pub fn check_raw_fallback(
    contract: &CredentialContract,
    broker: &CredentialBrokerReport,
) -> Result<(), CredentialRefusal> {
    if contract.posture() == BrokeragePosture::NotRequired {
        return Ok(());
    }
    for service in broker.services() {
        if let BrokerageMode::RawInjectionFallback { justification, .. } = &service.mode {
            match contract.raw_fallback() {
                RawFallbackPolicy::Refuse => {
                    return Err(CredentialRefusal::RawFallbackNotPermitted {
                        service: service.service.clone(),
                    });
                }
                RawFallbackPolicy::PermittedWhenJustified => {
                    if justification.trim().is_empty() {
                        return Err(CredentialRefusal::RawFallbackUnjustified {
                            service: service.service.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// Whether `authority` grants [`CapabilityDomain::Credential`] for
/// `requested_scope`.
pub fn check_credential_grant(
    authority: &CredentialAuthority,
    requested_scope: &RequirementScope,
) -> Result<(), CredentialRefusal> {
    match authority.credential_state() {
        AuthorityState::Denied => Err(CredentialRefusal::NoCredentialGrant),
        AuthorityState::CompatibilityResidual => Ok(()),
        AuthorityState::Leased(lease) => {
            if lease.covers(requested_scope) {
                Ok(())
            } else {
                Err(CredentialRefusal::CredentialScopeNotCoveredByGrant)
            }
        }
    }
}

/// The structural "no silent exposure" check: every name
/// [`CredentialBrokerReport::secretless_env_names`] names must be in
/// [`crate::spec::CredentialPosture::removed`] and in neither `delegated` nor
/// `ambient_unremoved`.
pub fn check_posture_matches_brokerage(
    broker: &CredentialBrokerReport,
    posture: &crate::spec::CredentialPosture,
) -> Result<(), CredentialRefusal> {
    for name in broker.secretless_env_names() {
        let removed = posture.removed.iter().any(|n| n == name);
        let delegated = posture.delegated.iter().any(|n| n == name);
        let ambient = posture.ambient_unremoved.iter().any(|n| n == name);
        if !removed || delegated || ambient {
            let service = broker
                .services()
                .iter()
                .find(|s| s.env_names.iter().any(|n| n == name))
                .map(|s| s.service.clone())
                .unwrap_or_default();
            return Err(CredentialRefusal::BrokeredCredentialStillReachesChild {
                name: name.to_string(),
                service,
            });
        }
    }
    Ok(())
}

/// Whether `broker` can account for every ceiling `ceilings` states. A no-op
/// when `ceilings` states nothing.
pub fn check_ceilings(ceilings: &CredentialCeilings, broker: &CredentialBrokerReport) -> Result<(), CredentialRefusal> {
    if ceilings.is_empty() {
        return Ok(());
    }
    if let SupportLevel::Unsupported { reason } = broker.ceiling_support() {
        let field = ceilings
            .stated_fields()
            .into_iter()
            .next()
            .unwrap_or("credential_ceiling");
        Err(CredentialRefusal::CeilingStatedButUnsupported {
            field,
            reason: reason.clone(),
        })
    } else {
        Ok(())
    }
}

/// Refuse a launch whose requested credential-brokerage properties the
/// available mediating component, this run's explicit authority, and the
/// actual computed environment posture cannot together satisfy.
///
/// Stops at the first refusal, in this order: [`BrokeragePosture::NotRequired`]
/// admits unconditionally, without consulting the broker, authority or
/// posture at all (the rc.7/rc.8 compatibility path — mirrors
/// [`crate::egress::egress_gate`]'s own first line exactly). Otherwise:
/// broker availability and failure posture, required mode, raw-fallback
/// policy, the credential grant, posture-matches-brokerage, then quantitative
/// ceilings.
pub fn credential_gate(
    contract: &CredentialContract,
    broker: &CredentialBrokerReport,
    authority: &CredentialAuthority,
    posture: &crate::spec::CredentialPosture,
    requested_scope: &RequirementScope,
) -> Result<CredentialWitness, CredentialRefusal> {
    if contract.posture() == BrokeragePosture::NotRequired {
        return Ok(CredentialWitness(()));
    }

    check_broker_available(contract, broker)?;
    check_required_mode(contract, broker)?;
    check_raw_fallback(contract, broker)?;
    check_credential_grant(authority, requested_scope)?;
    check_posture_matches_brokerage(broker, posture)?;
    check_ceilings(contract.ceilings(), broker)?;

    Ok(CredentialWitness(()))
}

/// A setup fact, recorded once per brokered service: this run's brokerage
/// mode for it. [`EvidenceKind::Installed`] + [`ClaimTerm::Planned`] — a fact
/// about setup, never a runtime fact, so it can never itself support
/// [`crate::evidence::EnforcementEvidence::claim_for`]. Mirrors
/// [`crate::egress::mediation_depth_record`] exactly.
pub fn brokerage_mode_record(service: &BrokeredService) -> EvidenceRecord {
    EvidenceRecord::new(
        EvidenceKind::Installed,
        CapabilityDomain::Credential,
        ClaimTerm::Planned,
        format!(
            "this run's credential brokerage for `{}`: {}",
            service.service,
            service.mode.as_str()
        ),
    )
}

/// The raw-fallback arm's evidence: planned secretless, achieved raw.
///
/// [`EvidenceKind::Installed`] + [`ClaimTerm::Degraded`] — `Degraded` is not
/// among [`ClaimTerm::asserts_coverage`]'s six terms and ranks lowest in
/// `crate::evidence`'s internal ordering, so this record can never raise
/// [`crate::evidence::EnforcementEvidence::claim_for`] for
/// [`CapabilityDomain::Credential`]. `detail` carries the justification and
/// names the service; never a credential value.
pub fn residual_exposure_record(service: &BrokeredService) -> EvidenceRecord {
    let detail = match &service.mode {
        BrokerageMode::RawInjectionFallback {
            justification,
            tracked_by,
        } => {
            let tracked = tracked_by
                .as_deref()
                .map(|t| format!(" (tracked by {t})"))
                .unwrap_or_default();
            let why = if justification.trim().is_empty() {
                "no justification was stated"
            } else {
                justification.as_str()
            };
            format!(
                "`{}`'s source credential reaches the child as a raw fallback: {why}{tracked}",
                service.service
            )
        }
        other => format!(
            "`{}` is recorded as residual exposure but its reported mode is `{}`, not a raw fallback",
            service.service,
            other.as_str()
        ),
    };
    EvidenceRecord::new(
        EvidenceKind::Installed,
        CapabilityDomain::Credential,
        ClaimTerm::Degraded,
        detail,
    )
}
