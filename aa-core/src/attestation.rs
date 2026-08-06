//! Protection attestation — what a governance component may truthfully claim,
//! and the evidence that lets it claim it (AAASM-5535, ADR 0033 §6 and §7).
//!
//! # Why this exists
//!
//! ADR 0033 §7 records three signals in the current implementation that *look*
//! like coverage and are not: an environment variable that replaces a probe
//! result outright, a probe satisfied by a binary merely existing on `$PATH`,
//! and a layer asserted unconditionally by construction. Each of them reaches a
//! wire surface as an "active layer", which is a protection claim the system
//! cannot substantiate.
//!
//! The defect is structural, not textual. A `bool` — or a bitflag — has nowhere
//! to record *how* it came to be true, so every caller downstream is forced to
//! read "present" as "protecting". This module makes the basis of a claim part
//! of the claim, so that a basis which is not evidence cannot produce a term
//! that asserts coverage.
//!
//! # The three axes the ticket requires kept apart
//!
//! * [`SelectedMode`] — what configuration *asked for*. Intent. Never evidence.
//! * [`AttestationBasis`] — how the component's state was established.
//! * [`ClaimTerm`] — what may therefore be said, drawn from ADR 0033 §6.
//!
//! [`LayerAttestation::verified_state_at`] is the derivation between them, and
//! it is one-directional: `selected_mode` can only *lower* or hold the verified
//! state, never raise it. Asking for a control does not deliver one.
//!
//! # Relationship to ADR 0030's ladder
//!
//! [`ProtectionLevel`](crate::integration::ProtectionLevel) is the *developer
//! integration* ladder: it answers "how well is this tool integrated", keyed by
//! [`IntegrationCapability`](crate::integration::IntegrationCapability) and
//! backed by receipts. This module is deliberately **not** a second copy of it.
//! It answers a different question — "what can this enforcement component claim
//! about actions right now" — for components that have no receipt and no tool:
//! the proxy, the host-level mechanism, the in-process SDK path. The two meet
//! only in discipline: missing evidence resolves downward in both.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The ADR 0033 §6 claim vocabulary.
///
/// This is a *vocabulary*, not a ladder: the variants are not ordered and must
/// not be compared. A governance claim is incomplete without its decision
/// timing and its failure posture, so downstream material picks one of these
/// terms rather than an undifferentiated verb like "protects", "enforces" or
/// "catches".
///
/// The split that matters for safety is
/// [`asserts_coverage`](Self::asserts_coverage): six terms say *something
/// happened for this action*, and five say nothing did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ClaimTerm {
    /// An event reached the evidence pipeline.
    Observed,
    /// A pattern of interest was found in observed material.
    Detected,
    /// The control plane produced a decision for this action.
    Evaluated,
    /// The action did not take effect, and the decision preceded the effect.
    ///
    /// The only term that claims prevention. It requires a refusal by a
    /// component sitting *before* the effect; an asynchronous kill after the
    /// syscall has run is [`Detected`](Self::Detected), not this.
    DeniedBeforeExecution,
    /// The action proceeded with content removed.
    Redacted,
    /// The action was held pending a human decision.
    ApprovalRequired,
    /// A planned control is configured but unavailable, so the achieved level
    /// is below the planned level.
    Degraded,
    /// No control inspected this action or payload; nothing is known about it.
    ///
    /// Scoped deliberately: a connection-level observation may still exist for
    /// the same traffic, so *Unmeasured* about a payload does not imply
    /// *unobserved* about its connection.
    Unmeasured,
    /// Implemented but not validated for production use.
    Experimental,
    /// Decided but not implemented.
    Planned,
    /// Not available on this platform or configuration, with no plan asserted.
    Unsupported,
}

impl ClaimTerm {
    /// Whether this term asserts that a control acted on the action.
    ///
    /// This is the load-bearing predicate of the module: a basis that is not
    /// evidence must never yield a term for which this returns `true`. The six
    /// terms that assert coverage each require a durable artifact naming the
    /// component that produced them; the other five are the honest answers when
    /// no such artifact exists.
    pub fn asserts_coverage(self) -> bool {
        matches!(
            self,
            Self::Observed
                | Self::Detected
                | Self::Evaluated
                | Self::DeniedBeforeExecution
                | Self::Redacted
                | Self::ApprovalRequired
        )
    }

    /// Whether this term claims the action was stopped before it took effect.
    ///
    /// Distinct from [`asserts_coverage`](Self::asserts_coverage): observing,
    /// detecting and evaluating are all coverage and none of them are
    /// prevention. Treating observation as prevention is the single failure
    /// this vocabulary exists to prevent.
    pub fn is_prevention(self) -> bool {
        matches!(self, Self::DeniedBeforeExecution)
    }

    /// The lowercase wire name, matching the `serde` representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Detected => "detected",
            Self::Evaluated => "evaluated",
            Self::DeniedBeforeExecution => "denied_before_execution",
            Self::Redacted => "redacted",
            Self::ApprovalRequired => "approval_required",
            Self::Degraded => "degraded",
            Self::Unmeasured => "unmeasured",
            Self::Experimental => "experimental",
            Self::Planned => "planned",
            Self::Unsupported => "unsupported",
        }
    }
}

impl fmt::Display for ClaimTerm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the component that actually decided reported it did.
///
/// The name is deliberate: an adjudication is a report *by the deciding
/// component*, not an inference by an observer. A probe on the near side of a
/// MitM can see that its request went out and that nothing obviously failed,
/// and neither fact is evidence (ADR 0033 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum AdjudicatedOutcome {
    /// The deciding component refused the action before it took effect.
    Blocked,
    /// The action proceeded with content removed.
    Redacted,
    /// The action was held for a human decision.
    HeldForApproval,
    /// A decision was produced, but nothing in the path was obliged to honour
    /// it. The advisory case: an answer was computed and returned to a caller
    /// that may or may not act on it.
    DecidedAdvisory,
    /// A pattern of interest was reported, with no decision attached.
    Flagged,
    /// An event was recorded, with no pattern and no decision attached.
    Recorded,
    /// The probe ran but its result could not be attributed to any component.
    Inconclusive,
}

impl AdjudicatedOutcome {
    /// The ADR 0033 §6 term this outcome supports.
    pub fn claim(self) -> ClaimTerm {
        match self {
            Self::Blocked => ClaimTerm::DeniedBeforeExecution,
            Self::Redacted => ClaimTerm::Redacted,
            Self::HeldForApproval => ClaimTerm::ApprovalRequired,
            Self::DecidedAdvisory => ClaimTerm::Evaluated,
            Self::Flagged => ClaimTerm::Detected,
            Self::Recorded => ClaimTerm::Observed,
            // An unattributable probe result is the absence of evidence, not
            // weak evidence. It must not decay into a coverage term.
            Self::Inconclusive => ClaimTerm::Unmeasured,
        }
    }
}

/// How a component's reported state was established.
///
/// Recording the basis is the whole mechanism. ADR 0033 §7 names three signals
/// that reach a wire surface looking like coverage —
/// [`EnvironmentOverride`](Self::EnvironmentOverride),
/// [`AssumedPresent`](Self::AssumedPresent) and
/// [`ArtifactPresent`](Self::ArtifactPresent) — and each of them has a
/// [`claim_ceiling`](Self::claim_ceiling) that asserts no coverage at all. A
/// caller cannot construct a coverage claim out of them by accident, because
/// there is no code path from those variants to a coverage term.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "basis"))]
#[non_exhaustive]
pub enum AttestationBasis {
    /// An operator-supplied environment variable replaced the probe result
    /// (ADR 0033 §7, `AA_LAYERS`). No probe ran. Never evidence: the whole
    /// point of the override is to state an answer rather than measure one.
    EnvironmentOverride {
        /// The variable that supplied the answer.
        variable: String,
    },
    /// The component is asserted by construction, with nothing probed (ADR 0033
    /// §7, `LayerSet::SDK`). Never evidence: an in-process hook that exists in
    /// the build says nothing about whether any agent adopted it.
    AssumedPresent,
    /// A binary, socket or file was found to exist. Presence is not routing:
    /// ADR 0033 §7 records that `probe_proxy` is satisfied by a binary on
    /// `$PATH` without establishing that any process routes traffic through it.
    ArtifactPresent {
        /// What was found.
        artifact: String,
    },
    /// The mechanism cannot be activated because its component is not present
    /// in this build or distribution.
    AbsentFromBuild {
        /// The component that is missing.
        component: String,
    },
    /// The platform has no implementation of this mechanism.
    PlatformUnsupported {
        /// The platform, as the build reports it.
        platform: String,
    },
    /// A named prerequisite of the mechanism was checked and was not met.
    PrerequisiteUnmet {
        /// What was required.
        requirement: String,
    },
    /// The component that decides reported what it did with a real or synthetic
    /// action. The only basis that can carry a coverage term.
    Adjudicated {
        /// What that component reported.
        outcome: AdjudicatedOutcome,
    },
}

impl AttestationBasis {
    /// The strongest [`ClaimTerm`] this basis can justify, ignoring intent and
    /// freshness.
    ///
    /// This is the safety property of the module, stated as a total function:
    /// every variant except [`Adjudicated`](Self::Adjudicated) maps to a term
    /// for which [`ClaimTerm::asserts_coverage`] is `false`. Adding a variant
    /// therefore forces an author to decide, explicitly, whether it is
    /// evidence — there is no default that quietly grants coverage.
    pub fn claim_ceiling(&self) -> ClaimTerm {
        match self {
            // Stating an answer is not measuring one.
            Self::EnvironmentOverride { .. } => ClaimTerm::Unmeasured,
            // Shipping a hook is not adopting it.
            Self::AssumedPresent => ClaimTerm::Unmeasured,
            // Being installed is not being in the path.
            Self::ArtifactPresent { .. } => ClaimTerm::Unmeasured,
            // No plan is asserted by absence alone, so §6 `Unsupported` is the
            // honest term; `Degraded` is reserved for a control that *was*
            // planned, and that is decided in `LayerAttestation`.
            Self::AbsentFromBuild { .. } => ClaimTerm::Unsupported,
            Self::PlatformUnsupported { .. } => ClaimTerm::Unsupported,
            // A failed prerequisite leaves the action uninspected, which is
            // exactly §6 `Unmeasured`.
            Self::PrerequisiteUnmet { .. } => ClaimTerm::Unmeasured,
            Self::Adjudicated { outcome } => outcome.claim(),
        }
    }

    /// Whether this basis is capable of substantiating a coverage claim.
    pub fn is_evidence(&self) -> bool {
        self.claim_ceiling().asserts_coverage()
    }
}

/// What configuration asked for — intent, held strictly apart from evidence.
///
/// The ticket's requirement is that `selected_mode` and `verified_state` are
/// separate fields, because conflating them is how "we turned eBPF on" becomes
/// "eBPF is protecting you". Selection is an input to
/// [`LayerAttestation::verified_state_at`] only in the lowering direction: it
/// is what turns an unsubstantiated component from
/// [`ClaimTerm::Unsupported`]/[`ClaimTerm::Unmeasured`] into
/// [`ClaimTerm::Degraded`], because §6 reserves *Degraded* for a control that
/// was planned. It can never raise a term.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SelectedMode {
    /// Configuration asks for this component to be active.
    Enabled,
    /// Configuration asks for this component to stay off.
    Disabled,
    /// Configuration says nothing; the component is whatever the host provides.
    Unset,
}

impl SelectedMode {
    /// The lowercase wire name, matching the `serde` representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Unset => "unset",
        }
    }
}

impl fmt::Display for SelectedMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default freshness window for an attestation: 5 minutes.
///
/// Deliberately far shorter than the integration ladder's 24 hours
/// ([`DEFAULT_FRESHNESS_WINDOW_SECS`](crate::integration::DEFAULT_FRESHNESS_WINDOW_SECS)).
/// That window covers configuration read-back, which changes when a user edits
/// a file. This one covers whether a *process* is still in the path, which can
/// stop being true the moment that process exits — the AAASM-5276 spike
/// measured ~66 µs between a component stopping and its protection ceasing.
/// "Probed at startup" must not read the same as "true now".
pub const DEFAULT_ATTESTATION_FRESHNESS_SECS: u64 = 300;

/// What one governance component may claim, and why.
///
/// Read the three fields as a sentence: configuration asked for
/// `selected_mode`, we established the component's state by `basis` at
/// `observed_at_unix_secs`, and therefore
/// [`verified_state_at`](Self::verified_state_at) is all we may say.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LayerAttestation {
    /// Stable identifier of the component this attestation is about, e.g.
    /// `"proxy"`, `"host/ebpf"`, `"sdk"`.
    pub component: String,
    /// What configuration asked for. Intent, never evidence.
    pub selected_mode: SelectedMode,
    /// How the component's state was established.
    pub basis: AttestationBasis,
    /// When the basis was established, as seconds since the Unix epoch.
    pub observed_at_unix_secs: u64,
    /// Human-readable detail naming what was actually checked, for status
    /// output and audit. Says what was verified rather than asserting that
    /// something was.
    pub detail: String,
}

impl LayerAttestation {
    /// Construct one component attestation.
    pub fn new(
        component: impl Into<String>,
        selected_mode: SelectedMode,
        basis: AttestationBasis,
        observed_at_unix_secs: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            component: component.into(),
            selected_mode,
            basis,
            observed_at_unix_secs,
            detail: detail.into(),
        }
    }

    /// Whether the basis was established inside the freshness window ending at
    /// `now_unix_secs`.
    ///
    /// A basis timestamped in the future is treated as fresh; clock skew is not
    /// something this type can adjudicate.
    pub fn is_fresh(&self, now_unix_secs: u64, window_secs: u64) -> bool {
        now_unix_secs.saturating_sub(self.observed_at_unix_secs) <= window_secs
    }

    /// The term this component may claim as of `now_unix_secs`.
    ///
    /// Three rules, applied in order, and every one of them resolves downward:
    ///
    /// 1. Start from [`AttestationBasis::claim_ceiling`]. Nothing may exceed it.
    /// 2. **Stale evidence is not evidence.** A coverage term whose basis has
    ///    fallen outside the freshness window collapses to
    ///    [`ClaimTerm::Unmeasured`] — or to [`ClaimTerm::Degraded`] if the
    ///    component was selected, since a planned control whose evidence has
    ///    expired is precisely §6's *Degraded*.
    /// 3. **A control that was planned and is unsubstantiated is *Degraded*,**
    ///    not *Unsupported* and not *Unmeasured*: §6 scopes *Unsupported* to
    ///    "with no plan asserted", and asking for a control is asserting a plan.
    ///
    /// `selected_mode` appears only in rules 2 and 3, and in both it lowers.
    /// There is no branch in which it raises the term.
    pub fn verified_state_at(&self, now_unix_secs: u64, window_secs: u64) -> ClaimTerm {
        let ceiling = self.basis.claim_ceiling();

        if ceiling.asserts_coverage() && !self.is_fresh(now_unix_secs, window_secs) {
            return self.unsubstantiated_term();
        }
        if !ceiling.asserts_coverage() {
            return self.unsubstantiated_term_from(ceiling);
        }
        ceiling
    }

    /// The term for a component with no substantiated coverage, when the
    /// ceiling itself carries no information (the stale-evidence case).
    fn unsubstantiated_term(&self) -> ClaimTerm {
        self.unsubstantiated_term_from(ClaimTerm::Unmeasured)
    }

    /// The term for a component with no substantiated coverage, preserving the
    /// ceiling's own distinction between *Unsupported* and *Unmeasured* unless
    /// selection overrides it.
    fn unsubstantiated_term_from(&self, ceiling: ClaimTerm) -> ClaimTerm {
        match self.selected_mode {
            SelectedMode::Enabled => ClaimTerm::Degraded,
            SelectedMode::Disabled | SelectedMode::Unset => ceiling,
        }
    }

    /// Whether this component's claim, as of `now_unix_secs`, asserts that a
    /// control acted on an action.
    pub fn asserts_coverage_at(&self, now_unix_secs: u64, window_secs: u64) -> bool {
        self.verified_state_at(now_unix_secs, window_secs).asserts_coverage()
    }
}

/// Schema version of the attestation payload.
///
/// The ticket requires a *versioned contract*, because a consumer that renders
/// this — the public trust surface among them — must be able to refuse a
/// payload it does not understand rather than guess at it. Bump on any change
/// to the meaning of an existing field; additive optional fields do not bump.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// The complete protection attestation for one process at one instant.
///
/// Carries the provenance a consumer needs to decide whether to trust it at
/// all: which schema, which build, which platform, and when it was produced.
/// Without those, a rendered table cannot distinguish "this build has no host
/// mechanism" from "this build's host mechanism is off".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProtectionAttestation {
    /// [`ATTESTATION_SCHEMA_VERSION`] at the time of production.
    pub schema_version: u32,
    /// Version of the component that produced this attestation.
    pub component_version: String,
    /// Target triple the producing build was compiled for. A claim is only
    /// meaningful against the platform it was made on (ADR 0033 §5.3).
    pub platform: String,
    /// When this attestation was produced, as seconds since the Unix epoch.
    pub generated_at_unix_secs: u64,
    /// The window beyond which a basis stops counting as evidence.
    pub freshness_window_secs: u64,
    /// One entry per governance component, including the ones that cannot run.
    ///
    /// Components that are absent are listed, not omitted: an omitted component
    /// is indistinguishable from one that was never considered, and the whole
    /// point is that a consumer can see the gap.
    pub layers: Vec<LayerAttestation>,
}

impl ProtectionAttestation {
    /// Construct an attestation at the current schema version.
    pub fn new(
        component_version: impl Into<String>,
        platform: impl Into<String>,
        generated_at_unix_secs: u64,
        layers: Vec<LayerAttestation>,
    ) -> Self {
        Self {
            schema_version: ATTESTATION_SCHEMA_VERSION,
            component_version: component_version.into(),
            platform: platform.into(),
            generated_at_unix_secs,
            freshness_window_secs: DEFAULT_ATTESTATION_FRESHNESS_SECS,
            layers,
        }
    }

    /// Every component's claim as of `now_unix_secs`, in declaration order.
    pub fn verified_states_at(&self, now_unix_secs: u64) -> Vec<(&str, ClaimTerm)> {
        self.layers
            .iter()
            .map(|l| {
                (
                    l.component.as_str(),
                    l.verified_state_at(now_unix_secs, self.freshness_window_secs),
                )
            })
            .collect()
    }

    /// Whether *any* component substantiates a coverage claim right now.
    ///
    /// The honest answer to "is this agent governed at all". On a build with no
    /// component in any action's path this is `false`, and it must be allowed
    /// to be `false` — a system that cannot say "nothing is verified" cannot be
    /// trusted when it says something is.
    pub fn any_coverage_verified_at(&self, now_unix_secs: u64) -> bool {
        self.layers
            .iter()
            .any(|l| l.asserts_coverage_at(now_unix_secs, self.freshness_window_secs))
    }

    /// Components that were selected but cannot substantiate coverage.
    pub fn degraded_at(&self, now_unix_secs: u64) -> Vec<&LayerAttestation> {
        self.layers
            .iter()
            .filter(|l| l.verified_state_at(now_unix_secs, self.freshness_window_secs) == ClaimTerm::Degraded)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed instant, so freshness is a property of the test rather than of
    /// the wall clock.
    const NOW: u64 = 1_700_000_000;

    /// One attestation with everything but the axis under test held constant.
    fn at(basis: AttestationBasis, selected: SelectedMode, observed_at: u64) -> LayerAttestation {
        LayerAttestation::new("test/component", selected, basis, observed_at, "fixture")
    }

    // ── ADR 0033 §7: the three signals that look like coverage ───────────────

    /// §7 defect 1: `AA_LAYERS` replaces the entire probe result with an
    /// environment variable. Stating an answer must not produce a claim.
    #[test]
    fn env_override_basis_cannot_claim_coverage() {
        let basis = AttestationBasis::EnvironmentOverride {
            variable: "AA_LAYERS".into(),
        };
        assert_eq!(basis.claim_ceiling(), ClaimTerm::Unmeasured);
        assert!(!basis.is_evidence());

        let a = at(basis, SelectedMode::Unset, NOW);
        assert!(!a.asserts_coverage_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS));
    }

    /// §7 defect 3: `LayerSet::SDK` is asserted unconditionally, independent of
    /// whether any agent adopted the SDK. Shipping a hook is not adopting it.
    #[test]
    fn assumed_present_basis_cannot_claim_coverage() {
        let basis = AttestationBasis::AssumedPresent;
        assert_eq!(basis.claim_ceiling(), ClaimTerm::Unmeasured);
        assert!(!basis.is_evidence());

        let a = at(basis, SelectedMode::Unset, NOW);
        assert!(!a.asserts_coverage_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS));
    }

    /// §7 defect 2: `probe_proxy` is satisfied by a binary existing on `$PATH`
    /// and does not establish that any process routes traffic through it.
    #[test]
    fn artifact_present_basis_cannot_claim_coverage() {
        let basis = AttestationBasis::ArtifactPresent {
            artifact: "aa-proxy".into(),
        };
        assert_eq!(basis.claim_ceiling(), ClaimTerm::Unmeasured);
        assert!(!basis.is_evidence());

        let a = at(basis, SelectedMode::Unset, NOW);
        assert!(!a.asserts_coverage_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS));
    }

    /// The safety property stated over the whole basis enum rather than one
    /// variant at a time: adjudication by the deciding component is the *only*
    /// route to a coverage term. A future variant added without a deliberate
    /// decision fails here.
    #[test]
    fn adjudication_is_the_only_basis_that_can_assert_coverage() {
        let non_evidence = vec![
            AttestationBasis::EnvironmentOverride {
                variable: "AA_LAYERS".into(),
            },
            AttestationBasis::AssumedPresent,
            AttestationBasis::ArtifactPresent {
                artifact: "aa-proxy".into(),
            },
            AttestationBasis::AbsentFromBuild {
                component: "aa-ebpf-loaderd".into(),
            },
            AttestationBasis::PlatformUnsupported {
                platform: "aarch64-apple-darwin".into(),
            },
            AttestationBasis::PrerequisiteUnmet {
                requirement: "kernel >= 5.8".into(),
            },
        ];
        for basis in &non_evidence {
            assert!(!basis.is_evidence(), "{basis:?} must not substantiate a coverage claim");
        }
        assert!(AttestationBasis::Adjudicated {
            outcome: AdjudicatedOutcome::Blocked
        }
        .is_evidence());
    }

    /// The adjudication → §6 term mapping, asserted as a table so a change to
    /// any row is a deliberate edit rather than a silent drift.
    #[test]
    fn adjudicated_outcomes_map_to_their_adr_0033_terms() {
        let table = [
            (AdjudicatedOutcome::Blocked, ClaimTerm::DeniedBeforeExecution),
            (AdjudicatedOutcome::Redacted, ClaimTerm::Redacted),
            (AdjudicatedOutcome::HeldForApproval, ClaimTerm::ApprovalRequired),
            (AdjudicatedOutcome::DecidedAdvisory, ClaimTerm::Evaluated),
            (AdjudicatedOutcome::Flagged, ClaimTerm::Detected),
            (AdjudicatedOutcome::Recorded, ClaimTerm::Observed),
            (AdjudicatedOutcome::Inconclusive, ClaimTerm::Unmeasured),
        ];
        for (outcome, expected) in table {
            assert_eq!(outcome.claim(), expected, "{outcome:?}");
        }
    }

    /// Only one term claims prevention. An asynchronous kill after the syscall
    /// has run, or an evaluation nothing was obliged to honour, must not read
    /// as blocking (ADR 0033 §6, §5.1).
    #[test]
    fn only_a_block_claims_prevention() {
        assert!(AdjudicatedOutcome::Blocked.claim().is_prevention());
        for outcome in [
            AdjudicatedOutcome::Redacted,
            AdjudicatedOutcome::HeldForApproval,
            AdjudicatedOutcome::DecidedAdvisory,
            AdjudicatedOutcome::Flagged,
            AdjudicatedOutcome::Recorded,
            AdjudicatedOutcome::Inconclusive,
        ] {
            assert!(
                !outcome.claim().is_prevention(),
                "{outcome:?} must not read as prevention"
            );
        }
    }

    /// Intent is not evidence. Whatever the basis, enabling a component must
    /// never turn a non-coverage term into a coverage term.
    #[test]
    fn selecting_a_component_never_raises_its_claim() {
        let bases = vec![
            AttestationBasis::EnvironmentOverride {
                variable: "AA_LAYERS".into(),
            },
            AttestationBasis::AssumedPresent,
            AttestationBasis::ArtifactPresent {
                artifact: "aa-proxy".into(),
            },
            AttestationBasis::AbsentFromBuild {
                component: "aa-ebpf-loaderd".into(),
            },
            AttestationBasis::PlatformUnsupported {
                platform: "x86_64-pc-windows-msvc".into(),
            },
            AttestationBasis::PrerequisiteUnmet {
                requirement: "BTF at /sys/kernel/btf/vmlinux".into(),
            },
            AttestationBasis::Adjudicated {
                outcome: AdjudicatedOutcome::Inconclusive,
            },
        ];
        for basis in bases {
            for mode in [SelectedMode::Enabled, SelectedMode::Disabled, SelectedMode::Unset] {
                let a = at(basis.clone(), mode, NOW);
                let term = a.verified_state_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS);
                assert!(
                    !term.asserts_coverage(),
                    "{basis:?} + {mode} produced the coverage term {term}"
                );
            }
        }
    }

    /// ADR 0033 §6 scopes *Unsupported* to "with no plan asserted". Asking for
    /// a control asserts a plan, so a selected component that cannot run is
    /// *Degraded* — the state that carries both the planned and the achieved
    /// level — not *Unsupported* and not *Unmeasured*.
    #[test]
    fn a_planned_but_unsubstantiated_component_is_degraded() {
        let unsupported = at(
            AttestationBasis::PlatformUnsupported {
                platform: "aarch64-apple-darwin".into(),
            },
            SelectedMode::Enabled,
            NOW,
        );
        assert_eq!(
            unsupported.verified_state_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS),
            ClaimTerm::Degraded
        );

        let unmet = at(
            AttestationBasis::PrerequisiteUnmet {
                requirement: "aa-ebpf-loaderd socket".into(),
            },
            SelectedMode::Enabled,
            NOW,
        );
        assert_eq!(
            unmet.verified_state_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS),
            ClaimTerm::Degraded
        );
    }

    /// The converse of the rule above: with no plan asserted, an absent
    /// mechanism keeps the ceiling's own distinction. A build that simply has
    /// no host mechanism reports *Unsupported*, not a degradation of something
    /// nobody asked for.
    #[test]
    fn an_unrequested_absent_component_stays_unsupported() {
        for mode in [SelectedMode::Disabled, SelectedMode::Unset] {
            let a = at(
                AttestationBasis::AbsentFromBuild {
                    component: "aa-ebpf-loaderd".into(),
                },
                mode,
                NOW,
            );
            assert_eq!(
                a.verified_state_at(NOW, DEFAULT_ATTESTATION_FRESHNESS_SECS),
                ClaimTerm::Unsupported,
                "{mode}"
            );
        }
    }
}
