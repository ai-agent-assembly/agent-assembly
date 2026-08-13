//! Resolving an [`ExecutionSpec`] against one backend's actual capabilities,
//! before anything is spawned.
//!
//! [`negotiate`] is the single decision point of this crate, and it is a free
//! function rather than a trait method on purpose: every backend must refuse
//! for the same reasons. If each backend implemented its own negotiation, the
//! rule "an observe-only capability cannot satisfy a prevention requirement"
//! would hold only as often as backend authors remembered it.
//!
//! Refusal is the `Err` arm. An [`EnforcementPlan`] therefore cannot represent a
//! refused launch, and a caller cannot spawn one by ignoring a status field.

use aa_core::attestation::ClaimTerm;

use crate::capability::{
    BackendCapabilities, CapabilityDomain, CapabilityReport, DecisionTiming, DescendantCoverage, Mediation, Synchrony,
};
use crate::spec::{ControlRequirement, DescendantRequirement, ExecutionSpec, RequirementIntent, RequirementPosture};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Where a backend came from, for the release-input questions of ADR 0035 §11.
///
/// Recorded rather than checked: this crate has no opinion on which licenses are
/// acceptable. It only guarantees that a plan and its evidence can always answer
/// "what was this, and where did it come from", so a review that does have an
/// opinion has something to read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Provenance {
    /// Where the backend implementation came from.
    pub source: String,
    /// SPDX license identifier of the backend implementation.
    pub license: String,
    /// Whether the implementation was modified from its upstream source.
    pub modified: bool,
}

/// Which backend answered, and what it is.
///
/// Present in [`EnforcementPlan`] and [`crate::evidence::EnforcementEvidence`];
/// absent from [`ExecutionSpec`] and [`ControlRequirement`]. That asymmetry is
/// the enforcement of ADR 0035 §3 — backend identity is an execution-plan fact,
/// so policy has no field in which to depend on it, and swapping backends cannot
/// silently change what a policy means.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BackendIdentity {
    /// Stable machine identifier for the backend.
    pub id: String,
    /// Version of the backend implementation.
    pub version: String,
    /// Source, license and modification status.
    pub provenance: Provenance,
}

/// A backend's mechanism-specific realization of one requirement.
///
/// **Opaque.** This crate stores and renders these strings and never parses
/// them. That is what keeps mechanism vocabulary out of the contract: a backend
/// can describe exactly what it did, in its own terms, without any of those
/// terms becoming a type here that policy could then be written against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Lowering {
    steps: Vec<String>,
}

impl Lowering {
    /// A lowering consisting of the given backend-authored steps.
    pub fn new<I, S>(steps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            steps: steps.into_iter().map(Into::into).collect(),
        }
    }

    /// A lowering that applies no mechanism.
    pub fn none() -> Self {
        Self::default()
    }

    /// The backend-authored steps, in order.
    pub fn steps(&self) -> &[String] {
        &self.steps
    }

    /// Whether the backend applied no mechanism.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// Why a requirement could not be met.
///
/// Deliberately fine-grained. "Could not enforce filesystem writes" is not an
/// actionable message; "the backend observes filesystem writes but the
/// requirement needs a decision before the effect" tells an operator whether to
/// change the policy, change the backend, or accept the risk.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RefusalReason {
    /// The backend cannot be selected on this host at all.
    BackendUnavailable {
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// The backend said nothing about this domain.
    ///
    /// Distinct from [`DomainUnsupported`](Self::DomainUnsupported): silence is
    /// not a claim of absence, and treating it as one would let an incomplete
    /// capability report read as a deliberate one.
    NoCapabilityReported {
        /// The domain the requirement named.
        domain: CapabilityDomain,
    },
    /// The backend reported no mechanism for this domain.
    DomainUnsupported {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// The backend's stated reason.
        reason: String,
    },
    /// The requirement needs a denial and the capability only watches.
    ///
    /// The refusal ADR 0035 §4 exists to mandate: *"A required prevention
    /// control that is only observable must not be silently promoted to
    /// prevention."*
    ObserveOnlyForPreventionRequirement {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// What the capability actually does.
        mediation: Mediation,
    },
    /// The backend enforces, but its decision does not precede the effect.
    ///
    /// An asynchronous kill after the call completed is
    /// [`ClaimTerm::Detected`], not prevention.
    DecisionTooLate {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// When the backend's decision actually lands.
        timing: DecisionTiming,
    },
    /// The backend decides before the effect, but the action does not wait for
    /// the decision, so it can win the race.
    DecisionNotSynchronous {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// The backend's actual synchrony.
        synchrony: Synchrony,
    },
    /// The capability produces no evidence, and the requirement asked for
    /// evidence.
    NoEvidenceProduced {
        /// The domain the requirement named.
        domain: CapabilityDomain,
    },
    /// The requirement needs process-tree coverage and the capability stops at
    /// the launched process.
    ///
    /// ADR 0035 §6: an agent that escapes by spawning a child has no boundary,
    /// so this is a refusal and not a footnote.
    DescendantCoverageInsufficient {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// What the capability actually covers.
        offered: DescendantCoverage,
    },
    /// A host precondition the capability depends on is not known to hold.
    PrerequisiteUnsatisfied {
        /// The domain the requirement named.
        domain: CapabilityDomain,
        /// The precondition.
        requirement: String,
    },
}

impl RefusalReason {
    /// The domain this refusal concerns, if it concerns one.
    ///
    /// `None` for [`BackendUnavailable`](Self::BackendUnavailable), which is
    /// about the host rather than any single control.
    pub fn domain(&self) -> Option<CapabilityDomain> {
        match self {
            Self::BackendUnavailable { .. } => None,
            Self::NoCapabilityReported { domain }
            | Self::DomainUnsupported { domain, .. }
            | Self::ObserveOnlyForPreventionRequirement { domain, .. }
            | Self::DecisionTooLate { domain, .. }
            | Self::DecisionNotSynchronous { domain, .. }
            | Self::NoEvidenceProduced { domain }
            | Self::DescendantCoverageInsufficient { domain, .. }
            | Self::PrerequisiteUnsatisfied { domain, .. } => Some(*domain),
        }
    }
}

/// What a degraded requirement actually got, as opposed to what it asked for.
///
/// The `achieved` half of the planned/achieved pair, mirroring
/// `aa_core::integration::state::ProtectionState::Degraded`. Kept as its own
/// type rather than reusing [`RequirementIntent`] because the achieved state has
/// a possibility the intent side does not: *nothing at all*.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum AchievedControl {
    /// The domain is watched but not prevented.
    Observed {
        /// When the observation happens relative to the effect.
        timing: DecisionTiming,
        /// How far down the process tree the observation reaches.
        descendants: DescendantCoverage,
    },
    /// Nothing covers the domain.
    None,
}

/// What became of one requirement.
///
/// [`is_prevention`](Self::is_prevention) is true for exactly one variant.
/// [`Degraded`](Self::Degraded) is emphatically not one of them: a degraded
/// requirement carries what it *planned* to do, and reading that field as an
/// achievement is the mistake this whole type exists to make impossible.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum RequirementOutcome {
    /// The backend will deny this before the effect.
    Enforced {
        /// When the decision lands. Always [`DecisionTiming::Pre`].
        timing: DecisionTiming,
        /// How far down the process tree the control reaches.
        descendants: DescendantCoverage,
    },
    /// The backend will produce evidence about this and will not deny it.
    Observed {
        /// When the observation happens relative to the effect.
        timing: DecisionTiming,
        /// How far down the process tree the observation reaches.
        descendants: DescendantCoverage,
    },
    /// The requirement could not be met, and its posture permitted proceeding
    /// in a weaker state that must be recorded as weaker.
    Degraded {
        /// What policy asked for.
        planned: RequirementIntent,
        /// What the backend will actually do.
        achieved: AchievedControl,
        /// Why the planned state was not reached.
        reason: RefusalReason,
    },
    /// An optional requirement could not be met. The launch proceeds and the
    /// domain is uncovered.
    Unmet {
        /// Why.
        reason: RefusalReason,
    },
}

impl RequirementOutcome {
    /// Whether this outcome means the action will be stopped before it takes
    /// effect.
    pub fn is_prevention(&self) -> bool {
        matches!(self, Self::Enforced { .. })
    }

    /// Whether this outcome is weaker than what policy asked for.
    pub fn is_shortfall(&self) -> bool {
        matches!(self, Self::Degraded { .. } | Self::Unmet { .. })
    }

    /// The strongest [`ClaimTerm`] this outcome could support once exercised.
    ///
    /// A ceiling on what a decision from this control may be *called*, not an
    /// assertion that any decision happened. [`Unmet`](Self::Unmet) maps to
    /// [`ClaimTerm::Unmeasured`] rather than [`ClaimTerm::Unsupported`] because
    /// the run-level fact is that nothing inspected the action; whether the
    /// product supports the control at all is a different statement, made
    /// somewhere else.
    pub fn claim_ceiling(&self) -> ClaimTerm {
        match self {
            Self::Enforced { .. } => ClaimTerm::DeniedBeforeExecution,
            Self::Observed { .. } => ClaimTerm::Observed,
            Self::Degraded { .. } => ClaimTerm::Degraded,
            Self::Unmet { .. } => ClaimTerm::Unmeasured,
        }
    }
}

/// One requirement, what became of it, and how the backend realized it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlannedRequirement {
    /// What policy asked for.
    pub requirement: ControlRequirement,
    /// What the backend will do about it.
    pub outcome: RequirementOutcome,
    /// The backend's mechanism-specific realization, opaque to this crate.
    pub lowering: Lowering,
}

/// The posture a launch will start in.
///
/// [`Refused`](Self::Refused) never appears on an [`EnforcementPlan`] — see that
/// type. It exists because evidence must be able to describe a refused launch,
/// which is a thing that happened and which E6 needs to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum LaunchPosture {
    /// Every requirement was met as asked.
    Ready,
    /// At least one requirement fell short, with permission to do so.
    Degraded,
    /// The launch was refused before spawn.
    Refused,
}

/// A launch that will not happen, and the complete list of reasons.
///
/// All unmet required requirements are reported, not just the first: an operator
/// fixing one at a time and re-running would otherwise discover them serially.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PlanRefusal {
    backend: BackendIdentity,
    backend_unavailable: Option<String>,
    unmet: Vec<(ControlRequirement, RefusalReason)>,
}

impl PlanRefusal {
    /// Which backend refused.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// Set when the backend itself cannot be selected on this host, in which
    /// case [`unmet`](Self::unmet) is empty because no requirement was reached.
    pub fn backend_unavailable(&self) -> Option<&str> {
        self.backend_unavailable.as_deref()
    }

    /// Every required requirement that could not be met, with its reason.
    pub fn unmet(&self) -> &[(ControlRequirement, RefusalReason)] {
        &self.unmet
    }

    /// Every reason, including a backend-level unavailability.
    pub fn reasons(&self) -> Vec<RefusalReason> {
        let mut out = Vec::new();
        if let Some(reason) = &self.backend_unavailable {
            out.push(RefusalReason::BackendUnavailable { reason: reason.clone() });
        }
        out.extend(self.unmet.iter().map(|(_, reason)| reason.clone()));
        out
    }
}

impl core::fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "backend `{}` refused the launch ({} unmet requirement(s))",
            self.backend.id,
            self.unmet.len()
        )
    }
}

impl std::error::Error for PlanRefusal {}

/// The resolved lowering of an [`ExecutionSpec`] onto one backend, decided
/// before the untrusted process starts.
///
/// Constructible only by [`negotiate`], and only when no required requirement
/// was unmet. Consequently [`posture`](Self::posture) is [`LaunchPosture::Ready`]
/// or [`LaunchPosture::Degraded`] and never [`LaunchPosture::Refused`] — a
/// refused launch is the `Err` arm, not a plan with a flag on it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnforcementPlan {
    backend: BackendIdentity,
    spec: ExecutionSpec,
    planned: Vec<PlannedRequirement>,
    posture: LaunchPosture,
}

impl EnforcementPlan {
    /// The backend that will execute this plan.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// The spec this plan resolves.
    pub fn spec(&self) -> &ExecutionSpec {
        &self.spec
    }

    /// Every requirement and what became of it, in the spec's declaration
    /// order.
    pub fn planned(&self) -> &[PlannedRequirement] {
        &self.planned
    }

    /// The posture the launch will start in. Never
    /// [`LaunchPosture::Refused`].
    pub fn posture(&self) -> LaunchPosture {
        self.posture
    }

    /// Requirements that fell short of what policy asked for.
    ///
    /// The list `--dry-run` must show, and the reason a `Degraded` posture can
    /// never be summarised as "protected".
    pub fn shortfalls(&self) -> impl Iterator<Item = &PlannedRequirement> {
        self.planned.iter().filter(|p| p.outcome.is_shortfall())
    }

    /// Domains this plan will deny before the effect.
    pub fn prevented_domains(&self) -> Vec<CapabilityDomain> {
        self.planned
            .iter()
            .filter(|p| p.outcome.is_prevention())
            .map(|p| p.requirement.domain())
            .collect()
    }
}

/// Check one requirement against one backend's capability report.
fn evaluate(
    requirement: &ControlRequirement,
    report: Option<&CapabilityReport>,
) -> Result<RequirementOutcome, RefusalReason> {
    let domain = requirement.domain();

    let Some(report) = report else {
        return Err(RefusalReason::NoCapabilityReported { domain });
    };

    if let crate::capability::SupportLevel::Unsupported { reason } = report.support() {
        return Err(RefusalReason::DomainUnsupported {
            domain,
            reason: reason.clone(),
        });
    }

    match requirement.intent() {
        RequirementIntent::PreventBeforeEffect => {
            // Ordered from the most fundamental mismatch to the most specific,
            // so the reported reason is the one an operator would act on first.
            if report.mediation() != Mediation::Enforce {
                return Err(RefusalReason::ObserveOnlyForPreventionRequirement {
                    domain,
                    mediation: report.mediation(),
                });
            }
            if report.timing() != DecisionTiming::Pre {
                return Err(RefusalReason::DecisionTooLate {
                    domain,
                    timing: report.timing(),
                });
            }
            if report.synchrony() != Synchrony::Sync {
                return Err(RefusalReason::DecisionNotSynchronous {
                    domain,
                    synchrony: report.synchrony(),
                });
            }
            if let Some(prerequisite) = report.unsatisfied_prerequisite() {
                return Err(RefusalReason::PrerequisiteUnsatisfied {
                    domain,
                    requirement: prerequisite.requirement.clone(),
                });
            }
            check_descendants(requirement, report)?;
            Ok(RequirementOutcome::Enforced {
                timing: report.timing(),
                descendants: report.descendants(),
            })
        }
        RequirementIntent::Observe => {
            if !report.can_observe() {
                return Err(RefusalReason::NoEvidenceProduced { domain });
            }
            check_descendants(requirement, report)?;
            Ok(RequirementOutcome::Observed {
                timing: report.timing(),
                descendants: report.descendants(),
            })
        }
    }
}

/// A process-tree requirement is met only by process-tree coverage.
///
/// [`DescendantCoverage::Unmeasured`] fails alongside
/// [`DescendantCoverage::TargetProcessOnly`]: an unmeasured boundary is not a
/// boundary anyone can rely on, and accepting it would let a backend meet the
/// requirement by declining to look.
fn check_descendants(requirement: &ControlRequirement, report: &CapabilityReport) -> Result<(), RefusalReason> {
    if requirement.descendants() == DescendantRequirement::ProcessTree
        && report.descendants() != DescendantCoverage::ProcessTree
    {
        return Err(RefusalReason::DescendantCoverageInsufficient {
            domain: requirement.domain(),
            offered: report.descendants(),
        });
    }
    Ok(())
}

/// What a degraded requirement actually gets from a capability that could not
/// meet it.
fn achieved(report: Option<&CapabilityReport>) -> AchievedControl {
    match report {
        Some(report) if report.can_observe() => AchievedControl::Observed {
            timing: report.timing(),
            descendants: report.descendants(),
        },
        _ => AchievedControl::None,
    }
}

/// Resolve a spec against a backend's capabilities, before spawn.
///
/// This is where ADR 0035 §4 is implemented. Every requirement lands in exactly
/// one of the four [`RequirementOutcome`] variants, and the choice between
/// refusing and degrading is made by the requirement's own
/// [`RequirementPosture`] — never by a global switch, and never by the backend.
///
/// `lower` is the backend's chance to describe how it will realize each
/// requirement. It is called once per requirement, including for shortfalls, so
/// that evidence can show what a degraded requirement did get.
///
/// # Errors
///
/// [`PlanRefusal`] when the backend is unavailable, or when any requirement with
/// [`RequirementPosture::Required`] cannot be met. The refusal lists every unmet
/// required requirement, not only the first.
// `clippy::result_large_err` fires because `PlanRefusal` is 152 bytes, above the
// lint's 128-byte threshold. The lint exists to catch a small `Ok` paying for a
// large `Err` on every call — and that is measurably not the case here:
// `EnforcementPlan` is 376 bytes, so `Result<EnforcementPlan, PlanRefusal>` is
// 376 bytes whether or not the error is boxed. Boxing would buy nothing and
// would put a `Box` in the public contract that every backend must then repeat.
//
// `refusal_is_free_to_carry_by_value` pins that justification: if
// `EnforcementPlan` ever shrinks below `PlanRefusal`, the premise stops holding
// and that test fails rather than this comment quietly going stale.
#[allow(clippy::result_large_err)]
pub fn negotiate(
    spec: &ExecutionSpec,
    backend: &BackendIdentity,
    capabilities: &BackendCapabilities,
    lower: &dyn Fn(&ControlRequirement, &RequirementOutcome) -> Lowering,
) -> Result<EnforcementPlan, PlanRefusal> {
    if let crate::capability::BackendAvailability::Unavailable { reason } = capabilities.availability() {
        return Err(PlanRefusal {
            backend: backend.clone(),
            backend_unavailable: Some(reason.clone()),
            unmet: Vec::new(),
        });
    }

    let mut planned = Vec::with_capacity(spec.requirements().len());
    let mut unmet = Vec::new();

    for requirement in spec.requirements() {
        let report = capabilities.report_for(requirement.domain());
        let outcome = match evaluate(requirement, report) {
            Ok(outcome) => outcome,
            Err(reason) => match requirement.posture() {
                RequirementPosture::Required => {
                    unmet.push((requirement.clone(), reason));
                    continue;
                }
                RequirementPosture::DegradeIfUnavailable => RequirementOutcome::Degraded {
                    planned: requirement.intent(),
                    achieved: achieved(report),
                    reason,
                },
                RequirementPosture::Optional => RequirementOutcome::Unmet { reason },
            },
        };
        let lowering = lower(requirement, &outcome);
        planned.push(PlannedRequirement {
            requirement: requirement.clone(),
            outcome,
            lowering,
        });
    }

    if !unmet.is_empty() {
        return Err(PlanRefusal {
            backend: backend.clone(),
            backend_unavailable: None,
            unmet,
        });
    }

    let posture = if planned.iter().any(|p| p.outcome.is_shortfall()) {
        LaunchPosture::Degraded
    } else {
        LaunchPosture::Ready
    };

    Ok(EnforcementPlan {
        backend: backend.clone(),
        spec: spec.clone(),
        planned,
        posture,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The justification for `#[allow(clippy::result_large_err)]` on
    /// [`negotiate`] and [`crate::backend::IsolationBackend::plan`].
    ///
    /// That lint targets a small `Ok` variant paying for a large `Err` on every
    /// call. Here the `Ok` variant is the larger of the two, so the `Result` is
    /// exactly as big either way and boxing the error would buy nothing while
    /// putting a `Box` in the public contract.
    ///
    /// If `EnforcementPlan` ever shrinks below `PlanRefusal`, that reasoning
    /// stops holding — and this fails, instead of the comment going stale
    /// unnoticed.
    #[test]
    fn refusal_is_free_to_carry_by_value() {
        use core::mem::size_of;
        assert!(
            size_of::<PlanRefusal>() <= size_of::<EnforcementPlan>(),
            "PlanRefusal ({}) outgrew EnforcementPlan ({}); revisit the \
             result_large_err allow on `negotiate` and `IsolationBackend::plan`",
            size_of::<PlanRefusal>(),
            size_of::<EnforcementPlan>(),
        );
        assert_eq!(
            size_of::<Result<EnforcementPlan, PlanRefusal>>(),
            size_of::<EnforcementPlan>(),
            "boxing the error variant would have to save bytes to be worth it",
        );
    }
}
