//! One canonical projection of a run's isolation posture: what was *requested*,
//! what a backend could actually *provide*, and what may therefore be *said*.
//!
//! Authority: ADR 0035 §4/§9/§10 and ADR 0033 §6. Implementation is AAASM-5710.
//!
//! # Why a projection rather than a renderer
//!
//! `--dry-run` and a live launch have to describe the same boundary. Before this
//! module they would each have had to walk an [`EnforcementPlan`], a
//! [`PolicyLowering`] and an [`EnforcementEvidence`] and decide for themselves
//! what to call each result — which is exactly the kind of duplicated judgement
//! that drifts, and the direction it drifts in is always upward. An
//! [`IsolationReport`] is built once, from those sources, and both surfaces
//! render *it*.
//!
//! It lives in `aa-isolation` rather than in `aa-cli` so audit and the status
//! surface consume the same object the CLI prints, and so the rules below are
//! held by one type instead of by three call sites.
//!
//! # The five states this module refuses to collapse
//!
//! | State | Means |
//! | --- | --- |
//! | [`ControlState::Prevention`] | A control will refuse the action before it takes effect |
//! | [`ControlState::ObserveOnly`] | A control watches and cannot refuse |
//! | [`ControlState::Degraded`] | Something weaker than policy asked for, with permission |
//! | [`ControlState::Unsupported`] | Asked for, and could not be provided |
//! | [`ControlState::Unmeasured`] | Nothing looked |
//!
//! And, on the *requested* side, three more that are just as easily confused —
//! [`RequestedControl::NotStated`] (the operator could have written a
//! restriction and did not), [`RequestedControl::PolicyCannotExpress`] (there is
//! no way to write one), and [`RequestedControl::NotDerived`] (nothing
//! established which of the two it is). A domain the policy schema cannot
//! express is **not** a domain needing no control, and rendering it beside a
//! blank requirement list would read as one.
//!
//! # What this type will not do
//!
//! * **Configuration is not enforcement.** No constructor accepts
//!   [`BackendAvailability`](crate::capability::BackendAvailability), and no
//!   field holds it. A backend being installable on this host is a fact about
//!   the host; it is not a fact about this run, and there is nowhere here to put
//!   it where a reader could round it up. [`EvidenceKind::Configured`] and
//!   [`EvidenceKind::Installed`] map to [`EvidenceBasis::SetupOnly`], which is
//!   rendered as its own token and never as a decision.
//! * **A pre-launch plan never claims coverage.** Every domain in a report built
//!   by [`IsolationReport::from_plan`] carries [`ClaimTerm::Planned`] at
//!   strongest, matching [`EnforcementEvidence::from_plan`]. A plan is an
//!   intention; nothing has happened yet.
//! * **Runtime evidence only lowers, never silently raises.**
//!   [`IsolationReport::with_evidence`] takes the claim from
//!   [`EnforcementEvidence::claim_for`], which ignores setup-time records, and
//!   then additionally refuses a prevention term unless
//!   [`EnforcementEvidence::supports_prevention_claim`] holds — because a
//!   runtime record may *carry* a prevention term without an
//!   [`EvidenceKind::Decision`] behind it, and that gap is the evidenced
//!   transition this bar is about.
//! * **An empty requirement set is not a clean boundary.** A run that asked the
//!   execution boundary for nothing renders as
//!   [`ReportedPosture::NoBoundary`], never as [`ReportedPosture::Ready`].
//! * **Unremoved ambient authority is not least-authority.** A non-empty
//!   [`CredentialPosture::ambient_unremoved`] makes
//!   [`IsolationReport::is_least_authority`] false and drops a `Ready` posture
//!   to [`ReportedPosture::Degraded`] (ADR 0035 §9).
//!
//! # Names, never values
//!
//! Everything here is rendered into `--dry-run` stdout and into audit. No field
//! holds credential material and none should be added: [`CredentialPosture`] is
//! names only by its own contract, and this module carries the names through
//! without ever reading an environment value.
//!
//! # No mechanism vocabulary
//!
//! Nothing here names an operating-system or vendor isolation facility, and
//! nothing may be added that does (ADR 0035 §3). A backend's own description of
//! what it did travels as [`crate::plan::Lowering`], which this crate stores and
//! never parses.

use aa_core::attestation::ClaimTerm;

use crate::capability::{CapabilityDomain, DecisionTiming, DescendantCoverage};
use crate::descriptor::DescriptorInventory;
use crate::evidence::{EnforcementEvidence, EvidenceKind};
use crate::lowering::{DomainCoverage, PolicyLowering};
use crate::plan::{
    AchievedControl, BackendIdentity, EnforcementPlan, LaunchPosture, PlanRefusal, RefusalReason, RequirementOutcome,
};
use crate::spec::{
    ControlRequirement, CredentialPosture, DescendantRequirement, ExecutionSpec, IdentityRef, RequirementIntent,
    RequirementPosture, RequirementScope,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The identifier every machine-readable record is prefixed with.
///
/// Bumped when a downstream consumer would have to change to keep reading the
/// output of [`IsolationReport::machine_lines`]. Adding a new `domain.*` key is
/// not such a change; renaming or removing one is.
pub const REPORT_SCHEMA: &str = "aasm.isolation.report/1";

/// Whether the report describes a launch that has happened.
///
/// The distinction is load-bearing rather than cosmetic: at
/// [`PreLaunch`](Self::PreLaunch) no claim in the report may assert coverage,
/// because nothing has run. Moving to [`PostRun`](Self::PostRun) is done only by
/// [`IsolationReport::with_evidence`], which is the evidenced transition ADR
/// 0035 §10 requires before a runtime fact may strengthen anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ReportStage {
    /// The launch has not started. Every state is what the plan would do.
    PreLaunch,
    /// The launch happened and recorded evidence has been joined to the plan.
    PostRun,
}

impl ReportStage {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreLaunch => "pre_launch",
            Self::PostRun => "post_run",
        }
    }
}

/// The correlation ids that let runtime evidence be joined back to this run.
///
/// Carried rather than derived because neither id exists inside this crate: both
/// are minted by whoever is launching. They are here so an audit record and a
/// `--dry-run` receipt name the same session (ADR 0035 §10's joinability
/// requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SessionRef {
    /// Identifies this single launch invocation.
    pub session_id: String,
    /// Correlates this launch's records with each other.
    pub trace_id: String,
}

impl SessionRef {
    /// A reference to one session.
    pub fn new(session_id: impl Into<String>, trace_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            trace_id: trace_id.into(),
        }
    }
}

/// What was launched.
///
/// The program and the *number* of arguments, not the argument vector. The argv
/// is already rendered by whoever previews or audits the launch, and repeating
/// it here would put an operator-supplied string — which may carry a secret
/// passed on a command line — into a second surface for no gain. The program
/// name is what identifies the target; the count is what tells a reader the
/// report is describing the launch they are looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TargetRef {
    /// The program the launch runs.
    pub program: String,
    /// How many arguments follow it.
    pub arg_count: usize,
}

impl TargetRef {
    /// A target naming `program` with `arg_count` arguments after it.
    pub fn new(program: impl Into<String>, arg_count: usize) -> Self {
        Self {
            program: program.into(),
            arg_count,
        }
    }

    /// The target `spec` describes.
    pub fn of(spec: &ExecutionSpec) -> Self {
        Self::new(spec.program(), spec.args().len())
    }
}

/// What policy asked of one [`CapabilityDomain`] — or why it asked nothing.
///
/// The three "nothing" variants are the point. They are the same blank in a
/// requirement list and three completely different security statements, and a
/// reader who cannot tell them apart will read every one of them as "no control
/// is needed here".
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RequestedControl {
    /// Policy stated a requirement for this domain.
    Stated {
        /// What the control is asked to do.
        intent: RequirementIntent,
        /// What happens when it cannot.
        posture: RequirementPosture,
        /// How far down the process tree it must reach.
        descendants: DescendantRequirement,
        /// What within the domain it applies to.
        scope: RequirementScope,
    },
    /// The schema has a node for this domain and this document left it unset.
    ///
    /// The remedy is to edit the policy — there is one to edit. Distinct from
    /// [`PolicyCannotExpress`](Self::PolicyCannotExpress) for exactly that
    /// reason.
    NotStated {
        /// The policy node that would have carried it.
        node: String,
        /// What the schema documents an absent node to mean.
        schema_default: String,
    },
    /// The schema has no node that can express this domain at all.
    ///
    /// **Never read as "no restriction is required."** It is the absence of a
    /// way to ask, not the presence of an answer.
    PolicyCannotExpress {
        /// Why, naming the nearest policy node and why it is not this one.
        detail: String,
    },
    /// No policy lowering was attached, so nothing established which of the
    /// three above applies.
    ///
    /// The honest answer for a report built without a
    /// [`PolicyLowering`]: not "nothing was asked", but "nothing recorded
    /// whether anything was asked".
    NotDerived,
}

impl RequestedControl {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stated { .. } => "stated",
            Self::NotStated { .. } => "not_stated",
            Self::PolicyCannotExpress { .. } => "policy_cannot_express",
            Self::NotDerived => "not_derived",
        }
    }

    /// Whether policy stated a requirement for this domain.
    pub fn is_stated(&self) -> bool {
        matches!(self, Self::Stated { .. })
    }

    /// Whether the policy schema cannot express this domain at all.
    pub fn is_unrepresentable(&self) -> bool {
        matches!(self, Self::PolicyCannotExpress { .. })
    }

    /// The requirement `requirement` states, projected.
    pub fn of(requirement: &ControlRequirement) -> Self {
        Self::Stated {
            intent: requirement.intent(),
            posture: requirement.posture(),
            descendants: requirement.descendants(),
            scope: requirement.scope().clone(),
        }
    }
}

/// Why nothing is known about a domain.
///
/// Three different silences. A domain nobody asked about, a domain no backend
/// was consulted about, and a domain something looked at and could not resolve
/// are not the same fact, and the first two are routinely mistaken for safety.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum UnmeasuredReason {
    /// No backend was selected, so nothing was negotiated, prepared or applied.
    NoBackendSelected,
    /// No requirement named this domain, so nothing was asked to cover it.
    NoControlRequested,
    /// Something looked and could not establish an answer.
    Inconclusive {
        /// Why, in words an operator can act on.
        detail: String,
    },
}

impl UnmeasuredReason {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoBackendSelected => "no_backend_selected",
            Self::NoControlRequested => "no_control_requested",
            Self::Inconclusive { .. } => "inconclusive",
        }
    }
}

/// What the execution boundary will do — or did — about one domain.
///
/// [`Degraded`](Self::Degraded) is a variant of its own rather than an
/// [`ObserveOnly`](Self::ObserveOnly) with a note, so that a reader cannot miss
/// the difference by skimming a wording change: the two render under different
/// tokens, in different sections, and a degraded entry always carries the
/// *planned* state it did not reach.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ControlState {
    /// A control will refuse the action before it takes effect.
    ///
    /// Names what the control *will do*, not what it has done. Whether anything
    /// was actually stopped is [`DomainProjection::claim`], which needs
    /// evidence.
    Prevention {
        /// When the decision lands.
        timing: DecisionTiming,
        /// How far down the process tree the control reaches.
        descendants: DescendantCoverage,
    },
    /// A control watches this domain and cannot refuse it.
    ObserveOnly {
        /// When the observation happens relative to the effect.
        timing: DecisionTiming,
        /// How far down the process tree the observation reaches.
        descendants: DescendantCoverage,
    },
    /// Something weaker than policy asked for, with permission to proceed.
    Degraded {
        /// What policy asked for.
        planned: RequirementIntent,
        /// What is actually there instead.
        achieved: AchievedControl,
        /// Why the planned state was not reached.
        reason: RefusalReason,
    },
    /// Asked for, and could not be provided.
    Unsupported {
        /// Why.
        reason: RefusalReason,
    },
    /// Nothing looked.
    Unmeasured {
        /// Which silence this is.
        reason: UnmeasuredReason,
    },
}

impl ControlState {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prevention { .. } => "prevention",
            Self::ObserveOnly { .. } => "observe_only",
            Self::Degraded { .. } => "degraded",
            Self::Unsupported { .. } => "unsupported",
            Self::Unmeasured { .. } => "unmeasured",
        }
    }

    /// Whether the control is positioned to refuse the action.
    ///
    /// Not a claim that it refused one. Only [`DomainProjection::claim`] can say
    /// that, and only with an [`EvidenceKind::Decision`] behind it.
    pub fn is_prevention(&self) -> bool {
        matches!(self, Self::Prevention { .. })
    }

    /// Whether this is weaker than what policy asked for.
    pub fn is_shortfall(&self) -> bool {
        matches!(self, Self::Degraded { .. } | Self::Unsupported { .. })
    }

    /// How strong this state is, weakest first.
    ///
    /// Used only to fold duplicate requirements for one domain down to a single
    /// projection, and it takes the **minimum** so that two requirements naming
    /// the same domain can never round the domain up. [`Unsupported`] ranks
    /// below [`Unmeasured`] deliberately: "we asked and it cannot be provided"
    /// is a stronger warning than "nothing looked", and folding must surface the
    /// stronger warning.
    ///
    /// [`Unsupported`]: Self::Unsupported
    /// [`Unmeasured`]: Self::Unmeasured
    fn rank(&self) -> u8 {
        match self {
            Self::Unsupported { .. } => 0,
            Self::Degraded { .. } => 1,
            Self::Unmeasured { .. } => 2,
            Self::ObserveOnly { .. } => 3,
            Self::Prevention { .. } => 4,
        }
    }
}

/// What kind of evidence stands behind a domain's claim.
///
/// The whole reason this is a separate axis from [`ClaimTerm`] is ADR 0033's
/// forbidden design 6: a settings file's existence is not coverage, and
/// `configured` is not a claim term. [`SetupOnly`](Self::SetupOnly) is the
/// grade a configured-and-installed control gets, and it is rendered as its own
/// token so no reader has to infer from a claim term whether anything decided
/// anything.
///
/// Unlike [`ClaimTerm`], this **is** a ladder and is ordered as one: the
/// variants are declared weakest-first and [`Ord`] is derived, because
/// [`EvidenceBasis::of`] has to fold several records for one domain down to the
/// strongest grade among them. Ordering evidence *grades* is safe in a way that
/// ordering claim *terms* is not — a grade says how firmly something is known,
/// while a term says what happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EvidenceBasis {
    /// No record concerns this domain.
    None,
    /// Only setup-time records: a control was requested, or applied before the
    /// process started. Neither says anything decided anything.
    SetupOnly,
    /// The control was reached by real activity, or corroborated from outside,
    /// but produced no decision record.
    RuntimeWithoutDecision,
    /// The control produced a decision about a specific action.
    Decision,
}

impl EvidenceBasis {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SetupOnly => "setup_only",
            Self::RuntimeWithoutDecision => "runtime_without_decision",
            Self::Decision => "decision",
        }
    }

    /// The basis `evidence` records for `domain`.
    ///
    /// [`EvidenceKind::IndependentVerification`] lands in
    /// [`RuntimeWithoutDecision`](Self::RuntimeWithoutDecision) rather than
    /// [`Decision`](Self::Decision): corroboration of a decision presupposes the
    /// decision, so a probe that failed does not by itself establish that this
    /// control is why.
    pub fn of(evidence: &EnforcementEvidence, domain: CapabilityDomain) -> Self {
        let mut basis = Self::None;
        for record in evidence.records_for(domain) {
            let candidate = match record.kind {
                EvidenceKind::Configured | EvidenceKind::Installed => Self::SetupOnly,
                EvidenceKind::Exercised | EvidenceKind::IndependentVerification => Self::RuntimeWithoutDecision,
                EvidenceKind::Decision => Self::Decision,
            };
            if candidate > basis {
                basis = candidate;
            }
        }
        basis
    }
}

/// Everything the report knows about one [`CapabilityDomain`].
///
/// Four axes, because collapsing any pair of them is a way to overclaim:
/// *requested* is what policy asked, *state* is what the boundary will do,
/// *claim* is what may be said out loud, and *evidence* is what stands behind
/// the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DomainProjection {
    /// The domain.
    pub domain: CapabilityDomain,
    /// What policy asked, or why it asked nothing.
    pub requested: RequestedControl,
    /// What the execution boundary will do about it.
    pub state: ControlState,
    /// What may be said about it, in ADR 0033 §6 vocabulary.
    ///
    /// Never a coverage-asserting term at [`ReportStage::PreLaunch`] — a plan is
    /// an intention, and [`ClaimTerm::Planned`] is the only honest word for one.
    pub claim: ClaimTerm,
    /// What stands behind [`claim`](Self::claim).
    pub evidence: EvidenceBasis,
    /// What the policy schema could not express about this domain *even where a
    /// requirement was lowered* — the residual gap between what ADR 0035 asks a
    /// control to be scoped by and what an operator can currently write.
    pub residual_policy_gaps: Vec<String>,
}

/// The posture a report may state about a run.
///
/// [`NoBoundary`](Self::NoBoundary) exists because the alternative was to report
/// a run that asked for nothing, and got nothing, as
/// [`Ready`](Self::Ready) — which is true of the negotiation and false of the
/// run, and is the precise failure Epic AAASM-5702 exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ReportedPosture {
    /// A backend was selected, every requirement was met as asked, and no
    /// authority reaches the child that policy did not intend.
    Ready,
    /// A backend was selected and something fell short — a requirement, or the
    /// authority the child inherits.
    Degraded,
    /// The launch was refused before spawn.
    Refused,
    /// No execution-isolation boundary was established at all.
    ///
    /// Not a weaker `Ready`. Nothing was negotiated, prepared or evidenced, so
    /// there is no boundary to describe and nothing about the run's isolation
    /// may be claimed.
    NoBoundary,
}

impl ReportedPosture {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Refused => "refused",
            Self::NoBoundary => "no_boundary",
        }
    }

    /// The all-caps label a human render uses, so the three non-ready postures
    /// cannot be skimmed past.
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Degraded => "DEGRADED",
            Self::Refused => "REFUSED",
            Self::NoBoundary => "NO BOUNDARY ESTABLISHED",
        }
    }
}

/// How far negotiation with a backend got.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
enum Negotiated {
    /// No backend was consulted.
    Absent { reason: String },
    /// A backend answered and the launch may proceed in this posture.
    Planned(LaunchPosture),
    /// A backend answered and refused.
    Refused,
}

/// The canonical projection of one run's isolation posture.
///
/// Built once — by [`from_plan`](Self::from_plan),
/// [`from_refusal`](Self::from_refusal) or [`no_boundary`](Self::no_boundary) —
/// and rendered by every surface that describes the run, so a preview, a live
/// launch and an audit record cannot disagree about what was protected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IsolationReport {
    stage: ReportStage,
    session: SessionRef,
    identity: IdentityRef,
    target: TargetRef,
    backend: Option<BackendIdentity>,
    requested: Vec<ControlRequirement>,
    domains: Vec<DomainProjection>,
    credentials: CredentialPosture,
    descriptors: Option<DescriptorInventory>,
    unmapped_policy: Vec<String>,
    refusals: Vec<(CapabilityDomain, RefusalReason)>,
    backend_unavailable: Option<String>,
    negotiated: Negotiated,
}

impl IsolationReport {
    /// A report for a run with no execution-isolation boundary.
    ///
    /// The honest state when no backend has been selected: every domain is
    /// [`UnmeasuredReason::NoBackendSelected`], the posture is
    /// [`ReportedPosture::NoBoundary`], and no domain carries a coverage claim.
    /// `reason` says why in words an operator can act on.
    ///
    /// This is deliberately *not* expressible as a `Ready` plan with an empty
    /// requirement list. [`crate::plan::negotiate`] resolves an empty spec to
    /// [`LaunchPosture::Ready`] against any backend at all, including one that
    /// enforces nothing, and "we asked for nothing and got it" must not reach a
    /// reader as readiness.
    pub fn no_boundary(
        session: SessionRef,
        identity: IdentityRef,
        target: TargetRef,
        credentials: CredentialPosture,
        reason: impl Into<String>,
    ) -> Self {
        let domains = CapabilityDomain::ALL
            .iter()
            .map(|&domain| DomainProjection {
                domain,
                requested: RequestedControl::NotDerived,
                state: ControlState::Unmeasured {
                    reason: UnmeasuredReason::NoBackendSelected,
                },
                claim: ClaimTerm::Unmeasured,
                evidence: EvidenceBasis::None,
                residual_policy_gaps: Vec::new(),
            })
            .collect();

        Self {
            stage: ReportStage::PreLaunch,
            session,
            identity,
            target,
            backend: None,
            requested: Vec::new(),
            domains,
            credentials,
            descriptors: None,
            unmapped_policy: Vec::new(),
            refusals: Vec::new(),
            backend_unavailable: None,
            negotiated: Negotiated::Absent { reason: reason.into() },
        }
    }

    /// A report for a negotiated plan, before anything runs.
    ///
    /// Every claim is [`ClaimTerm::Planned`] except where the outcome is itself
    /// a shortfall, which keeps its own ceiling. Nothing here asserts coverage,
    /// because nothing has happened yet — [`with_evidence`](Self::with_evidence)
    /// is the only path to a claim that does.
    ///
    /// A plan whose requirement list is empty is reported as
    /// [`ReportedPosture::NoBoundary`] rather than as its own
    /// [`LaunchPosture::Ready`]: a negotiation that was asked nothing succeeded
    /// at nothing.
    pub fn from_plan(session: SessionRef, plan: &EnforcementPlan) -> Self {
        let spec = plan.spec();
        let domains = CapabilityDomain::ALL
            .iter()
            .map(|&domain| {
                let mut projection: Option<DomainProjection> = None;
                for planned in plan.planned().iter().filter(|p| p.requirement.domain() == domain) {
                    let state = state_of(&planned.outcome);
                    let claim = if planned.outcome.is_shortfall() {
                        planned.outcome.claim_ceiling()
                    } else {
                        // A plan is an intention. `Planned` is the only honest
                        // term for one, whatever the control will be able to do.
                        ClaimTerm::Planned
                    };
                    let candidate = DomainProjection {
                        domain,
                        requested: RequestedControl::of(&planned.requirement),
                        state,
                        claim,
                        evidence: EvidenceBasis::None,
                        residual_policy_gaps: Vec::new(),
                    };
                    projection = Some(match projection {
                        Some(existing) if existing.state.rank() <= candidate.state.rank() => existing,
                        _ => candidate,
                    });
                }
                projection.unwrap_or(DomainProjection {
                    domain,
                    requested: RequestedControl::NotDerived,
                    state: ControlState::Unmeasured {
                        reason: UnmeasuredReason::NoControlRequested,
                    },
                    claim: ClaimTerm::Unmeasured,
                    evidence: EvidenceBasis::None,
                    residual_policy_gaps: Vec::new(),
                })
            })
            .collect();

        let negotiated = if plan.planned().is_empty() {
            Negotiated::Absent {
                reason: "the plan carries no capability requirement, so nothing was negotiated, \
                         prepared or applied"
                    .to_string(),
            }
        } else {
            Negotiated::Planned(plan.posture())
        };

        Self {
            stage: ReportStage::PreLaunch,
            session,
            identity: spec.identity().clone(),
            target: TargetRef::of(spec),
            backend: Some(plan.backend().clone()),
            requested: spec.requirements().to_vec(),
            domains,
            credentials: spec.credentials().clone(),
            descriptors: None,
            unmapped_policy: Vec::new(),
            refusals: Vec::new(),
            backend_unavailable: None,
            negotiated,
        }
    }

    /// A report for a launch refused before spawn.
    ///
    /// `spec` is required because [`PlanRefusal`] carries only the requirements
    /// that could **not** be met. Without the spec a domain that was requested
    /// and resolved would be indistinguishable from one nobody asked about, and
    /// this report would have to guess which — so the domains that were
    /// requested and are not in the refusal are reported as
    /// [`UnmeasuredReason::Inconclusive`] rather than as satisfied.
    pub fn from_refusal(session: SessionRef, spec: &ExecutionSpec, refusal: &PlanRefusal) -> Self {
        let domains = CapabilityDomain::ALL
            .iter()
            .map(|&domain| {
                let unmet = refusal.unmet().iter().find(|(r, _)| r.domain() == domain);
                let requested = spec.requirements().iter().find(|r| r.domain() == domain);
                let (state, claim) = match (&unmet, requested) {
                    (Some((_, reason)), _) => (
                        ControlState::Unsupported {
                            reason: (*reason).clone(),
                        },
                        ClaimTerm::Unsupported,
                    ),
                    (None, Some(_)) => (
                        ControlState::Unmeasured {
                            reason: UnmeasuredReason::Inconclusive {
                                detail: "the launch was refused, so this requirement's outcome was \
                                         never reported"
                                    .to_string(),
                            },
                        },
                        ClaimTerm::Unmeasured,
                    ),
                    (None, None) => (
                        ControlState::Unmeasured {
                            reason: UnmeasuredReason::NoControlRequested,
                        },
                        ClaimTerm::Unmeasured,
                    ),
                };
                DomainProjection {
                    domain,
                    requested: match (unmet, requested) {
                        (Some((requirement, _)), _) => RequestedControl::of(requirement),
                        (None, Some(requirement)) => RequestedControl::of(requirement),
                        (None, None) => RequestedControl::NotDerived,
                    },
                    state,
                    claim,
                    evidence: EvidenceBasis::None,
                    residual_policy_gaps: Vec::new(),
                }
            })
            .collect();

        Self {
            stage: ReportStage::PreLaunch,
            session,
            identity: spec.identity().clone(),
            target: TargetRef::of(spec),
            backend: Some(refusal.backend().clone()),
            requested: spec.requirements().to_vec(),
            domains,
            credentials: spec.credentials().clone(),
            descriptors: None,
            unmapped_policy: Vec::new(),
            refusals: refusal
                .unmet()
                .iter()
                .map(|(requirement, reason)| (requirement.domain(), reason.clone()))
                .collect(),
            backend_unavailable: refusal.backend_unavailable().map(str::to_string),
            negotiated: Negotiated::Refused,
        }
    }

    /// Attach the policy lowering the requirement set came from.
    ///
    /// This is what turns a blank requirement list into three distinguishable
    /// facts. Without it every unrequested domain reads
    /// [`RequestedControl::NotDerived`]; with it each one says whether the
    /// operator left a node unset, or whether the schema has no node to set.
    ///
    /// Only ever *adds* information: a domain that already carries a stated
    /// requirement keeps it, since the plan is the more specific source.
    pub fn with_policy(mut self, lowering: &PolicyLowering) -> Self {
        for projection in &mut self.domains {
            let Some(domain_lowering) = lowering.coverage(projection.domain) else {
                continue;
            };
            projection.residual_policy_gaps = domain_lowering.residual_gaps.clone();
            if projection.requested.is_stated() {
                continue;
            }
            projection.requested = match &domain_lowering.coverage {
                DomainCoverage::Lowered { .. } => lowering
                    .requirements()
                    .iter()
                    .find(|r| r.domain() == projection.domain)
                    .map_or(RequestedControl::NotDerived, RequestedControl::of),
                DomainCoverage::NotStated { node, schema_default } => RequestedControl::NotStated {
                    node: node.clone(),
                    schema_default: schema_default.clone(),
                },
                DomainCoverage::PolicyCannotExpress { detail } => {
                    RequestedControl::PolicyCannotExpress { detail: detail.clone() }
                }
            };
        }
        self.unmapped_policy = lowering.unmapped().to_vec();
        self
    }

    /// Attach what the launch established about the descriptors its child
    /// inherits.
    ///
    /// An inventory that does not [assert a clean
    /// boundary](DescriptorInventory::asserts_clean_boundary) makes
    /// [`is_least_authority`](Self::is_least_authority) false, exactly as
    /// unremoved ambient credentials do.
    pub fn with_descriptors(mut self, inventory: DescriptorInventory) -> Self {
        self.descriptors = Some(inventory);
        self
    }

    /// Join recorded evidence to the plan, moving the report to
    /// [`ReportStage::PostRun`].
    ///
    /// This is the *evidenced transition* ADR 0035 §10 requires before a runtime
    /// fact may strengthen a pre-launch claim, and it is deliberately narrow:
    ///
    /// * the claim comes from [`EnforcementEvidence::claim_for`], which ignores
    ///   setup-time records however strong a term they carry;
    /// * a prevention term is additionally refused unless
    ///   [`EnforcementEvidence::supports_prevention_claim`] holds. A runtime
    ///   record can carry [`ClaimTerm::DeniedBeforeExecution`] without an
    ///   [`EvidenceKind::Decision`] behind it — an
    ///   [`EvidenceKind::IndependentVerification`] of a failed action, say — and
    ///   that is corroboration, not a decision;
    /// * the posture may only be *lowered*. Evidence that a run was refused or
    ///   degraded overrides a readier plan; evidence never promotes a degraded
    ///   or absent boundary to ready.
    ///
    /// [`ControlState`] is untouched: what the backend was going to do is a
    /// property of the negotiation, and evidence reports what happened rather
    /// than rewriting what was planned.
    pub fn with_evidence(mut self, evidence: &EnforcementEvidence) -> Self {
        self.stage = ReportStage::PostRun;
        for projection in &mut self.domains {
            projection.evidence = EvidenceBasis::of(evidence, projection.domain);
            let mut claim = evidence.claim_for(projection.domain);
            if claim.is_prevention() && !evidence.supports_prevention_claim(projection.domain) {
                // A prevention term arrived on a runtime record with no decision
                // behind it. Corroboration presupposes the decision it
                // corroborates; without one, the strongest honest term is that
                // something was seen.
                claim = ClaimTerm::Observed;
            }
            projection.claim = claim;
        }

        // One-directional: evidence lowers a posture and never raises one.
        self.negotiated = match (&self.negotiated, evidence.posture()) {
            (_, LaunchPosture::Refused) => Negotiated::Refused,
            (Negotiated::Absent { reason }, _) => Negotiated::Absent { reason: reason.clone() },
            (Negotiated::Refused, _) => Negotiated::Refused,
            (Negotiated::Planned(LaunchPosture::Ready), LaunchPosture::Degraded) => {
                Negotiated::Planned(LaunchPosture::Degraded)
            }
            (Negotiated::Planned(planned), _) => Negotiated::Planned(*planned),
        };
        self
    }

    /// The stage this report describes.
    pub fn stage(&self) -> ReportStage {
        self.stage
    }

    /// The correlation ids runtime evidence joins on.
    pub fn session(&self) -> &SessionRef {
        &self.session
    }

    /// Who the launch is attributed to. **Asserted, not verified** — see
    /// [`IdentityRef`].
    pub fn identity(&self) -> &IdentityRef {
        &self.identity
    }

    /// What was launched.
    pub fn target(&self) -> &TargetRef {
        &self.target
    }

    /// Which backend answered, when one was selected.
    ///
    /// `None` means no backend was consulted. It never means "a backend is
    /// available": availability is a fact about the host, has no field here, and
    /// is not enforcement.
    pub fn backend(&self) -> Option<&BackendIdentity> {
        self.backend.as_ref()
    }

    /// The capability set policy asked for, in declaration order.
    pub fn requested_capability_set(&self) -> &[ControlRequirement] {
        &self.requested
    }

    /// Every domain, in [`CapabilityDomain::ALL`] order. Always nine entries.
    pub fn domains(&self) -> &[DomainProjection] {
        &self.domains
    }

    /// How the launch treats the authority the child would otherwise inherit.
    pub fn credentials(&self) -> &CredentialPosture {
        &self.credentials
    }

    /// What the launch established about inherited descriptors, when anything
    /// did.
    pub fn descriptors(&self) -> Option<&DescriptorInventory> {
        self.descriptors.as_ref()
    }

    /// Restrictions the policy expressed that no [`CapabilityDomain`] can carry.
    pub fn unmapped_policy(&self) -> &[String] {
        &self.unmapped_policy
    }

    /// Every required capability that was missing, with the reason, when the
    /// launch was refused.
    pub fn refusals(&self) -> &[(CapabilityDomain, RefusalReason)] {
        &self.refusals
    }

    /// Domains the policy schema cannot express at all.
    ///
    /// Renders separately from the domains an operator merely left unset. A
    /// domain here is not one needing no control; it is one nobody can ask
    /// about.
    pub fn unrepresentable_domains(&self) -> impl Iterator<Item = &DomainProjection> {
        self.domains.iter().filter(|d| d.requested.is_unrepresentable())
    }

    /// Domains nothing looked at.
    pub fn unmeasured_domains(&self) -> impl Iterator<Item = &DomainProjection> {
        self.domains
            .iter()
            .filter(|d| matches!(d.state, ControlState::Unmeasured { .. }))
    }

    /// Domains that fell short of what policy asked for.
    pub fn shortfalls(&self) -> impl Iterator<Item = &DomainProjection> {
        self.domains.iter().filter(|d| d.state.is_shortfall())
    }

    /// Whether the run holds no authority beyond what it was deliberately
    /// given.
    ///
    /// False when [`CredentialPosture::ambient_unremoved`] is non-empty (ADR
    /// 0035 §9: authority that *could not* be removed is not authority that
    /// *was*), and false when an attached descriptor inventory does not assert a
    /// clean boundary. Both are residual authority; neither is a failure of the
    /// run, and both must be said out loud rather than left for a reader to
    /// notice from an absence.
    pub fn is_least_authority(&self) -> bool {
        let descriptors_clean = match &self.descriptors {
            Some(inventory) => inventory.asserts_clean_boundary(),
            None => true,
        };
        !self.credentials.has_unremoved_ambient_authority() && descriptors_clean
    }

    /// The posture this run may be described as.
    ///
    /// Derived rather than stored, so the two things that can lower it —
    /// negotiation and residual authority — cannot be set independently of what
    /// the report actually contains. A `Ready` negotiation with unremoved
    /// ambient authority is [`ReportedPosture::Degraded`], because a run holding
    /// authority policy wanted removed is not equivalently protected.
    pub fn posture(&self) -> ReportedPosture {
        match &self.negotiated {
            Negotiated::Absent { .. } => ReportedPosture::NoBoundary,
            Negotiated::Refused => ReportedPosture::Refused,
            Negotiated::Planned(LaunchPosture::Ready) => {
                if self.is_least_authority() {
                    ReportedPosture::Ready
                } else {
                    ReportedPosture::Degraded
                }
            }
            Negotiated::Planned(_) => ReportedPosture::Degraded,
        }
    }

    /// Why no boundary was established, when none was.
    pub fn boundary_absent_reason(&self) -> Option<&str> {
        match &self.negotiated {
            Negotiated::Absent { reason } => Some(reason),
            _ => None,
        }
    }

    /// Whether this report claims the domain's actions were stopped before they
    /// took effect.
    ///
    /// True only at [`ReportStage::PostRun`], and only where the joined evidence
    /// carried an [`EvidenceKind::Decision`]. A plan can never make this true,
    /// whatever the control was going to do.
    pub fn claims_prevention(&self, domain: CapabilityDomain) -> bool {
        self.domains
            .iter()
            .any(|d| d.domain == domain && d.claim.is_prevention())
    }
}

/// The [`ControlState`] one negotiated outcome projects to.
fn state_of(outcome: &RequirementOutcome) -> ControlState {
    match outcome {
        RequirementOutcome::Enforced { timing, descendants } => ControlState::Prevention {
            timing: *timing,
            descendants: *descendants,
        },
        RequirementOutcome::Observed { timing, descendants } => ControlState::ObserveOnly {
            timing: *timing,
            descendants: *descendants,
        },
        RequirementOutcome::Degraded {
            planned,
            achieved,
            reason,
        } => ControlState::Degraded {
            planned: *planned,
            achieved: achieved.clone(),
            reason: reason.clone(),
        },
        RequirementOutcome::Unmet { reason } => ControlState::Unsupported { reason: reason.clone() },
    }
}
