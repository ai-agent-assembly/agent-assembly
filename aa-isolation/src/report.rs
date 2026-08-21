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

/// How a backend came to be the one this launch negotiated against.
///
/// Distinct from [`ReportedPosture`], which is about what the selected backend
/// achieved; this is about how it came to be selected at all — a fact an
/// operator reading a refusal needs to know before deciding whether to name a
/// different backend or accept none (AAASM-5808).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum SelectionMode {
    /// The operator named the backend directly (`--isolation-backend`, or
    /// `--isolation process`, which is hardcoded to one backend).
    Explicit,
    /// `--isolation auto` walked the fixed candidate list in order and this
    /// backend was the first one that could plan the launch.
    Automatic,
    /// No selection process ran — no boundary was requested.
    Default,
}

impl SelectionMode {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Automatic => "automatic",
            Self::Default => "default",
        }
    }
}

/// What became of one candidate backend during automatic selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CandidateVerdict {
    /// This candidate was the one selected.
    Selected,
    /// This candidate could not be selected on this host at all.
    RejectedUnavailable,
    /// This candidate is available but could not plan the launch's lowered
    /// requirements.
    RejectedRequirementsUnmet,
}

impl CandidateVerdict {
    /// A stable lowercase identifier for reports and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Selected => "selected",
            Self::RejectedUnavailable => "rejected_unavailable",
            Self::RejectedRequirementsUnmet => "rejected_requirements_unmet",
        }
    }
}

/// One candidate backend automatic selection considered, and what became of
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConsideredBackend {
    /// The candidate's stable backend id.
    pub id: String,
    /// What became of this candidate.
    pub verdict: CandidateVerdict,
    /// An operator-facing sentence explaining the verdict.
    pub detail: String,
    /// The domains this candidate could not meet, when the verdict is
    /// [`CandidateVerdict::RejectedRequirementsUnmet`]. Empty for every other
    /// verdict.
    pub unmet_domains: Vec<CapabilityDomain>,
}

/// How a backend was selected for this launch, and what the walk considered
/// along the way.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BackendSelection {
    /// How this launch's backend came to be selected.
    pub mode: SelectionMode,
    /// Every candidate the selection walk looked at, in the order it looked
    /// at them.
    pub considered: Vec<ConsideredBackend>,
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
    selection: Option<BackendSelection>,
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
            selection: None,
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
            selection: None,
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
            selection: None,
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

    /// Attach how the backend this report describes came to be selected.
    ///
    /// Absent entirely (`None`) rather than defaulted to
    /// [`SelectionMode::Default`] when nothing calls this — a report that has
    /// never been told how selection happened must not guess.
    pub fn with_selection(mut self, selection: BackendSelection) -> Self {
        self.selection = Some(selection);
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

    /// How the backend this report describes came to be selected, when
    /// anything recorded it.
    pub fn selection(&self) -> Option<&BackendSelection> {
        self.selection.as_ref()
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

/// Collapse anything that would break a line-oriented record into a space.
///
/// Applied to every value that came from outside this crate — a backend's
/// refusal reason, a policy node name, a schema default. A machine consumer
/// splits [`IsolationReport::machine_lines`] on `\n` and on the first `=`, so a
/// value carrying either would silently become a record of its own.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// A stable token for what policy asked a control to do.
fn intent_token(intent: RequirementIntent) -> &'static str {
    match intent {
        RequirementIntent::PreventBeforeEffect => "prevent_before_effect",
        RequirementIntent::Observe => "observe",
    }
}

/// A stable token for what happens when a requirement cannot be met.
fn requirement_posture_token(posture: RequirementPosture) -> &'static str {
    match posture {
        RequirementPosture::Required => "required",
        RequirementPosture::Optional => "optional",
        RequirementPosture::DegradeIfUnavailable => "degrade_if_unavailable",
    }
}

/// A stable token for how far down the process tree a requirement must reach.
fn descendant_requirement_token(descendants: DescendantRequirement) -> &'static str {
    match descendants {
        DescendantRequirement::ProcessTree => "process_tree",
        DescendantRequirement::TargetProcessOnly => "target_process_only",
    }
}

/// What a requirement applies to within its domain, rendered.
///
/// Selectors are the operator's own policy text — paths, destinations, call
/// names — and are printed so a reader can see what the requirement actually
/// covers. They are never credential material: [`RequirementScope`] carries
/// selectors, and the crate's credential vocabulary carries names only.
fn scope_detail(scope: &RequirementScope) -> String {
    match scope {
        RequirementScope::Whole => "whole_domain".to_string(),
        RequirementScope::Selectors(selectors) => {
            let rendered: Vec<String> = selectors.iter().map(|s| sanitize(s)).collect();
            format!("selectors[{}]: {}", rendered.len(), rendered.join(", "))
        }
        RequirementScope::Limits(limits) => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(v) = limits.max_memory_bytes {
                parts.push(format!("max_memory_bytes={v}"));
            }
            if let Some(v) = limits.max_cpu_seconds {
                parts.push(format!("max_cpu_seconds={v}"));
            }
            if let Some(v) = limits.max_pids {
                parts.push(format!("max_pids={v}"));
            }
            if let Some(v) = limits.max_wall_clock_seconds {
                parts.push(format!("max_wall_clock_seconds={v}"));
            }
            if let Some(v) = limits.max_file_size_bytes {
                parts.push(format!("max_file_size_bytes={v}"));
            }
            if let Some(v) = limits.max_open_files {
                parts.push(format!("max_open_files={v}"));
            }
            if parts.is_empty() {
                "limits: none stated".to_string()
            } else {
                format!("limits: {}", parts.join(" "))
            }
        }
    }
}

/// A stable token naming which refusal this is.
///
/// A free function rather than a method on [`RefusalReason`] so this ticket adds
/// no surface to the negotiation module. The match is exhaustive within the
/// crate, so a new variant fails to compile here rather than falling into a
/// catch-all that renders it as something else.
fn refusal_token(reason: &RefusalReason) -> &'static str {
    match reason {
        RefusalReason::BackendUnavailable { .. } => "backend_unavailable",
        RefusalReason::NoCapabilityReported { .. } => "no_capability_reported",
        RefusalReason::DomainUnsupported { .. } => "domain_unsupported",
        RefusalReason::ObserveOnlyForPreventionRequirement { .. } => "observe_only_for_prevention_requirement",
        RefusalReason::DecisionTooLate { .. } => "decision_too_late",
        RefusalReason::DecisionNotSynchronous { .. } => "decision_not_synchronous",
        RefusalReason::NoEvidenceProduced { .. } => "no_evidence_produced",
        RefusalReason::DescendantCoverageInsufficient { .. } => "descendant_coverage_insufficient",
        RefusalReason::PrerequisiteUnsatisfied { .. } => "prerequisite_unsatisfied",
    }
}

/// Why a requirement could not be met, in words an operator can act on.
///
/// Every arm names the *specific* missing capability rather than a generic
/// failure: "could not enforce filesystem writes" tells an operator nothing they
/// can do, while "the backend observes this domain but the requirement needs a
/// decision before the effect" tells them whether to change the policy, the
/// backend, or their expectations.
fn refusal_detail(reason: &RefusalReason) -> String {
    match reason {
        RefusalReason::BackendUnavailable { reason } => {
            format!("the backend cannot be selected on this host: {}", sanitize(reason))
        }
        RefusalReason::NoCapabilityReported { domain } => format!(
            "the backend said nothing about `{domain}`; silence is not a claim that the domain is uncovered, \
             and it is not a claim that it is covered either"
        ),
        RefusalReason::DomainUnsupported { domain, reason } => {
            format!("the backend reports no mechanism for `{domain}`: {}", sanitize(reason))
        }
        RefusalReason::ObserveOnlyForPreventionRequirement { domain, mediation } => format!(
            "`{domain}` needs a decision before the effect and this capability only \
             `{}`s; an observing control is never promoted to a preventing one",
            mediation.as_manifest_str()
        ),
        RefusalReason::DecisionTooLate { domain, timing } => format!(
            "`{domain}` is enforced but the decision lands `{}` rather than before the effect",
            timing.as_manifest_str()
        ),
        RefusalReason::DecisionNotSynchronous { domain, synchrony } => format!(
            "`{domain}` decides before the effect but the action is `{}` rather than waiting for the \
             decision, so it can win the race",
            synchrony.as_manifest_str()
        ),
        RefusalReason::NoEvidenceProduced { domain } => {
            format!("`{domain}` produces no evidence and the requirement asked for evidence")
        }
        RefusalReason::DescendantCoverageInsufficient { domain, offered } => format!(
            "`{domain}` needs process-tree coverage and this capability covers `{}`",
            offered.as_str()
        ),
        RefusalReason::PrerequisiteUnsatisfied { domain, requirement } => format!(
            "`{domain}` depends on a host precondition that is not known to hold: {}",
            sanitize(requirement)
        ),
    }
}

/// What a degraded requirement actually got, rendered.
fn achieved_detail(achieved: &AchievedControl) -> String {
    match achieved {
        AchievedControl::Observed { timing, descendants } => format!(
            "observed(timing={}, descendants={})",
            timing.as_manifest_str(),
            descendants.as_str()
        ),
        AchievedControl::None => "nothing".to_string(),
    }
}

/// The parenthetical that follows a [`ControlState`]'s token.
fn state_detail(state: &ControlState) -> String {
    match state {
        ControlState::Prevention { timing, descendants } | ControlState::ObserveOnly { timing, descendants } => {
            format!(
                "timing={}, descendants={}",
                timing.as_manifest_str(),
                descendants.as_str()
            )
        }
        ControlState::Degraded {
            planned,
            achieved,
            reason,
        } => format!(
            "planned={}, achieved={}, reason={}",
            intent_token(*planned),
            achieved_detail(achieved),
            refusal_token(reason)
        ),
        ControlState::Unsupported { reason } => refusal_token(reason).to_string(),
        ControlState::Unmeasured { reason } => match reason {
            UnmeasuredReason::Inconclusive { detail } => format!("inconclusive: {}", sanitize(detail)),
            other => other.as_str().to_string(),
        },
    }
}

/// What policy asked, rendered.
fn requested_detail(requested: &RequestedControl) -> String {
    match requested {
        RequestedControl::Stated {
            intent,
            posture,
            descendants,
            scope,
        } => format!(
            "intent={}, posture={}, descendants={}, scope={}",
            intent_token(*intent),
            requirement_posture_token(*posture),
            descendant_requirement_token(*descendants),
            scope_detail(scope)
        ),
        RequestedControl::NotStated { node, schema_default } => format!(
            "node=`{}` left unset; schema default: {}",
            sanitize(node),
            sanitize(schema_default)
        ),
        RequestedControl::PolicyCannotExpress { detail } => sanitize(detail),
        RequestedControl::NotDerived => "no policy lowering was attached to this report".to_string(),
    }
}

/// A copy of `names`, sorted, so a report of the same run renders identically
/// twice.
fn sorted(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = names.to_vec();
    out.sort();
    out
}

impl IsolationReport {
    /// The operator-facing rendering of this report.
    ///
    /// Deterministic: the same report renders byte-identically every time. Every
    /// list is emitted in a fixed order — domains in [`CapabilityDomain::ALL`]
    /// order, credential names sorted — so a diff between two runs is a
    /// difference in the runs and never in the iteration.
    ///
    /// The sections are ordered by how much they change what a reader should
    /// believe: the posture and whether the run is least-authority come first,
    /// then what was asked, then per-domain results, then the four different
    /// kinds of gap. Shortfalls, refusals and policy gaps each get a section of
    /// their own rather than a marker inside the table, because a reader
    /// skimming a table will read a marker as a footnote.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("--- execution isolation ---\n");
        self.render_header(&mut out);
        self.render_requested(&mut out);
        self.render_domains(&mut out);
        self.render_shortfalls(&mut out);
        self.render_refusals(&mut out);
        self.render_policy_gaps(&mut out);
        self.render_authority(&mut out);
        self.render_unmeasured(&mut out);
        out
    }

    /// Identity, session, target, backend and the two headline judgements.
    fn render_header(&self, out: &mut String) {
        let posture = self.posture();
        let stage = match self.stage {
            ReportStage::PreLaunch => "pre-launch — nothing has run; every state below is what the plan would do",
            ReportStage::PostRun => "post-run — states are the plan's; claims are what recorded evidence supports",
        };
        out.push_str(&format!("schema:           {REPORT_SCHEMA}\n"));
        out.push_str(&format!("stage:            {stage}\n"));
        out.push_str(&format!("posture:          {}\n", posture.label()));
        if let Some(reason) = self.boundary_absent_reason() {
            out.push_str(&format!("posture_detail:   {}\n", sanitize(reason)));
        }
        if let Some(reason) = &self.backend_unavailable {
            out.push_str(&format!("backend_refusal:  {}\n", sanitize(reason)));
        }
        out.push_str(&format!("least_authority:  {}\n", self.least_authority_line()));
        out.push_str(&format!("agent_id:         {}\n", sanitize(&self.identity.agent_id)));
        out.push_str(&format!(
            "team_id:          {}\n",
            self.identity
                .team_id
                .as_deref()
                .map_or_else(|| "<none>".to_string(), sanitize)
        ));
        out.push_str(&format!(
            "lineage:          {}\n",
            if self.identity.lineage.is_empty() {
                "<root launch, no ancestors>".to_string()
            } else {
                self.identity
                    .lineage
                    .iter()
                    .map(|a| sanitize(a))
                    .collect::<Vec<_>>()
                    .join(" > ")
            }
        ));
        out.push_str(&format!("session_id:       {}\n", sanitize(&self.session.session_id)));
        out.push_str(&format!("trace_id:         {}\n", sanitize(&self.session.trace_id)));
        out.push_str(&format!(
            "target:           {} ({} argument(s))\n",
            sanitize(&self.target.program),
            self.target.arg_count
        ));
        match &self.backend {
            Some(backend) => {
                out.push_str(&format!(
                    "backend:          {} version={} source={} license={} modified={}\n",
                    sanitize(&backend.id),
                    sanitize(&backend.version),
                    sanitize(&backend.provenance.source),
                    sanitize(&backend.provenance.license),
                    backend.provenance.modified,
                ));
            }
            None => out.push_str(
                "backend:          <none selected — no backend was consulted. Whether one could \
                 have been is a fact about this host, not about this run, and is not stated here>\n",
            ),
        }
        if let Some(selection) = &self.selection {
            out.push_str(&format!("selection:        {}\n", selection.mode.as_str()));
            for candidate in &selection.considered {
                out.push_str(&format!(
                    "  considered:     {} [{}] {}\n",
                    sanitize(&candidate.id),
                    candidate.verdict.as_str(),
                    sanitize(&candidate.detail)
                ));
            }
        }
    }

    /// The least-authority verdict, with the reason it is what it is.
    fn least_authority_line(&self) -> String {
        if self.is_least_authority() {
            return "yes — no inherited credential name and no inherited descriptor reaches the child \
                    unintended, as far as this launch could establish"
                .to_string();
        }
        let mut reasons: Vec<String> = Vec::new();
        let ambient = self.credentials.ambient_unremoved.len();
        if ambient > 0 {
            reasons.push(format!(
                "{ambient} inherited credential name(s) reach the child that policy wanted removed and \
                 this launch could not remove"
            ));
        }
        if let Some(inventory) = &self.descriptors {
            if !inventory.asserts_clean_boundary() {
                reasons.push("the inherited-descriptor boundary is not clean".to_string());
            }
        }
        format!("NO — {}", reasons.join("; "))
    }

    /// The capability set policy asked for.
    fn render_requested(&self, out: &mut String) {
        out.push_str("\nrequested capability set:\n");
        if self.requested.is_empty() {
            out.push_str(
                "  <empty> — this launch asked the execution boundary for nothing. An empty requirement \
                 set is not a clean boundary and must not be read as one: nothing was demanded, so \
                 nothing was refused, degraded or met.\n",
            );
            return;
        }
        for requirement in &self.requested {
            out.push_str(&format!(
                "  {:<17} {}\n",
                requirement.domain().as_str(),
                requested_detail(&RequestedControl::of(requirement))
            ));
        }
    }

    /// The per-capability table: requested, state, claim, evidence.
    fn render_domains(&self, out: &mut String) {
        out.push_str(
            "\nper-capability (state is what the boundary does; claim is what may be said; evidence is \
             what stands behind the claim):\n",
        );
        out.push_str(&format!(
            "  {:<17} {:<22} {:<13} {:<12} {}\n",
            "DOMAIN", "REQUESTED", "STATE", "CLAIM", "EVIDENCE"
        ));
        for projection in &self.domains {
            out.push_str(&format!(
                "  {:<17} {:<22} {:<13} {:<12} {}\n",
                projection.domain.as_str(),
                projection.requested.as_str(),
                projection.state.as_str(),
                projection.claim.as_str(),
                projection.evidence.as_str(),
            ));
        }
    }

    /// Degraded and unsupported controls, each with what it did *not* reach.
    fn render_shortfalls(&self, out: &mut String) {
        let shortfalls: Vec<&DomainProjection> = self.shortfalls().collect();
        if shortfalls.is_empty() {
            return;
        }
        out.push_str(
            "\ndegraded or unsupported controls — these are NOT enforced, and a run carrying any of \
             them is not equivalently protected:\n",
        );
        for projection in shortfalls {
            out.push_str(&format!(
                "  {} [{}] {}\n",
                projection.domain.as_str(),
                projection.state.as_str(),
                state_detail(&projection.state)
            ));
            let reason = match &projection.state {
                ControlState::Degraded { reason, .. } | ControlState::Unsupported { reason } => Some(reason),
                _ => None,
            };
            if let Some(reason) = reason {
                out.push_str(&format!("      {}\n", refusal_detail(reason)));
            }
        }
    }

    /// The refusal, naming every missing required capability.
    fn render_refusals(&self, out: &mut String) {
        if self.refusals.is_empty() && self.backend_unavailable.is_none() {
            return;
        }
        out.push_str("\nrefused before launch — the exact required capabilities that are missing:\n");
        if let Some(reason) = &self.backend_unavailable {
            out.push_str(&format!("  <backend> [backend_unavailable] {}\n", sanitize(reason)));
        }
        for (domain, reason) in &self.refusals {
            out.push_str(&format!(
                "  {} [{}] {}\n",
                domain.as_str(),
                refusal_token(reason),
                refusal_detail(reason)
            ));
        }
    }

    /// The three kinds of policy gap, each in its own block.
    ///
    /// Kept apart on purpose. A domain the schema cannot express, a domain the
    /// operator left unset, and a restriction the operator wrote that no domain
    /// can carry are three different remedies — change the product, change the
    /// policy, or accept that the intent was lost — and merging them would leave
    /// a reader unable to tell which one they are looking at.
    fn render_policy_gaps(&self, out: &mut String) {
        let unrepresentable: Vec<&DomainProjection> = self.unrepresentable_domains().collect();
        if !unrepresentable.is_empty() {
            out.push_str(
                "\npolicy cannot express these domains — there is no way for an operator to state a \
                 restriction here. This is the absence of a way to ask, NOT a judgement that no control \
                 is required:\n",
            );
            for projection in unrepresentable {
                out.push_str(&format!(
                    "  {} {}\n",
                    projection.domain.as_str(),
                    requested_detail(&projection.requested)
                ));
            }
        }

        let not_stated: Vec<&DomainProjection> = self
            .domains
            .iter()
            .filter(|d| matches!(d.requested, RequestedControl::NotStated { .. }))
            .collect();
        if !not_stated.is_empty() {
            out.push_str(
                "\nnot stated by this policy — the schema has a node for these and the operator left it \
                 unset. Unlike the block above, there is a policy line to write:\n",
            );
            for projection in not_stated {
                out.push_str(&format!(
                    "  {} {}\n",
                    projection.domain.as_str(),
                    requested_detail(&projection.requested)
                ));
            }
        }

        let residual: Vec<&DomainProjection> = self
            .domains
            .iter()
            .filter(|d| !d.residual_policy_gaps.is_empty())
            .collect();
        if !residual.is_empty() {
            out.push_str(
                "\npartially expressible — a requirement was lowered for these domains and something \
                 else about them could not be written:\n",
            );
            for projection in residual {
                for gap in &projection.residual_policy_gaps {
                    out.push_str(&format!("  {} {}\n", projection.domain.as_str(), sanitize(gap)));
                }
            }
        }

        if !self.unmapped_policy.is_empty() {
            out.push_str(
                "\npolicy statements no capability domain can carry — the operator wrote these and the \
                 execution boundary has nowhere to put them:\n",
            );
            for statement in &self.unmapped_policy {
                out.push_str(&format!("  {}\n", sanitize(statement)));
            }
        }
    }

    /// Residual ambient authority: credential names and inherited descriptors.
    fn render_authority(&self, out: &mut String) {
        out.push_str("\nresidual ambient authority (names only — no credential value is ever placed here):\n");
        let ambient = sorted(&self.credentials.ambient_unremoved);
        if ambient.is_empty() {
            out.push_str(
                "  ambient_unremoved: <none found>. This is a name-shaped lower bound, so an empty list \
                 is not evidence that no ambient authority reached the child.\n",
            );
        } else {
            out.push_str(&format!(
                "  ambient_unremoved ({}): {}\n",
                ambient.len(),
                ambient.iter().map(|n| sanitize(n)).collect::<Vec<_>>().join(", ")
            ));
            out.push_str(
                "      These reach the child and policy wanted them gone. The run is NOT \
                 least-authority.\n",
            );
        }
        let removed = sorted(&self.credentials.removed);
        out.push_str(&format!(
            "  removed ({}): {}\n",
            removed.len(),
            if removed.is_empty() {
                "<none>".to_string()
            } else {
                removed.iter().map(|n| sanitize(n)).collect::<Vec<_>>().join(", ")
            }
        ));
        let delegated = sorted(&self.credentials.delegated);
        out.push_str(&format!(
            "  delegated ({}): {}\n",
            delegated.len(),
            if delegated.is_empty() {
                "<none>".to_string()
            } else {
                delegated.iter().map(|n| sanitize(n)).collect::<Vec<_>>().join(", ")
            }
        ));
        let contradictions = self.credentials.contradictions();
        if !contradictions.is_empty() {
            out.push_str(&format!(
                "  CONTRADICTORY ({}): {} — reported in two lists that cannot both be true; this posture \
                 cannot be read\n",
                contradictions.len(),
                contradictions.join(", ")
            ));
        }
        match &self.descriptors {
            Some(inventory) => {
                for line in inventory.describe() {
                    out.push_str(&format!("  {}\n", sanitize(&line)));
                }
            }
            None => out.push_str(
                "  inherited descriptors: <no inventory taken> — nothing enumerated what the child \
                 inherits, which is not the same as nothing being inherited.\n",
            ),
        }
    }

    /// Every domain nothing looked at, with which silence it is.
    fn render_unmeasured(&self, out: &mut String) {
        let unmeasured: Vec<&DomainProjection> = self.unmeasured_domains().collect();
        if unmeasured.is_empty() {
            return;
        }
        out.push_str("\nunmeasured — nothing established anything about these domains:\n");
        for projection in unmeasured {
            out.push_str(&format!(
                "  {} {}\n",
                projection.domain.as_str(),
                state_detail(&projection.state)
            ));
        }
    }

    /// The machine-readable projection, one `key=value` record per line.
    ///
    /// A downstream dashboard or CI check consumes this without reading any of
    /// the prose in [`render`](Self::render): split each line on the first `=`,
    /// key off the token vocabulary, and never parse a sentence. Every value is
    /// passed through a sanitizer that removes control characters, so a line
    /// always holds exactly one record.
    ///
    /// The shape is stable within a [`REPORT_SCHEMA`] version. Keys are added
    /// without a bump; a rename or removal is a bump.
    ///
    /// Emitted rather than serialized because `aa-isolation`'s `serde` feature is
    /// off by default and deliberately so — the crate's types are a contract
    /// between crates, not a wire format, and a shipped binary should not have to
    /// enable a serialization surface to be able to report what it did.
    pub fn machine_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        let mut push = |key: &str, value: String| lines.push(format!("{key}={}", sanitize(&value)));

        push("schema", REPORT_SCHEMA.to_string());
        push("stage", self.stage.as_str().to_string());
        push("posture", self.posture().as_str().to_string());
        push(
            "posture_detail",
            self.boundary_absent_reason().unwrap_or_default().to_string(),
        );
        push("least_authority", self.is_least_authority().to_string());
        push("agent_id", self.identity.agent_id.clone());
        push("team_id", self.identity.team_id.clone().unwrap_or_default());
        push("lineage_depth", self.identity.depth().to_string());
        push("session_id", self.session.session_id.clone());
        push("trace_id", self.session.trace_id.clone());
        push("target_program", self.target.program.clone());
        push("target_arg_count", self.target.arg_count.to_string());

        push("backend_selected", self.backend.is_some().to_string());
        if let Some(backend) = &self.backend {
            push("backend_id", backend.id.clone());
            push("backend_version", backend.version.clone());
            push("backend_source", backend.provenance.source.clone());
            push("backend_license", backend.provenance.license.clone());
            push("backend_modified", backend.provenance.modified.to_string());
        }
        push(
            "backend_unavailable",
            self.backend_unavailable.clone().unwrap_or_default(),
        );

        if let Some(selection) = &self.selection {
            push("backend_selection_mode", selection.mode.as_str().to_string());
            push(
                "backend_selection.considered_count",
                selection.considered.len().to_string(),
            );
            for (index, candidate) in selection.considered.iter().enumerate() {
                push(
                    &format!("backend_selection.considered.{index}.id"),
                    candidate.id.clone(),
                );
                push(
                    &format!("backend_selection.considered.{index}.verdict"),
                    candidate.verdict.as_str().to_string(),
                );
                push(
                    &format!("backend_selection.considered.{index}.detail"),
                    candidate.detail.clone(),
                );
                push(
                    &format!("backend_selection.considered.{index}.unmet_domain_count"),
                    candidate.unmet_domains.len().to_string(),
                );
                for (gap_index, domain) in candidate.unmet_domains.iter().enumerate() {
                    push(
                        &format!("backend_selection.considered.{index}.unmet_domain.{gap_index}"),
                        domain.as_str().to_string(),
                    );
                }
            }
        }

        push("requested_requirement_count", self.requested.len().to_string());
        push("domain_count", self.domains.len().to_string());
        for projection in &self.domains {
            let domain = projection.domain.as_str();
            push(
                &format!("domain.{domain}.requested"),
                projection.requested.as_str().to_string(),
            );
            push(
                &format!("domain.{domain}.requested_detail"),
                requested_detail(&projection.requested),
            );
            push(&format!("domain.{domain}.state"), projection.state.as_str().to_string());
            push(
                &format!("domain.{domain}.state_detail"),
                state_detail(&projection.state),
            );
            push(&format!("domain.{domain}.claim"), projection.claim.as_str().to_string());
            push(
                &format!("domain.{domain}.evidence"),
                projection.evidence.as_str().to_string(),
            );
            push(
                &format!("domain.{domain}.policy_gap_count"),
                projection.residual_policy_gaps.len().to_string(),
            );
            for (index, gap) in projection.residual_policy_gaps.iter().enumerate() {
                push(&format!("domain.{domain}.policy_gap.{index}"), gap.clone());
            }
        }

        push("refusal_count", self.refusals.len().to_string());
        for (index, (domain, reason)) in self.refusals.iter().enumerate() {
            push(&format!("refusal.{index}.domain"), domain.as_str().to_string());
            push(&format!("refusal.{index}.reason"), refusal_token(reason).to_string());
            push(&format!("refusal.{index}.detail"), refusal_detail(reason));
        }

        for (label, names) in [
            ("removed", &self.credentials.removed),
            ("delegated", &self.credentials.delegated),
            ("ambient_unremoved", &self.credentials.ambient_unremoved),
        ] {
            let names = sorted(names);
            push(&format!("credential.{label}_count"), names.len().to_string());
            for (index, name) in names.iter().enumerate() {
                push(&format!("credential.{label}.{index}"), name.clone());
            }
        }
        push(
            "credential.contradiction_count",
            self.credentials.contradictions().len().to_string(),
        );

        push("descriptors_present", self.descriptors.is_some().to_string());
        if let Some(inventory) = &self.descriptors {
            push(
                "descriptors.enumeration_complete",
                inventory.completeness().is_complete().to_string(),
            );
            push("descriptors.residual_count", inventory.residual().count().to_string());
            push(
                "descriptors.asserts_clean_boundary",
                inventory.asserts_clean_boundary().to_string(),
            );
        }

        push("policy.unmapped_count", self.unmapped_policy.len().to_string());
        for (index, statement) in self.unmapped_policy.iter().enumerate() {
            push(&format!("policy.unmapped.{index}"), statement.clone());
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aa_security::policy::{Capability, CapabilitySet, PolicyDocument};

    use super::*;
    use crate::capability::{
        BackendAvailability, BackendCapabilities, CapabilityReport, Mediation, PlatformBoundary, Synchrony,
    };
    use crate::descriptor::{DescriptorDisposition, InheritedDescriptor};
    use crate::evidence::EvidenceRecord;
    use crate::lowering::{lower_policy, LoweringOptions};
    use crate::plan::{negotiate, Lowering, PlanRefusal, Provenance};

    const WRITE: CapabilityDomain = CapabilityDomain::FilesystemWrite;
    const EGRESS: CapabilityDomain = CapabilityDomain::NetworkEgress;
    const SYSCALL: CapabilityDomain = CapabilityDomain::Syscall;

    fn backend() -> BackendIdentity {
        BackendIdentity {
            id: "reference".into(),
            version: "1.2.3".into(),
            provenance: Provenance {
                source: "workspace".into(),
                license: "Apache-2.0".into(),
                modified: false,
            },
        }
    }

    fn session() -> SessionRef {
        SessionRef::new("session-1", "trace-1")
    }

    /// A capability that meets every condition for pre-effect denial.
    fn preventing(domain: CapabilityDomain) -> CapabilityReport {
        CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
            .with_descendants(DescendantCoverage::ProcessTree)
    }

    /// The same capability with only its enforcement signal removed. It still
    /// watches, is still pre-effect, still synchronous and still covers the
    /// tree — the single difference is that it cannot refuse.
    fn observing(domain: CapabilityDomain) -> CapabilityReport {
        CapabilityReport::new(domain, Mediation::Observe, DecisionTiming::Pre, Synchrony::Sync)
            .with_descendants(DescendantCoverage::ProcessTree)
    }

    fn capabilities(reports: Vec<CapabilityReport>) -> BackendCapabilities {
        BackendCapabilities::new(
            BackendAvailability::Available,
            PlatformBoundary::SharedHostKernel,
            reports,
        )
        .expect("test reports name distinct domains")
    }

    fn spec_of(requirements: Vec<ControlRequirement>, credentials: CredentialPosture) -> ExecutionSpec {
        let mut spec = ExecutionSpec::new("mock-tool", IdentityRef::root("agent-1").with_team("pioneer"))
            .with_args(["--flag", "value"])
            .with_credentials(credentials);
        for requirement in requirements {
            spec = spec.with_requirement(requirement);
        }
        spec
    }

    // Same justification as `negotiate`'s own allow, pinned by
    // `plan::tests::refusal_is_free_to_carry_by_value`: `EnforcementPlan` is the
    // larger variant, so the `Result` costs the same either way and boxing the
    // error would buy nothing.
    #[allow(clippy::result_large_err)]
    fn plan_of(spec: &ExecutionSpec, caps: &BackendCapabilities) -> Result<EnforcementPlan, PlanRefusal> {
        negotiate(spec, &backend(), caps, &|_, _| Lowering::none())
    }

    fn parse(report: &IsolationReport) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for line in report.machine_lines() {
            let (key, value) = line.split_once('=').expect("every record is key=value");
            assert!(!key.is_empty(), "empty key in `{line}`");
            assert!(
                map.insert(key.to_string(), value.to_string()).is_none(),
                "duplicate machine key `{key}`",
            );
        }
        map
    }

    /// The block a render heading introduces, up to the blank line that ends it.
    ///
    /// Assertions scoped to one section rather than to the whole render: without
    /// this, `!block.contains("filesystem_write")` would be satisfied — or
    /// violated — by an unrelated later section that happens to mention it, and
    /// the test would be measuring the wrong text.
    fn section(rendered: &str, heading: &str) -> String {
        let mut lines = rendered.lines().skip_while(|line| !line.starts_with(heading));
        let first = lines.next().expect("the section heading exists");
        std::iter::once(first)
            .chain(lines.take_while(|line| !line.trim().is_empty()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// One requirement per outcome the projection has a state for, so a single
    /// report exercises every arm.
    fn mixed_plan() -> EnforcementPlan {
        let spec = spec_of(
            vec![
                ControlRequirement::prevent(WRITE),
                ControlRequirement::prevent(EGRESS).with_posture(RequirementPosture::DegradeIfUnavailable),
                ControlRequirement::prevent(SYSCALL).with_posture(RequirementPosture::Optional),
            ],
            CredentialPosture {
                removed: vec!["ZZ_TOKEN".into(), "AA_TOKEN".into()],
                delegated: Vec::new(),
                ambient_unremoved: Vec::new(),
            },
        );
        let caps = capabilities(vec![
            preventing(WRITE),
            observing(EGRESS),
            CapabilityReport::unsupported(SYSCALL, "no mechanism in this deployment"),
        ]);
        plan_of(&spec, &caps).expect("only the required requirement must be met")
    }

    /// AC: dry-run prints a *deterministic* section derived from the canonical
    /// plan. Two renders of one report, and two reports of one run, must be
    /// byte-identical — otherwise a diff between two runs is unreadable.
    ///
    /// The credential lists are deliberately supplied out of order, so a
    /// rendering that iterated them as given rather than sorting would still
    /// pass the first assertion and fail the third.
    #[test]
    fn the_same_run_renders_byte_identically() {
        let first = IsolationReport::from_plan(session(), &mixed_plan());
        let second = IsolationReport::from_plan(session(), &mixed_plan());

        assert_eq!(first.render(), first.render(), "one report must render stably");
        assert_eq!(first.machine_lines(), first.machine_lines());
        assert_eq!(first.render(), second.render(), "one run must render stably");
        assert_eq!(first.machine_lines(), second.machine_lines());

        let removed_line = first
            .render()
            .lines()
            .find(|l| l.trim_start().starts_with("removed ("))
            .expect("the credential block names what was removed")
            .to_string();
        assert!(
            removed_line.contains("AA_TOKEN, ZZ_TOKEN"),
            "credential names must be sorted, not rendered in arrival order: {removed_line}"
        );
    }

    /// AC: per-capability requested vs achieved is visible and unsupported
    /// requirements are not hidden; explicit degradation is *structurally*
    /// distinct from enforcement.
    ///
    /// Five states, five tokens, and the degraded one lands in a section whose
    /// heading says it is not enforced — not a wording difference a reader can
    /// skim past.
    #[test]
    fn the_five_control_states_render_distinctly() {
        let report = IsolationReport::from_plan(session(), &mixed_plan());
        let machine = parse(&report);

        assert_eq!(machine["domain.filesystem_write.state"], "prevention");
        assert_eq!(machine["domain.network_egress.state"], "degraded");
        assert_eq!(machine["domain.syscall.state"], "unsupported");
        assert_eq!(machine["domain.credential.state"], "unmeasured");
        assert_eq!(machine["domain.credential.state_detail"], "no_control_requested");

        let tokens = ["prevention", "degraded", "unsupported", "unmeasured"];
        let mut distinct = tokens.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), tokens.len(), "the state tokens must not collide");

        let rendered = report.render();
        assert!(
            rendered.contains("degraded or unsupported controls — these are NOT enforced"),
            "degradation needs a section of its own, not a footnote: {rendered}"
        );
        let degraded_block = section(&rendered, "degraded or unsupported controls");
        assert!(
            degraded_block.contains("network_egress [degraded]"),
            "the degraded domain must appear in the shortfall section: {degraded_block}"
        );
        assert!(
            degraded_block.contains("planned=prevent_before_effect"),
            "a degraded entry must carry what it planned and did not reach: {degraded_block}"
        );
        assert!(
            degraded_block.contains("syscall [unsupported]"),
            "an unsupported requirement must not be hidden: {degraded_block}"
        );
        assert!(
            !degraded_block.contains("filesystem_write"),
            "a prevented domain must not be listed as a shortfall: {degraded_block}"
        );
    }

    /// AC: a refused launch explains the *exact* missing required capability.
    ///
    /// "Could not enforce network egress" is not actionable; the refusal has to
    /// say which condition of prevention the capability failed, so an operator
    /// knows whether to change the policy, the backend, or their expectations.
    #[test]
    fn a_refusal_names_the_exact_missing_required_capability() {
        let spec = spec_of(
            vec![ControlRequirement::prevent(WRITE), ControlRequirement::prevent(EGRESS)],
            CredentialPosture::default(),
        );
        let caps = capabilities(vec![preventing(WRITE), observing(EGRESS)]);
        let refusal = plan_of(&spec, &caps).expect_err("a required prevention requirement met an observer");

        let report = IsolationReport::from_refusal(session(), &spec, &refusal);
        assert_eq!(report.posture(), ReportedPosture::Refused);
        assert_eq!(report.refusals().len(), 1, "exactly one requirement was unmet");
        assert_eq!(report.refusals()[0].0, EGRESS);

        let rendered = report.render();
        assert!(rendered.contains("REFUSED"), "{rendered}");
        let refusal_block = section(&rendered, "refused before launch");
        assert!(
            refusal_block.contains("network_egress [observe_only_for_prevention_requirement]"),
            "the refusal must name the domain and the specific condition: {refusal_block}"
        );
        assert!(
            refusal_block.contains("only `observe`s"),
            "the refusal must say what the capability actually does: {refusal_block}"
        );
        assert!(
            !refusal_block.contains("filesystem_write"),
            "a requirement that was not the problem must not be named as missing: {refusal_block}"
        );

        let machine = parse(&report);
        assert_eq!(machine["refusal.0.domain"], "network_egress");
        assert_eq!(machine["refusal.0.reason"], "observe_only_for_prevention_requirement");
        assert_eq!(
            machine["domain.filesystem_write.state"], "unmeasured",
            "a requirement whose outcome was never reported is unmeasured, not satisfied"
        );
    }

    /// **Negative control 1 (AAASM-5710).** Removing the backend's enforcement
    /// signal must *lower* the reported state rather than leaving it green.
    ///
    /// The two capability reports differ in exactly one field — [`Mediation`] —
    /// and everything else about the run is held constant: same spec, same
    /// backend identity, same posture selection. If the projection ever mapped a
    /// degraded outcome to [`ControlState::Prevention`], or let a `Ready`
    /// negotiation survive a shortfall, this goes red.
    #[test]
    fn removing_the_backends_enforcement_signal_lowers_the_reported_state() {
        let spec = spec_of(
            vec![ControlRequirement::prevent(WRITE).with_posture(RequirementPosture::DegradeIfUnavailable)],
            CredentialPosture::default(),
        );

        let enforcing = plan_of(&spec, &capabilities(vec![preventing(WRITE)])).expect("an enforcing backend plans");
        let green = IsolationReport::from_plan(session(), &enforcing);
        assert_eq!(parse(&green)["domain.filesystem_write.state"], "prevention");
        assert_eq!(green.posture(), ReportedPosture::Ready);

        let bypassed = plan_of(&spec, &capabilities(vec![observing(WRITE)])).expect("degradation was permitted");
        let lowered = IsolationReport::from_plan(session(), &bypassed);
        let machine = parse(&lowered);
        assert_eq!(
            machine["domain.filesystem_write.state"], "degraded",
            "an observing capability must never project as prevention"
        );
        assert_eq!(machine["domain.filesystem_write.claim"], "degraded");
        assert_eq!(
            lowered.posture(),
            ReportedPosture::Degraded,
            "a shortfall must lower the run's posture"
        );
        assert_ne!(
            green.render(),
            lowered.render(),
            "the two runs must not render the same"
        );
    }

    /// **Negative control 2 (AAASM-5710).** Evidence with no
    /// [`EvidenceKind::Decision`] record must not claim prevention — however
    /// many other records carry a prevention term.
    ///
    /// Three progressively stronger inputs, and only the last one moves the
    /// claim: setup-time records (ADR 0033 forbidden design 6 — configuration is
    /// not enforcement), then a runtime corroboration that carries
    /// `denied_before_execution` without a decision behind it, then the decision
    /// itself. Deleting either gate in `with_evidence` turns this red.
    #[test]
    fn evidence_without_a_decision_record_never_claims_prevention() {
        let spec = spec_of(vec![ControlRequirement::prevent(WRITE)], CredentialPosture::default());
        let plan = plan_of(&spec, &capabilities(vec![preventing(WRITE)])).expect("an enforcing backend plans");
        let report = IsolationReport::from_plan(session(), &plan);

        // Pre-launch: the control *will* prevent, and the claim is still only
        // that it is planned. Nothing has run.
        assert_eq!(parse(&report)["domain.filesystem_write.state"], "prevention");
        assert_eq!(parse(&report)["domain.filesystem_write.claim"], "planned");
        assert!(!report.claims_prevention(WRITE));

        // Setup-time only, both records carrying the strongest possible term.
        let mut evidence = EnforcementEvidence::from_plan(&plan);
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Installed,
            WRITE,
            ClaimTerm::DeniedBeforeExecution,
            "the control was applied before the process started",
        ));
        let setup_only = report.clone().with_evidence(&evidence);
        let machine = parse(&setup_only);
        assert_eq!(machine["domain.filesystem_write.evidence"], "setup_only");
        assert_eq!(
            machine["domain.filesystem_write.claim"], "unmeasured",
            "an installed control that decided nothing has measured nothing"
        );
        assert!(!setup_only.claims_prevention(WRITE));

        // A runtime record, corroborating rather than deciding.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::IndependentVerification,
            WRITE,
            ClaimTerm::DeniedBeforeExecution,
            "an out-of-band probe of this domain failed",
        ));
        let corroborated = report.clone().with_evidence(&evidence);
        let machine = parse(&corroborated);
        assert_eq!(machine["domain.filesystem_write.evidence"], "runtime_without_decision");
        assert_ne!(
            machine["domain.filesystem_write.claim"], "denied_before_execution",
            "corroboration presupposes the decision it corroborates; it does not supply one"
        );
        assert!(!corroborated.claims_prevention(WRITE));

        // The decision, and only now does the claim rise.
        evidence.record(EvidenceRecord::new(
            EvidenceKind::Decision,
            WRITE,
            ClaimTerm::DeniedBeforeExecution,
            "refused a write to a path outside the permitted set",
        ));
        let decided = report.with_evidence(&evidence);
        let machine = parse(&decided);
        assert_eq!(machine["domain.filesystem_write.evidence"], "decision");
        assert_eq!(machine["domain.filesystem_write.claim"], "denied_before_execution");
        assert_eq!(machine["stage"], "post_run");
        assert!(decided.claims_prevention(WRITE));
    }

    /// **Negative control 3 (AAASM-5710).** A non-empty `ambient_unremoved` must
    /// change the rendered posture, not merely add a line somewhere.
    ///
    /// Everything except the credential list is held constant between the two
    /// reports. If `posture()` ever stopped consulting
    /// `is_least_authority`, the second half goes red.
    #[test]
    fn unremoved_ambient_authority_changes_the_rendered_posture() {
        let requirements = || vec![ControlRequirement::prevent(WRITE)];
        let caps = capabilities(vec![preventing(WRITE)]);

        let clean = spec_of(
            requirements(),
            CredentialPosture {
                removed: vec!["ANTHROPIC_API_KEY".into()],
                delegated: Vec::new(),
                ambient_unremoved: Vec::new(),
            },
        );
        let clean = IsolationReport::from_plan(session(), &plan_of(&clean, &caps).expect("plans"));
        assert!(clean.is_least_authority());
        assert_eq!(clean.posture(), ReportedPosture::Ready);
        assert_eq!(parse(&clean)["least_authority"], "true");
        assert_eq!(parse(&clean)["posture"], "ready");

        let residual = spec_of(
            requirements(),
            CredentialPosture {
                removed: vec!["ANTHROPIC_API_KEY".into()],
                delegated: Vec::new(),
                ambient_unremoved: vec!["AWS_SECRET_ACCESS_KEY".into(), "GITHUB_TOKEN".into()],
            },
        );
        let residual = IsolationReport::from_plan(session(), &plan_of(&residual, &caps).expect("plans"));
        assert!(!residual.is_least_authority());
        assert_eq!(
            residual.posture(),
            ReportedPosture::Degraded,
            "a run holding authority policy wanted removed is not equivalently protected"
        );
        let machine = parse(&residual);
        assert_eq!(machine["least_authority"], "false");
        assert_eq!(machine["posture"], "degraded");
        assert_eq!(machine["credential.ambient_unremoved_count"], "2");
        assert_eq!(machine["credential.ambient_unremoved.0"], "AWS_SECRET_ACCESS_KEY");

        let rendered = residual.render();
        assert!(rendered.contains("least_authority:  NO —"), "{rendered}");
        assert!(rendered.contains("The run is NOT least-authority."), "{rendered}");
        assert!(rendered.contains("AWS_SECRET_ACCESS_KEY"), "{rendered}");
        assert_ne!(clean.render(), rendered);
    }

    /// A negotiation that was asked for nothing succeeded at nothing.
    ///
    /// `negotiate` resolves an empty spec to [`LaunchPosture::Ready`] against any
    /// backend at all, including one that enforces nothing. That is correct for
    /// the negotiation and catastrophic as a report, so the projection reports
    /// [`ReportedPosture::NoBoundary`] instead — which is the honest state of
    /// `aasm run` today.
    #[test]
    fn a_plan_that_asked_for_nothing_is_not_reported_as_ready() {
        let spec = spec_of(Vec::new(), CredentialPosture::default());
        let plan = plan_of(&spec, &capabilities(Vec::new())).expect("an empty spec meets any backend");
        assert_eq!(
            plan.posture(),
            LaunchPosture::Ready,
            "the negotiation itself is ready — this is the state being guarded against"
        );

        let report = IsolationReport::from_plan(session(), &plan);
        assert_eq!(report.posture(), ReportedPosture::NoBoundary);
        assert_eq!(parse(&report)["posture"], "no_boundary");
        let rendered = report.render();
        assert!(
            rendered.contains("An empty requirement set is not a clean boundary"),
            "{rendered}"
        );
        assert!(rendered.contains("NO BOUNDARY ESTABLISHED"), "{rendered}");
    }

    /// A report with no backend states no backend, and nothing about the host's
    /// ability to supply one.
    ///
    /// ADR 0033 forbidden design 6 in its narrowest form: there is no field for
    /// availability, so there is nothing to round up.
    #[test]
    fn a_run_with_no_backend_claims_nothing_about_one() {
        let report = IsolationReport::no_boundary(
            session(),
            IdentityRef::root("agent-1"),
            TargetRef::new("mock-tool", 2),
            CredentialPosture::default(),
            "no isolation backend is selected by `aasm run` yet",
        );
        assert!(report.backend().is_none());
        assert_eq!(report.posture(), ReportedPosture::NoBoundary);

        let machine = parse(&report);
        assert_eq!(machine["backend_selected"], "false");
        assert!(!machine.contains_key("backend_id"));
        for domain in CapabilityDomain::ALL {
            let key = format!("domain.{}.state_detail", domain.as_str());
            assert_eq!(machine[&key], "no_backend_selected");
            assert_eq!(machine[&format!("domain.{}.claim", domain.as_str())], "unmeasured");
            assert_eq!(machine[&format!("domain.{}.evidence", domain.as_str())], "none");
        }
        assert!(
            report.render().contains("not about this run"),
            "the render must say availability is not a fact about this run"
        );
    }

    /// AC: policy gaps are rendered, and the three silences stay apart.
    ///
    /// `PolicyCannotExpress` (there is no way to ask), `NotStated` (there is a
    /// line to write and nobody wrote it) and `Unmeasured` (nobody looked) reach
    /// a reader through three different blocks with three different remedies.
    #[test]
    fn the_kinds_of_policy_silence_stay_structurally_apart() {
        let mut set = CapabilitySet::default();
        set.deny.insert(Capability::FileWrite);
        let policy = PolicyDocument {
            capabilities: Some(set),
            ..PolicyDocument::default()
        };
        let lowering = lower_policy(&policy, &LoweringOptions::strict());
        assert!(
            lowering.unrepresentable().count() > 0,
            "the fixture must contain at least one unrepresentable domain"
        );

        let report = IsolationReport::no_boundary(
            session(),
            IdentityRef::root("agent-1"),
            TargetRef::new("mock-tool", 0),
            CredentialPosture::default(),
            "no backend is selected",
        )
        .with_policy(&lowering);

        let machine = parse(&report);
        for gap in lowering.unrepresentable() {
            let key = format!("domain.{}.requested", gap.domain.as_str());
            assert_eq!(
                machine[&key], "policy_cannot_express",
                "an unrepresentable domain must say so rather than reading as unrequested"
            );
            assert_eq!(
                machine[&format!("domain.{}.state", gap.domain.as_str())],
                "unmeasured",
                "unrepresentable is about the request; the control is still unmeasured"
            );
        }

        let rendered = report.render();
        assert!(
            rendered.contains("policy cannot express these domains"),
            "the unrepresentable block is mandatory: {rendered}"
        );
        assert!(
            rendered.contains("NOT a judgement that no control is required"),
            "the unrepresentable block must refuse the 'no restriction needed' reading: {rendered}"
        );
        assert!(
            rendered.contains("unmeasured — nothing established anything"),
            "unmeasured is its own block: {rendered}"
        );
        assert!(
            !rendered.contains("no restriction is required"),
            "no block may render a gap as an absence of need: {rendered}"
        );

        // The three request tokens are distinct strings, so a grep for one can
        // never match another.
        let tokens = ["stated", "not_stated", "policy_cannot_express", "not_derived"];
        let mut distinct = tokens.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), tokens.len());
    }

    /// AC: a downstream dashboard or CI check can consume the output without
    /// parsing prose.
    ///
    /// Every record is `key=value`, keys are unique, values hold no newline, and
    /// every domain answers all four axes. A consumer keys off tokens from a
    /// closed vocabulary and never reads a sentence.
    #[test]
    fn machine_output_has_a_stable_parseable_shape() {
        let report = IsolationReport::from_plan(session(), &mixed_plan());
        let machine = parse(&report);

        assert_eq!(machine["schema"], REPORT_SCHEMA);
        assert_eq!(machine["domain_count"], "9");
        assert_eq!(machine["backend_id"], "reference");
        assert_eq!(machine["backend_version"], "1.2.3");
        assert_eq!(machine["backend_source"], "workspace");
        assert_eq!(machine["backend_license"], "Apache-2.0");
        assert_eq!(machine["session_id"], "session-1");
        assert_eq!(machine["trace_id"], "trace-1");
        assert_eq!(machine["agent_id"], "agent-1");
        assert_eq!(machine["target_program"], "mock-tool");
        assert_eq!(machine["target_arg_count"], "2");
        assert_eq!(machine["requested_requirement_count"], "3");

        for domain in CapabilityDomain::ALL {
            for axis in ["requested", "state", "claim", "evidence"] {
                let key = format!("domain.{}.{axis}", domain.as_str());
                assert!(machine.contains_key(&key), "missing `{key}`");
                assert!(!machine[&key].is_empty(), "`{key}` is empty");
            }
        }

        let postures = ["ready", "degraded", "refused", "no_boundary"];
        assert!(
            postures.contains(&machine["posture"].as_str()),
            "posture must come from a closed vocabulary, got `{}`",
            machine["posture"]
        );
        let stages = ["pre_launch", "post_run"];
        assert!(stages.contains(&machine["stage"].as_str()));

        for line in report.machine_lines() {
            assert!(!line.contains('\n'), "a record must be one line: {line}");
        }
    }

    /// A value carrying a newline or a control character cannot forge a record.
    ///
    /// Backend refusal reasons and policy node names are free text from outside
    /// this crate; without sanitizing, one containing `\nposture=ready` would
    /// inject a record a consumer would believe.
    #[test]
    fn hostile_free_text_cannot_forge_a_machine_record() {
        let spec = spec_of(vec![ControlRequirement::prevent(WRITE)], CredentialPosture::default());
        let caps = capabilities(vec![CapabilityReport::unsupported(
            WRITE,
            "no mechanism\nposture=ready\nleast_authority=true",
        )]);
        let refusal = plan_of(&spec, &caps).expect_err("an unsupported domain refuses a required requirement");
        let report = IsolationReport::from_refusal(session(), &spec, &refusal);

        let machine = parse(&report);
        assert_eq!(machine["posture"], "refused", "the injected posture must not win");
        assert_eq!(machine["least_authority"], "true");
        assert!(machine["refusal.0.detail"].contains("posture=ready"));
        assert!(!machine["refusal.0.detail"].contains('\n'));
    }

    /// An inherited-descriptor boundary nothing could enumerate is not a clean
    /// one, and the report must say so the same way it does for credentials.
    #[test]
    fn an_unenumerable_descriptor_boundary_is_not_least_authority() {
        let spec = spec_of(vec![ControlRequirement::prevent(WRITE)], CredentialPosture::default());
        let plan = plan_of(&spec, &capabilities(vec![preventing(WRITE)])).expect("plans");
        let report = IsolationReport::from_plan(session(), &plan);
        assert_eq!(report.posture(), ReportedPosture::Ready);

        let with_gap = report.with_descriptors(DescriptorInventory::not_enumerable(
            "this host offers no way to enumerate open descriptors",
            vec![InheritedDescriptor {
                number: 0,
                description: "standard input".into(),
                disposition: DescriptorDisposition::Delegated {
                    reason: "the launched program expects it".into(),
                },
            }],
        ));
        assert!(!with_gap.is_least_authority());
        assert_eq!(with_gap.posture(), ReportedPosture::Degraded);
        assert_eq!(parse(&with_gap)["descriptors.asserts_clean_boundary"], "false");
    }

    /// Evidence lowers a posture and never raises one.
    ///
    /// A run whose evidence says it was refused is refused, whatever the plan
    /// said; a run with no boundary does not acquire one because evidence
    /// arrived carrying a readier posture.
    #[test]
    fn evidence_lowers_a_posture_and_never_raises_one() {
        let spec = spec_of(Vec::new(), CredentialPosture::default());
        let plan = plan_of(&spec, &capabilities(Vec::new())).expect("an empty spec meets any backend");
        let absent = IsolationReport::from_plan(session(), &plan);
        assert_eq!(absent.posture(), ReportedPosture::NoBoundary);

        let ready_evidence = EnforcementEvidence::new(backend(), LaunchPosture::Ready);
        assert_eq!(
            absent.clone().with_evidence(&ready_evidence).posture(),
            ReportedPosture::NoBoundary,
            "evidence must not conjure a boundary that was never established"
        );

        let write_spec = spec_of(vec![ControlRequirement::prevent(WRITE)], CredentialPosture::default());
        let write_plan = plan_of(&write_spec, &capabilities(vec![preventing(WRITE)])).expect("plans");
        let ready = IsolationReport::from_plan(session(), &write_plan);
        assert_eq!(ready.posture(), ReportedPosture::Ready);

        let refused_evidence = EnforcementEvidence::new(backend(), LaunchPosture::Refused);
        assert_eq!(
            ready.clone().with_evidence(&refused_evidence).posture(),
            ReportedPosture::Refused,
        );
        let degraded_evidence = EnforcementEvidence::new(backend(), LaunchPosture::Degraded);
        assert_eq!(
            ready.with_evidence(&degraded_evidence).posture(),
            ReportedPosture::Degraded,
        );
    }

    /// Two requirements naming one domain fold to the weaker of the two.
    ///
    /// A spec may carry duplicates, and picking the first — or the strongest —
    /// would let a second, laxer requirement raise a domain's reported state.
    #[test]
    fn duplicate_requirements_for_one_domain_fold_to_the_weaker_state() {
        let spec = spec_of(
            vec![
                ControlRequirement::observe(WRITE),
                ControlRequirement::prevent(WRITE).with_posture(RequirementPosture::DegradeIfUnavailable),
            ],
            CredentialPosture::default(),
        );
        let plan = plan_of(&spec, &capabilities(vec![observing(WRITE)])).expect("degradation was permitted");
        let report = IsolationReport::from_plan(session(), &plan);
        assert_eq!(
            parse(&report)["domain.filesystem_write.state"],
            "degraded",
            "an observed requirement must not raise a degraded one out of the shortfall list"
        );
        assert_eq!(report.posture(), ReportedPosture::Degraded);
    }
}
