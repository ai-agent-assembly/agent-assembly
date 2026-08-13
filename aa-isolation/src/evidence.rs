//! What may be claimed about a run, and what may not.
//!
//! ADR 0035 §10: *"A successful process spawn is not evidence that every desired
//! control was enforced."* This module is the type-level version of that
//! sentence. Evidence is graded by [`EvidenceKind`], and the grades are not
//! interchangeable: having configured a control and having watched it refuse
//! something are different facts, and only the second one supports a prevention
//! claim.
//!
//! Backend *availability* is deliberately not an [`EvidenceKind`]. It lives on
//! [`crate::capability::BackendAvailability`], reachable only through capability
//! discovery, so that no code path can read "a backend was available" out of an
//! evidence object and round it up.

use aa_core::attestation::ClaimTerm;

use crate::capability::CapabilityDomain;
use crate::plan::{BackendIdentity, EnforcementPlan, LaunchPosture, PlanRefusal};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// How strongly a record is tied to something actually happening.
///
/// The first two are facts about *setup* and are ignored by
/// [`EnforcementEvidence::claim_for`] no matter what claim term they carry. The
/// last three are facts about the *run*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EvidenceKind {
    /// A control was requested by the plan.
    ///
    /// The weakest grade. Says only that somebody intended something.
    Configured,
    /// A control was applied to the boundary before the process started.
    ///
    /// Still not a claim about any action: an installed control that is never
    /// reached decides nothing.
    Installed,
    /// The control was reached by real activity during the run.
    Exercised,
    /// The control produced a decision about a specific action.
    ///
    /// The only grade that can support a prevention claim.
    Decision,
    /// A mechanism outside the enforcing component confirmed the outcome — an
    /// adversarial probe that failed, a negative control that fired.
    ///
    /// Corroborates a [`Decision`](Self::Decision); does not replace one. See
    /// [`EnforcementEvidence::supports_prevention_claim`].
    IndependentVerification,
}

impl EvidenceKind {
    /// Whether this grade describes the run rather than its setup.
    pub fn is_runtime_fact(self) -> bool {
        matches!(self, Self::Exercised | Self::Decision | Self::IndependentVerification)
    }
}

/// One evidentiary fact about a run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EvidenceRecord {
    /// How strongly this record is tied to something happening.
    pub kind: EvidenceKind,
    /// The domain it concerns, or `None` for a record about the run as a whole.
    pub domain: Option<CapabilityDomain>,
    /// The claim term, in `aa-core`'s vocabulary.
    ///
    /// Carrying a coverage-asserting term here does not make the claim true;
    /// [`EnforcementEvidence::claim_for`] still requires the record's
    /// [`kind`](Self::kind) to be a runtime fact.
    pub claim: ClaimTerm,
    /// What happened, in words.
    pub detail: String,
}

impl EvidenceRecord {
    /// A record about one domain.
    pub fn new(kind: EvidenceKind, domain: CapabilityDomain, claim: ClaimTerm, detail: impl Into<String>) -> Self {
        Self {
            kind,
            domain: Some(domain),
            claim,
            detail: detail.into(),
        }
    }

    /// A record about the run as a whole rather than any one domain.
    pub fn about_run(kind: EvidenceKind, claim: ClaimTerm, detail: impl Into<String>) -> Self {
        Self {
            kind,
            domain: None,
            claim,
            detail: detail.into(),
        }
    }
}

/// Ordering over claim terms, strongest first, for picking what a domain's
/// evidence best supports.
///
/// Only the six coverage-asserting terms are ranked; everything else is the
/// floor. Prevention outranks every form of observation, and degradation ranks
/// below all of them precisely so it can never win against an observation.
fn rank(claim: ClaimTerm) -> u8 {
    match claim {
        ClaimTerm::DeniedBeforeExecution => 6,
        ClaimTerm::ApprovalRequired => 5,
        ClaimTerm::Redacted => 4,
        ClaimTerm::Detected => 3,
        ClaimTerm::Evaluated => 2,
        ClaimTerm::Observed => 1,
        _ => 0,
    }
}

/// Everything that may be claimed about one run, and the posture it ran in.
///
/// Consumable by the ADR 0033 E6 audit/protection-state pipeline. The invariant
/// that pipeline depends on is
/// [`supports_prevention_claim`](Self::supports_prevention_claim): it is false
/// unless a [`EvidenceKind::Decision`] record for that domain carries a
/// prevention term, whatever else the evidence contains.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EnforcementEvidence {
    backend: BackendIdentity,
    posture: LaunchPosture,
    records: Vec<EvidenceRecord>,
}

impl EnforcementEvidence {
    /// Empty evidence for a run in the given posture.
    pub fn new(backend: BackendIdentity, posture: LaunchPosture) -> Self {
        Self {
            backend,
            posture,
            records: Vec::new(),
        }
    }

    /// The evidence a plan justifies *before anything runs*.
    ///
    /// Every record is [`EvidenceKind::Configured`], and every claim is
    /// [`ClaimTerm::Planned`] — including for requirements the plan will
    /// enforce. A plan is an intention; the run has not happened yet, and the
    /// only honest term for an intention is `Planned`.
    ///
    /// Requirements that fell short additionally keep their outcome's own
    /// ceiling, so a degraded requirement reads as degraded rather than as
    /// planned-and-fine.
    pub fn from_plan(plan: &EnforcementPlan) -> Self {
        let records = plan
            .planned()
            .iter()
            .map(|planned| {
                let claim = if planned.outcome.is_shortfall() {
                    planned.outcome.claim_ceiling()
                } else {
                    ClaimTerm::Planned
                };
                EvidenceRecord::new(
                    EvidenceKind::Configured,
                    planned.requirement.domain(),
                    claim,
                    format!(
                        "planned by backend `{}`: {} lowering step(s)",
                        plan.backend().id,
                        planned.lowering.steps().len()
                    ),
                )
            })
            .collect();
        Self {
            backend: plan.backend().clone(),
            posture: plan.posture(),
            records,
        }
    }

    /// The evidence a refusal justifies.
    ///
    /// A refused launch is an outcome E6 must see, not an absence of one. Every
    /// record carries [`ClaimTerm::Unsupported`]: the refusal is a statement
    /// that the control could not be provided here, and nothing about the
    /// agent's behaviour was measured because the agent never ran.
    pub fn from_refusal(refusal: &PlanRefusal) -> Self {
        let mut records: Vec<EvidenceRecord> = Vec::new();
        if let Some(reason) = refusal.backend_unavailable() {
            records.push(EvidenceRecord::about_run(
                EvidenceKind::Configured,
                ClaimTerm::Unsupported,
                format!("backend unavailable: {reason}"),
            ));
        }
        for (requirement, reason) in refusal.unmet() {
            records.push(EvidenceRecord::new(
                EvidenceKind::Configured,
                requirement.domain(),
                ClaimTerm::Unsupported,
                format!("required requirement refused before spawn: {reason:?}"),
            ));
        }
        Self {
            backend: refusal.backend().clone(),
            posture: LaunchPosture::Refused,
            records,
        }
    }

    /// Add a record.
    pub fn record(&mut self, record: EvidenceRecord) {
        self.records.push(record);
    }

    /// Add a record, chaining.
    pub fn with_record(mut self, record: EvidenceRecord) -> Self {
        self.records.push(record);
        self
    }

    /// Which backend produced this evidence.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// The posture the run started in.
    pub fn posture(&self) -> LaunchPosture {
        self.posture
    }

    /// Every record, in the order recorded.
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }

    /// Records concerning one domain.
    pub fn records_for(&self, domain: CapabilityDomain) -> impl Iterator<Item = &EvidenceRecord> {
        self.records.iter().filter(move |r| r.domain == Some(domain))
    }

    /// Whether the evidence justifies saying this domain's actions were stopped
    /// before they took effect.
    ///
    /// Requires an [`EvidenceKind::Decision`] record whose claim term is
    /// [`ClaimTerm::is_prevention`]. Neither
    /// [`EvidenceKind::Configured`] nor [`EvidenceKind::Installed`] can make
    /// this true — that is ADR 0035's validation bar, *"E6 output never promotes
    /// `available`/`configured`/`observed` into `enforced` without evidence"*,
    /// held as a predicate rather than as a convention.
    ///
    /// [`EvidenceKind::IndependentVerification`] does not make it true either.
    /// Corroboration of a decision presupposes the decision; if the enforcing
    /// component never recorded one, an out-of-band probe showing the action
    /// failed does not establish that *this* control is why.
    pub fn supports_prevention_claim(&self, domain: CapabilityDomain) -> bool {
        self.records
            .iter()
            .any(|r| r.kind == EvidenceKind::Decision && r.domain == Some(domain) && r.claim.is_prevention())
    }

    /// Whether something outside the enforcing component corroborated this
    /// domain's outcome.
    pub fn is_independently_verified(&self, domain: CapabilityDomain) -> bool {
        self.records
            .iter()
            .any(|r| r.kind == EvidenceKind::IndependentVerification && r.domain == Some(domain))
    }

    /// The strongest claim the evidence actually supports for one domain.
    ///
    /// Considers only records whose [`EvidenceKind::is_runtime_fact`] holds, so
    /// setup-time records cannot raise the answer regardless of the claim term
    /// they carry. Returns [`ClaimTerm::Unmeasured`] when no runtime record
    /// asserts coverage — the honest answer when nothing looked.
    pub fn claim_for(&self, domain: CapabilityDomain) -> ClaimTerm {
        self.records
            .iter()
            .filter(|r| r.domain == Some(domain) && r.kind.is_runtime_fact())
            .map(|r| r.claim)
            .filter(|c| c.asserts_coverage())
            .max_by_key(|c| rank(*c))
            .unwrap_or(ClaimTerm::Unmeasured)
    }
}
