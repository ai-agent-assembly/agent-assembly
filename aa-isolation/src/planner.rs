//! Backend-neutral, property-based selection over pluggable enforcement
//! backends.
//!
//! AAASM-6167 (Epic AAASM-6159, "Agent Execution Runtime 2.0"). Generalizes the
//! per-CLI-build `--isolation auto` walk that ADR 0035's AAASM-5808 amendment
//! recorded (`aa-cli/src/commands/run.rs::auto_select`) into a mechanism this
//! crate owns: a caller states a [`RuntimeRequirements`], not a backend id, and
//! [`select`] walks candidates the same way that amendment already does. An
//! explicit pin still resolves through [`select_pinned`] and fails explicitly,
//! never silently, when it cannot be satisfied.
//!
//! # Why this does not touch [`crate::plan::negotiate`]
//!
//! `plan.rs`'s own module documentation calls [`negotiate`] "the single
//! decision point of this crate": every backend refuses for the same reasons
//! because there is exactly one function deciding refusal. [`select`] and
//! [`select_pinned`] each call it exactly once per candidate, through
//! [`evaluate_candidate`], and never reimplement any part of its per-domain
//! evaluation. "Does not regress the existing prevention invariant" therefore
//! holds because this module has no code path that could regress it — it
//! cannot re-decide what [`negotiate`] already decided, only add a further,
//! independent bar on top.
//!
//! # The independent bar this module adds
//!
//! [`negotiate`]'s prevention check reads exactly three axes: [`Mediation`],
//! [`DecisionTiming`] and [`Synchrony`]. It never reads
//! [`FailurePosture`] or [`SupportLevel`] — a report can be
//! `Enforce`/`Pre`/`Sync` (satisfying every prevention requirement `negotiate`
//! checks) while it is [`FailurePosture::FailOpenSilent`] or
//! [`SupportLevel::Partial`] with stated gaps. [`RuntimeRequirements`]'s
//! [`EvidenceMinimum`] states a floor on those two axes, and
//! [`unmet_evidence_minimums`] checks it directly against a candidate's
//! [`BackendCapabilities`] — never against the outcome `negotiate` already
//! reached. This is the ticket's "required evidence/attestation quality can
//! disqualify a backend" acceptance criterion: a candidate `negotiate` alone
//! would accept can still be rejected here.
//!
//! # Ordering: eligibility strictly before tie-break
//!
//! [`select`] decides [`evaluate_candidate`] for every candidate, one at a
//! time, in declared order, and returns the *first* one that is `Ok` — no
//! candidate is ever compared against another candidate's *properties*, only
//! against `requirements` directly. There is no step at which an ineligible
//! candidate could be preferred over an eligible one: ineligibility is decided
//! before a candidate is ever added to anything a tie-break could read.
//!
//! Tie-break among eligible candidates is the caller's own declared candidate
//! order — first eligible wins. This is deliberate, not a placeholder: the
//! ticket's "performance among security-equivalent candidates" is not backed
//! by real performance data anywhere in this workspace yet (the
//! AAASM-6168/6169/6170 backend spikes are unmerged prose with self-reported
//! overhead numbers, not measurements this crate can stand behind), so
//! inventing a numeric score here would be fabricating a policy input. It is
//! also exactly what `aa-cli`'s existing `CANDIDATES` walk already does, so
//! generalizing to this module changes no observable selection on today's
//! candidate set — see `tests::selects_first_eligible_in_declared_order`.
//!
//! # Why candidates are data, not `dyn IsolationBackend`
//!
//! `aa-isolation` cannot depend on any backend crate (see the crate-level
//! documentation on dependency direction), and
//! [`crate::backend::IsolationBackend::identity`]/[`crate::backend::IsolationBackend::capabilities`]
//! are already everything eligibility needs. [`Candidate`] is exactly that
//! pair. A caller holding `Box<dyn IsolationBackend>` per concrete backend
//! builds one [`Candidate`] per backend and, on a [`Selection::Selected`]
//! verdict, looks the winning id back up in its own list — the *construction*
//! site still knows concrete backend types (Rust needs one somewhere to build
//! them), but the *evaluation* path here never switches on a backend name,
//! which is what lets a future backend join the walk without a new match arm
//! in this crate.

use crate::capability::{BackendAvailability, BackendCapabilities, CapabilityDomain, FailurePosture, SupportLevel};
use crate::plan::{negotiate, BackendIdentity, EnforcementPlan, Lowering, PlanRefusal, RefusalReason};
use crate::report::{BackendSelection, CandidateVerdict, ConsideredBackend, SelectionMode};
use crate::requirements::RuntimeRequirements;
use crate::spec::ControlRequirement;

/// One backend the planner can evaluate: identity plus its capability report.
///
/// See the module documentation for why this is data rather than
/// `dyn IsolationBackend`.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// This candidate's identity.
    pub identity: BackendIdentity,
    /// What this candidate reported it can do, on this host, right now.
    pub capabilities: BackendCapabilities,
}

impl Candidate {
    /// A candidate named `identity` reporting `capabilities`.
    pub fn new(identity: BackendIdentity, capabilities: BackendCapabilities) -> Self {
        Self { identity, capabilities }
    }
}

/// Does `actual` meet a stated minimum [`FailurePosture`]?
///
/// A free function rather than an [`Ord`] impl on [`FailurePosture`] itself:
/// ordering a *ladder of acceptable outcomes* is a property of this planner's
/// evidence axis, not of the failure-posture vocabulary `plan.rs` and every
/// backend's `capability.rs` already use for other purposes — giving the type
/// itself a general ordering would invite comparisons that have nothing to do
/// with a stated minimum.
///
/// [`FailurePosture::NotApplicable`] — the default
/// [`crate::capability::CapabilityReport::new`] leaves a domain at when a
/// backend never calls `with_failure_posture` for it — meets nothing but
/// itself. A backend that never stated an opinion on this axis for a domain
/// must not be read as meeting a minimum it never addressed: silence is not
/// "closed", mirroring `negotiate`'s own "unknown capability is not
/// interpreted as supported" rule for
/// [`RefusalReason::NoCapabilityReported`], carried onto this axis instead of
/// the domain axis.
fn meets_failure_posture_minimum(actual: FailurePosture, minimum: FailurePosture) -> bool {
    use FailurePosture::{FailClosed, FailOpen, FailOpenSilent, NotApplicable, SilentTruncation};
    match minimum {
        FailClosed => actual == FailClosed,
        FailOpen => matches!(actual, FailClosed | FailOpen),
        SilentTruncation => matches!(actual, FailClosed | FailOpen | SilentTruncation),
        FailOpenSilent => matches!(actual, FailClosed | FailOpen | SilentTruncation | FailOpenSilent),
        NotApplicable => actual == NotApplicable,
    }
}

/// Every [`EvidenceMinimum`](crate::requirements::EvidenceMinimum) `requirements`
/// states that `capabilities` does not meet, independent of anything
/// [`negotiate`] already decided.
///
/// A domain [`BackendCapabilities::report_for`] has no report for at all fails
/// any stated minimum on it, for the same "unknown is not supported" reason
/// [`meets_failure_posture_minimum`] states for the failure-posture axis
/// specifically.
fn unmet_evidence_minimums(
    requirements: &RuntimeRequirements,
    capabilities: &BackendCapabilities,
) -> Vec<(CapabilityDomain, RefusalReason)> {
    let mut unmet = Vec::new();
    for (&domain, minimum) in requirements.evidence_minimums() {
        let Some(report) = capabilities.report_for(domain) else {
            unmet.push((domain, RefusalReason::NoCapabilityReported { domain }));
            continue;
        };

        let failure_ok = minimum.min_failure_posture().map_or(true, |required| {
            meets_failure_posture_minimum(report.failure_posture(), required)
        });
        let support_ok = !minimum.requires_full_support() || matches!(report.support(), SupportLevel::Full);

        if !failure_ok || !support_ok {
            unmet.push((
                domain,
                RefusalReason::EvidenceQualityBelowMinimum {
                    domain,
                    required_failure_posture: minimum.min_failure_posture(),
                    required_full_support: minimum.requires_full_support(),
                    actual_failure_posture: report.failure_posture(),
                    actual_support: report.support().clone(),
                },
            ));
        }
    }
    unmet
}

/// Resolve `requirements` against one candidate: [`negotiate`]'s eligibility
/// check, then this planner's evidence-minimum bar — strictly in that order,
/// and the second never runs if the first already refused.
///
/// # Errors
///
/// [`PlanRefusal`] naming every unmet requirement, whether the unmet reason
/// came from [`negotiate`] itself or from an unmet
/// [`EvidenceMinimum`](crate::requirements::EvidenceMinimum) — a pin's failure
/// and an automatic candidate's rejection are always the same shape of
/// answer.
#[allow(clippy::result_large_err)] // see `plan::negotiate`'s own justification; identical shape here
pub fn evaluate_candidate(
    requirements: &RuntimeRequirements,
    candidate: &Candidate,
) -> Result<EnforcementPlan, PlanRefusal> {
    let probe = requirements.probe_spec();
    let plan = negotiate(
        &probe,
        &candidate.identity,
        &candidate.capabilities,
        &|_requirement, _outcome| Lowering::none(),
    )?;

    let unmet = unmet_evidence_minimums(requirements, &candidate.capabilities);
    if unmet.is_empty() {
        return Ok(plan);
    }

    // Reattach the real `ControlRequirement` for each flagged domain, when the
    // requirement set already names one, so the refusal carries the same
    // requirement a `negotiate` refusal would. An evidence minimum can be
    // stated on a domain with no confinement requirement at all, in which
    // case a synthetic `observe`-intent requirement records that an evidence
    // bar existed for the domain — never a confinement demand nobody made.
    let unmet = unmet
        .into_iter()
        .map(|(domain, reason)| {
            let requirement = probe
                .requirements()
                .iter()
                .find(|r| r.domain() == domain)
                .cloned()
                .unwrap_or_else(|| ControlRequirement::observe(domain));
            (requirement, reason)
        })
        .collect();
    Err(PlanRefusal::from_unmet(candidate.identity.clone(), unmet))
}

/// The result of walking a candidate list with [`select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// A candidate satisfied every stated requirement.
    Selected {
        /// The winning candidate's identity.
        identity: BackendIdentity,
        /// The plan [`negotiate`] produced for the winner against the probe
        /// spec — not a plan carrying a caller's real program, args or
        /// identity. See [`RuntimeRequirements::probe_spec`].
        ///
        /// Boxed only to keep this variant close in size to
        /// [`Selection::Refused`] (clippy's `large_enum_variant`); nothing
        /// about ownership or mutability changes.
        plan: Box<EnforcementPlan>,
    },
    /// No candidate satisfied every stated requirement.
    Refused,
}

/// Walk `candidates` in the given order and select the first one that
/// satisfies `requirements`, or refuse naming every candidate and why.
///
/// Deterministic: the same `requirements` against the same `candidates` in the
/// same order always returns the same [`Selection`] and the same considered
/// list. See the module documentation for why eligibility is decided strictly
/// before any tie-break, and why the tie-break itself is declared order.
pub fn select(requirements: &RuntimeRequirements, candidates: &[Candidate]) -> (Selection, BackendSelection) {
    let mut considered = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        if let BackendAvailability::Unavailable { reason } = candidate.capabilities.availability() {
            considered.push(ConsideredBackend {
                id: candidate.identity.id.clone(),
                verdict: CandidateVerdict::RejectedUnavailable,
                detail: format!("the backend cannot be selected on this host — {reason}"),
                unmet_domains: Vec::new(),
            });
            continue;
        }

        match evaluate_candidate(requirements, candidate) {
            Ok(plan) => {
                considered.push(ConsideredBackend {
                    id: candidate.identity.id.clone(),
                    verdict: CandidateVerdict::Selected,
                    detail: "this candidate satisfied every stated runtime requirement".to_string(),
                    unmet_domains: Vec::new(),
                });
                return (
                    Selection::Selected {
                        identity: candidate.identity.clone(),
                        plan: Box::new(plan),
                    },
                    BackendSelection {
                        mode: SelectionMode::Automatic,
                        considered,
                    },
                );
            }
            Err(refusal) => {
                let unmet_domains = refusal
                    .unmet()
                    .iter()
                    .filter_map(|(_, reason)| reason.domain())
                    .collect();
                considered.push(ConsideredBackend {
                    id: candidate.identity.id.clone(),
                    verdict: CandidateVerdict::RejectedRequirementsUnmet,
                    detail: refusal.to_string(),
                    unmet_domains,
                });
            }
        }
    }

    (
        Selection::Refused,
        BackendSelection {
            mode: SelectionMode::Automatic,
            considered,
        },
    )
}

/// Resolve `requirements` against exactly one pinned candidate.
///
/// # Errors
///
/// [`PlanRefusal`] naming what the pin could not satisfy. Never falls back to
/// another candidate: an explicit pin that cannot meet `requirements` is a
/// configuration fact the operator asked to see, not a reason to pick
/// something else on their behalf — the ticket's "explicit pins remain
/// predictable" and "a pinned incompatible backend fails explicitly"
/// acceptance criteria. Routes through the identical [`evaluate_candidate`]
/// [`select`] uses, so a pin and an automatic walk can never disagree about
/// whether one candidate satisfies one requirement set.
#[allow(clippy::result_large_err)]
pub fn select_pinned(
    requirements: &RuntimeRequirements,
    candidate: &Candidate,
) -> Result<EnforcementPlan, PlanRefusal> {
    evaluate_candidate(requirements, candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        BackendAvailability, CapabilityReport, DecisionTiming, DescendantCoverage, Mediation, PlatformBoundary,
        Synchrony,
    };
    use crate::plan::{BackendIdentity, Provenance};
    use crate::requirements::EvidenceMinimum;

    fn identity(id: &str) -> BackendIdentity {
        BackendIdentity {
            id: id.to_string(),
            version: "0".to_string(),
            provenance: Provenance {
                source: "test".to_string(),
                license: "Apache-2.0".to_string(),
                modified: false,
            },
        }
    }

    /// A candidate that fully prevents `domains`, with `failure_posture` and
    /// `support` on every one of them — the knobs the mutation tests below
    /// move independently of `can_prevent()`.
    fn preventing_candidate(
        id: &str,
        domains: &[CapabilityDomain],
        failure_posture: FailurePosture,
        support: SupportLevel,
    ) -> Candidate {
        let reports = domains
            .iter()
            .map(|&domain| {
                CapabilityReport::new(domain, Mediation::Enforce, DecisionTiming::Pre, Synchrony::Sync)
                    .with_descendants(DescendantCoverage::ProcessTree)
                    .with_failure_posture(failure_posture)
                    .with_support(support.clone())
            })
            .collect();
        Candidate::new(
            identity(id),
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .expect("unique domains"),
        )
    }

    // --- Regression control: the existing `negotiate` invariant is unchanged ---

    /// Mutating `Mediation` from `Enforce` to `Observe` must still refuse a
    /// `PreventBeforeEffect` requirement — this is `negotiate`'s own invariant,
    /// re-asserted through the planner's entry point to prove the planner adds
    /// a check rather than replacing the existing one.
    #[test]
    fn observe_only_capability_is_refused_for_a_prevention_requirement() {
        let domain = CapabilityDomain::FilesystemWrite;
        let report = CapabilityReport::new(domain, Mediation::Observe, DecisionTiming::Pre, Synchrony::Sync)
            .with_descendants(DescendantCoverage::ProcessTree);
        let candidate = Candidate::new(
            identity("observe-only"),
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                vec![report],
            )
            .unwrap(),
        );
        let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(domain));

        let result = evaluate_candidate(&requirements, &candidate);
        assert!(
            result.is_err(),
            "an observe-only capability must never satisfy a prevention requirement"
        );
    }

    // --- The load-bearing mutation: the new evidence-minimum axis ---

    /// A candidate that `can_prevent()` a domain (enforce/pre/sync, full
    /// prevention semantics intact) is nonetheless excluded from the eligible
    /// set when its `FailurePosture` falls below a stated minimum — the axis
    /// `negotiate` never reads. The weakened candidate is placed *first* in
    /// declared order, which is what the tie-break would otherwise prefer, so
    /// this proves eligibility is decided strictly before any tie-break: if
    /// the filter ran after (or not at all), the weakened candidate would win.
    #[test]
    fn a_candidate_negotiate_would_accept_is_excluded_by_a_failure_posture_minimum() {
        let domain = CapabilityDomain::FilesystemWrite;
        let weak = preventing_candidate("weak", &[domain], FailurePosture::FailOpenSilent, SupportLevel::Full);
        let strong = preventing_candidate("strong", &[domain], FailurePosture::FailClosed, SupportLevel::Full);

        // Sanity: `negotiate` alone accepts the weak candidate — the mutation
        // is only meaningful if this holds.
        let probe = crate::spec::ExecutionSpec::new("probe", crate::spec::IdentityRef::root("probe"))
            .with_requirement(ControlRequirement::prevent(domain));
        assert!(
            negotiate(&probe, &weak.identity, &weak.capabilities, &|_, _| Lowering::none()).is_ok(),
            "the weak candidate must be a negotiate-eligible control for the mutation to prove anything"
        );

        let requirements = RuntimeRequirements::new()
            .with_confinement(ControlRequirement::prevent(domain))
            .with_evidence_minimum(
                domain,
                EvidenceMinimum::none().with_min_failure_posture(FailurePosture::FailClosed),
            );

        let (selection, report) = select(&requirements, &[weak.clone(), strong.clone()]);
        assert_eq!(
            selection,
            Selection::Selected {
                identity: strong.identity.clone(),
                plan: Box::new(evaluate_candidate(&requirements, &strong).expect("strong candidate is eligible")),
            },
            "the weak candidate must be skipped even though it is declared first and negotiate accepts it"
        );
        let weak_verdict = &report.considered[0];
        assert_eq!(weak_verdict.id, "weak");
        assert_eq!(weak_verdict.verdict, CandidateVerdict::RejectedRequirementsUnmet);
        assert_eq!(weak_verdict.unmet_domains, vec![domain]);
    }

    /// The same axis, on the independent `SupportLevel` bar rather than
    /// `FailurePosture`: `Partial` support does not disqualify a prevention
    /// claim in `negotiate` (see `CapabilityReport::can_prevent`'s own doc
    /// comment), but a stated `require_full_support` minimum excludes it here.
    #[test]
    fn a_candidate_negotiate_would_accept_is_excluded_by_a_full_support_minimum() {
        let domain = CapabilityDomain::FilesystemWrite;
        let partial = preventing_candidate(
            "partial",
            &[domain],
            FailurePosture::FailClosed,
            SupportLevel::Partial {
                limitations: vec!["does not cover device nodes".to_string()],
            },
        );
        let full = preventing_candidate("full", &[domain], FailurePosture::FailClosed, SupportLevel::Full);

        let requirements = RuntimeRequirements::new()
            .with_confinement(ControlRequirement::prevent(domain))
            .with_evidence_minimum(domain, EvidenceMinimum::none().with_full_support_required());

        let (selection, _report) = select(&requirements, &[partial, full.clone()]);
        assert_eq!(
            selection,
            Selection::Selected {
                identity: full.identity.clone(),
                plan: Box::new(evaluate_candidate(&requirements, &full).expect("full candidate is eligible")),
            }
        );
    }

    // --- Tie-break: declared order, reproducing today's first-match-wins ---

    #[test]
    fn selects_first_eligible_in_declared_order() {
        let domain = CapabilityDomain::FilesystemWrite;
        let a = preventing_candidate("a", &[domain], FailurePosture::FailClosed, SupportLevel::Full);
        let b = preventing_candidate("b", &[domain], FailurePosture::FailClosed, SupportLevel::Full);
        let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(domain));

        let (selection, _) = select(&requirements, &[a.clone(), b]);
        assert_eq!(
            selection,
            Selection::Selected {
                identity: a.identity.clone(),
                plan: Box::new(evaluate_candidate(&requirements, &a).expect("a is eligible")),
            }
        );
    }

    #[test]
    fn refuses_and_names_every_candidate_when_none_are_eligible() {
        let domain = CapabilityDomain::NetworkEgress;
        let unavailable = Candidate::new(identity("unavailable"), {
            BackendCapabilities::new(
                BackendAvailability::Unavailable {
                    reason: "not installed".to_string(),
                },
                PlatformBoundary::SharedHostKernel,
                Vec::new(),
            )
            .unwrap()
        });
        let inert = Candidate::new(identity("inert"), {
            let reports = CapabilityDomain::ALL
                .iter()
                .map(|&d| CapabilityReport::unsupported(d, "applies no mechanism"))
                .collect();
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .unwrap()
        });
        let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(domain));

        let (selection, report) = select(&requirements, &[unavailable, inert]);
        assert_eq!(selection, Selection::Refused);
        assert_eq!(report.considered.len(), 2);
        assert_eq!(report.considered[0].verdict, CandidateVerdict::RejectedUnavailable);
        assert_eq!(
            report.considered[1].verdict,
            CandidateVerdict::RejectedRequirementsUnmet
        );
    }

    // --- Explicit pin: same eligibility path, explicit failure ---

    #[test]
    fn a_pin_that_cannot_satisfy_requirements_fails_explicitly() {
        let domain = CapabilityDomain::NetworkEgress;
        let inert = Candidate::new(identity("inert"), {
            let reports = CapabilityDomain::ALL
                .iter()
                .map(|&d| CapabilityReport::unsupported(d, "applies no mechanism"))
                .collect();
            BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                reports,
            )
            .unwrap()
        });
        let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(domain));

        let refusal = select_pinned(&requirements, &inert).expect_err("an inert backend cannot prevent network egress");
        assert_eq!(refusal.backend().id, "inert");
        assert_eq!(refusal.unmet().len(), 1);
        assert_eq!(refusal.unmet()[0].0.domain(), domain);
    }

    #[test]
    fn a_pin_that_satisfies_requirements_succeeds() {
        let domain = CapabilityDomain::FilesystemWrite;
        let candidate = preventing_candidate("ok", &[domain], FailurePosture::FailClosed, SupportLevel::Full);
        let requirements = RuntimeRequirements::new().with_confinement(ControlRequirement::prevent(domain));

        let plan = select_pinned(&requirements, &candidate).expect("candidate satisfies the requirement");
        assert_eq!(plan.backend().id, "ok");
    }
}
