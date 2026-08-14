//! What was actually observed about an inspected action — as evidence, never as
//! a claim.
//!
//! # Why there is no `prevented: bool`
//!
//! ADR 0032 forbidden design #11 puts it directly: calling an outcome
//! "prevented" without execution evidence is not allowed. The reason is
//! specific rather than pedantic. The event type the runtime emits today is
//! named `CredentialLeakBlocked`, and it does not mean blocked — it means
//! *redact*, and redaction **forwards** the scrubbed bytes upstream. A boolean
//! named `prevented` set from that event would have been wrong for the single
//! most common case, and nothing downstream could have noticed.
//!
//! So this module records what was seen and lets the metric be derived. The
//! four conditions ADR 0032 §8 requires before an event counts as prevented
//! transmission are:
//!
//! 1. the enforcement point was **pre-transmission** — [`EnforcementPoint`];
//! 2. the decision was a deny or a transforming disposition —
//!    [`RuntimeVerdictLabel::is_deny_or_transforming`](super::RuntimeVerdictLabel::is_deny_or_transforming),
//!    which lives with the verdict because that is where the answer is;
//! 3. explicit evidence records that the action did not reach its destination —
//!    [`TransmissionEvidence::NotForwarded`];
//! 4. the action was not in observe mode — [`EnforcementMode`].
//!
//! [`ExecutionEvidence`] holds 1, 3 and 4;
//! [`SensitiveDataDecisionEvent::counts_as_prevented_transmission`](super::SensitiveDataDecisionEvent::counts_as_prevented_transmission)
//! adds 2 and is the only place the conjunction is spelled.
//!
//! # The evidence is not yet produced everywhere
//!
//! ADR 0032 §8 is explicit that the observable exists —
//! `aa_proxy::probe_adjudication::ForwardedPayload` — but is produced on only
//! one of the two `dial_upstream_tls` call sites and is never persisted.
//! Generalising and persisting it is AAASM-5358's work, not this ticket's.
//! Until then most events will carry [`TransmissionEvidence::NotRecorded`],
//! which is exactly the point: an unwired path reports *no evidence* and
//! therefore no prevention, rather than defaulting to a flattering answer.

use crate::policy::EnforcementMode;

/// Where in the request's life the decision was applied.
///
/// Condition 1 of the prevention test. A decision taken after the bytes left
/// cannot have stopped them, however restrictive it was — that is detection,
/// which is a different and less valuable thing than prevention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum EnforcementPoint {
    /// The decision was applied before the payload could leave the process or
    /// host — the SDK pre-execution gate, or the proxy before it dials
    /// upstream.
    PreTransmission,
    /// The decision was reached after the payload had already gone: an eBPF
    /// uprobe observing a completed write, or a post-hoc audit scan.
    PostTransmission,
    /// The producing layer did not record where it sat.
    ///
    /// Never satisfies condition 1. An unwired producer must not be able to
    /// claim prevention by saying nothing.
    NotRecorded,
}

impl EnforcementPoint {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PreTransmission => "pre_transmission",
            Self::PostTransmission => "post_transmission",
            Self::NotRecorded => "not_recorded",
        }
    }
}

/// What was observed about the bytes that would have gone to the destination.
///
/// Mirrors `aa_proxy::probe_adjudication::ForwardedPayload`, which is the
/// observable ADR 0032 §8 names, plus a [`NotRecorded`](Self::NotRecorded) for
/// the paths that do not produce it yet. The mirroring is deliberate: this is
/// the vocabulary of the thing that actually knows, and inventing a second one
/// would put a translation step between the evidence and the record of it.
///
/// Like `ForwardedPayload`, this is about **bytes, not about the decision**. A
/// layer that decided to redact but emitted a payload still carrying the
/// credential reports [`ForwardedCarryingSensitiveValue`](Self::ForwardedCarryingSensitiveValue)
/// and must not read as protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum TransmissionEvidence {
    /// There were no bytes to inspect: the request was refused. The only
    /// observation that can support a prevention claim.
    NotForwarded,
    /// Bytes were forwarded and re-inspection found nothing sensitive in them.
    /// This is what a successful redaction looks like — a *transformed
    /// transmission*, not a prevented one.
    ForwardedClean,
    /// Bytes were forwarded and re-inspection still found a sensitive value.
    ForwardedCarryingSensitiveValue,
    /// Bytes were forwarded and nothing re-inspected them, so this layer cannot
    /// say what they carried. Never protective.
    ForwardedNotInspected,
    /// No execution evidence was captured at all.
    ///
    /// The default state of every path AAASM-5358 has not reached yet. Distinct
    /// from [`ForwardedNotInspected`](Self::ForwardedNotInspected), which at
    /// least establishes that bytes went.
    NotRecorded,
}

impl TransmissionEvidence {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotForwarded => "not_forwarded",
            Self::ForwardedClean => "forwarded_clean",
            Self::ForwardedCarryingSensitiveValue => "forwarded_carrying_sensitive_value",
            Self::ForwardedNotInspected => "forwarded_not_inspected",
            Self::NotRecorded => "not_recorded",
        }
    }

    /// Whether the payload is known to have reached the destination.
    ///
    /// `false` for [`NotRecorded`](Self::NotRecorded) — absence of evidence is
    /// not evidence of transmission any more than it is evidence of prevention.
    /// Use [`proves_non_transmission`](Self::proves_non_transmission) for the
    /// other direction rather than negating this one.
    pub const fn proves_transmission(&self) -> bool {
        matches!(
            self,
            Self::ForwardedClean | Self::ForwardedCarryingSensitiveValue | Self::ForwardedNotInspected
        )
    }

    /// Whether the payload is known **not** to have reached the destination.
    ///
    /// True only for [`NotForwarded`](Self::NotForwarded). Deliberately not the
    /// negation of [`proves_transmission`](Self::proves_transmission): both are
    /// `false` for `NotRecorded`, because a path that recorded nothing has
    /// proved nothing in either direction.
    pub const fn proves_non_transmission(&self) -> bool {
        matches!(self, Self::NotForwarded)
    }
}

/// How the detection pass itself terminated.
///
/// ADR 0032 §5 and validation requirement 8: a detection source that could not
/// handle its input must produce an outcome distinguishable from "clean", never
/// a clean result. [`Completed`](Self::Completed) is the *only* value that says
/// detection ran to completion, and it says nothing about whether anything was
/// found — the finding counts do that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[non_exhaustive]
pub enum InspectionFailurePath {
    /// Detection ran to completion. Not a synonym for "found nothing".
    Completed,
    /// Detection could not complete and the action was allowed to proceed.
    FailedOpen,
    /// Detection could not complete and the action was refused.
    FailedClosed,
    /// The primary path could not complete and a reduced one answered instead —
    /// so the result is real but weaker, and a false-positive or false-negative
    /// report has to know that.
    Fallback,
}

impl InspectionFailurePath {
    /// The stable spelling used in events and metric labels.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::FailedOpen => "failed_open",
            Self::FailedClosed => "failed_closed",
            Self::Fallback => "fallback",
        }
    }

    /// Whether detection ran to completion.
    ///
    /// Exists so a reader asks this question instead of `!= FailedOpen`, which
    /// would quietly treat a fallback result as a full one.
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// The record of what happened to the action, assembled from what was observed.
///
/// Holds conditions 1, 3 and 4 of ADR 0032 §8's prevention test. Condition 2 is
/// a property of the verdict and is not duplicated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct ExecutionEvidence {
    /// Where the decision was applied.
    pub enforcement_point: EnforcementPoint,
    /// What was observed about the forwarded bytes.
    pub transmission: TransmissionEvidence,
    /// Whether enforcement was actually applied, or merely computed.
    ///
    /// Reuses [`EnforcementMode`] rather than introducing a third mode
    /// vocabulary. Only [`EnforcementMode::Enforce`] satisfies condition 4:
    /// under `Observe` the decision was computed and audited but never applied,
    /// and under `Disabled` policy evaluation did not run.
    pub mode: EnforcementMode,
}

impl ExecutionEvidence {
    /// Assemble an evidence record.
    pub const fn new(
        enforcement_point: EnforcementPoint,
        transmission: TransmissionEvidence,
        mode: EnforcementMode,
    ) -> Self {
        Self {
            enforcement_point,
            transmission,
            mode,
        }
    }

    /// The state of a path that has not been instrumented yet.
    ///
    /// Nothing observed, nothing claimed. This is the honest default for every
    /// producer AAASM-5358 has not reached, and it can never satisfy
    /// [`establishes_non_transmission`](Self::establishes_non_transmission).
    pub const fn unrecorded(mode: EnforcementMode) -> Self {
        Self::new(EnforcementPoint::NotRecorded, TransmissionEvidence::NotRecorded, mode)
    }

    /// Whether conditions 1, 3 and 4 of the prevention test all hold.
    ///
    /// Not the whole test — the verdict supplies condition 2. A caller wanting
    /// the prevention metric must use
    /// [`SensitiveDataDecisionEvent::counts_as_prevented_transmission`](super::SensitiveDataDecisionEvent::counts_as_prevented_transmission),
    /// which is the only place all four are conjoined.
    pub const fn establishes_non_transmission(&self) -> bool {
        matches!(self.enforcement_point, EnforcementPoint::PreTransmission)
            && self.transmission.proves_non_transmission()
            && matches!(self.mode, EnforcementMode::Enforce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single positive case. Everything else in this module is about the
    /// ways it must *not* hold.
    #[test]
    fn a_pre_transmission_enforced_refusal_establishes_non_transmission() {
        let evidence = ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        );
        assert!(evidence.establishes_non_transmission());
    }

    /// Dropping any one of the three conditions must destroy the claim. Written
    /// as a sweep rather than one happy assertion because a conjunction that
    /// silently loses a clause still passes its positive test.
    #[test]
    fn every_single_condition_is_load_bearing() {
        let base = ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        );

        for point in [EnforcementPoint::PostTransmission, EnforcementPoint::NotRecorded] {
            let weakened = ExecutionEvidence {
                enforcement_point: point,
                ..base
            };
            assert!(
                !weakened.establishes_non_transmission(),
                "a {point:?} decision cannot have stopped bytes that had already gone"
            );
        }

        for transmission in [
            TransmissionEvidence::ForwardedClean,
            TransmissionEvidence::ForwardedCarryingSensitiveValue,
            TransmissionEvidence::ForwardedNotInspected,
            TransmissionEvidence::NotRecorded,
        ] {
            let weakened = ExecutionEvidence { transmission, ..base };
            assert!(
                !weakened.establishes_non_transmission(),
                "{transmission:?} is not proof the payload was withheld"
            );
        }

        for mode in [EnforcementMode::Observe, EnforcementMode::Disabled] {
            let weakened = ExecutionEvidence { mode, ..base };
            assert!(
                !weakened.establishes_non_transmission(),
                "{mode:?} computes a decision without applying it"
            );
        }
    }

    /// A successful redaction is the case the old `CredentialLeakBlocked` name
    /// got wrong: the scrubbed bytes *were* forwarded, so it is a transformed
    /// transmission and must never read as prevention.
    #[test]
    fn a_clean_forwarded_payload_is_a_transmission_not_a_prevention() {
        assert!(TransmissionEvidence::ForwardedClean.proves_transmission());
        assert!(!TransmissionEvidence::ForwardedClean.proves_non_transmission());
    }

    /// Absence of evidence proves nothing in either direction. If the two
    /// predicates were ever made complements, an uninstrumented path would
    /// start claiming one of the two answers for free.
    #[test]
    fn unrecorded_evidence_proves_nothing_in_either_direction() {
        assert!(!TransmissionEvidence::NotRecorded.proves_transmission());
        assert!(!TransmissionEvidence::NotRecorded.proves_non_transmission());
        assert!(!ExecutionEvidence::unrecorded(EnforcementMode::Enforce).establishes_non_transmission());
    }

    /// `Completed` is not a synonym for "clean", and a fallback result is not a
    /// complete one — ADR 0032 §5's rule that a degraded pass never presents as
    /// a full one.
    #[test]
    fn only_a_completed_inspection_reads_as_complete() {
        assert!(InspectionFailurePath::Completed.is_complete());
        for degraded in [
            InspectionFailurePath::FailedOpen,
            InspectionFailurePath::FailedClosed,
            InspectionFailurePath::Fallback,
        ] {
            assert!(!degraded.is_complete(), "{degraded:?} read as a complete inspection");
        }
    }
}

#[cfg(all(test, feature = "serde"))]
mod serde_tests {
    use super::*;

    /// Each vocabulary serializes to exactly its `as_str()`, so the JSON and the
    /// documented spelling cannot drift one variant at a time — the same
    /// discipline `aa-security`'s canonical model applies to its own
    /// vocabularies.
    #[test]
    fn every_evidence_vocabulary_serializes_as_its_as_str() {
        macro_rules! assert_as_str {
            ($($value:expr),* $(,)?) => {
                $(
                    assert_eq!(
                        serde_json::to_string(&$value).unwrap(),
                        alloc::format!("\"{}\"", $value.as_str()),
                        "serialized form diverged from as_str() for {:?}",
                        $value
                    );
                )*
            };
        }

        assert_as_str!(
            EnforcementPoint::PreTransmission,
            EnforcementPoint::PostTransmission,
            EnforcementPoint::NotRecorded,
            TransmissionEvidence::NotForwarded,
            TransmissionEvidence::ForwardedClean,
            TransmissionEvidence::ForwardedCarryingSensitiveValue,
            TransmissionEvidence::ForwardedNotInspected,
            TransmissionEvidence::NotRecorded,
            InspectionFailurePath::Completed,
            InspectionFailurePath::FailedOpen,
            InspectionFailurePath::FailedClosed,
            InspectionFailurePath::Fallback,
        );
    }

    #[test]
    fn execution_evidence_round_trips() {
        let evidence = ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        );
        let json = serde_json::to_string(&evidence).unwrap();
        let restored: ExecutionEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, evidence);
        assert!(restored.establishes_non_transmission());
    }
}
