//! What this proxy *observed* about whether an inspected payload left the
//! process — recorded as evidence, never as a claim.
//!
//! # Why the proxy is one of only two places this can honestly originate
//!
//! Across the product "prevented" is almost never provable. The runtime's
//! `CredentialLeakBlocked` means *redact*, and redaction **forwards** the
//! scrubbed bytes; its scanner runs on an already-reported event, so it is
//! post-transmission by construction. The gateway and this proxy are the only
//! layers that decide **before** the bytes can leave, so they are the only two
//! that can produce [`TransmissionEvidence::NotForwarded`] truthfully
//! (ADR 0032 §8).
//!
//! # The invariant this module exists to make structural
//!
//! [`ForwardAuthorized`] has a private field and is minted by exactly one
//! function — [`forwarded`]. [`ProxyServer::dial_upstream_tls`] and the
//! plain-HTTP dial take one by value. So **no code path can reach the wire
//! while holding evidence that says the payload was withheld**: the key to the
//! dial is only issued together with evidence that says the opposite. That is a
//! compile-time property of the call graph, not a timing coincidence a test has
//! to chase.
//!
//! # Naming rule
//!
//! Every constructor here is named after what was *observed*, never after what
//! policy intended. `not_forwarded` says bytes did not go; it does not say the
//! request was "blocked", because a request can fail to go for reasons that
//! have nothing to do with a security decision — see
//! [`terminated_by_probe_protocol`], which is exactly that case and refuses to
//! attribute its non-transmission to the policy.
//!
//! [`ProxyServer::dial_upstream_tls`]: crate::proxy::ProxyServer

use aa_core::policy::EnforcementMode;
use aa_core::types::sensitive_data::{EnforcementPoint, ExecutionEvidence, TransmissionEvidence};

use crate::config::CredentialAction;
use crate::intercept::VerdictDecision;

/// Permission to dial upstream for one request.
///
/// Carries no data: its whole value is that it cannot be constructed outside
/// this module, and the only function that produces one — [`forwarded`] — also
/// produces evidence that the bytes were forwarded. A branch that observed
/// non-transmission therefore has no way to obtain one.
#[must_use = "a dial authorization exists only to be handed to the dial it authorizes"]
pub struct ForwardAuthorized(());

/// The enforcement mode the observed decision was actually taken under.
///
/// Derived from the decision rather than read off the configured action,
/// because the configured action is an intent and the decision is the
/// observation. The two diverge in both directions:
///
/// * `credential_action=alert_only` still yields
///   [`VerdictDecision::Block`] when a body's `Content-Encoding` cannot be
///   decoded — the refusal really was applied, so that is `Enforce`, and
///   reading `Observe` off the configured action would have thrown away a
///   genuine prevention.
/// * [`VerdictDecision::AlertAndForward`] is the definition of dry-run: a
///   finding was recorded and nothing was applied to the payload.
pub const fn observed_mode(decision: VerdictDecision, action: CredentialAction) -> EnforcementMode {
    match decision {
        // The refusal and the rewrite were both applied to the real payload.
        VerdictDecision::Block | VerdictDecision::ForwardRedacted => EnforcementMode::Enforce,
        // Findings recorded, payload untouched.
        VerdictDecision::AlertAndForward => EnforcementMode::Observe,
        // Nothing was found, so nothing was applied; the regime is whatever the
        // operator configured.
        VerdictDecision::Forward => match action {
            CredentialAction::Block | CredentialAction::RedactOnly => EnforcementMode::Enforce,
            CredentialAction::AlertOnly => EnforcementMode::Observe,
        },
    }
}

/// Evidence for a branch that returns to the client **without** dialling
/// upstream.
///
/// The strongest observation this product can make: the bytes are still here.
/// It is sound only because the branches that use it have no dial after them —
/// and [`ForwardAuthorized`] is what keeps that true as the code changes.
pub const fn not_forwarded(decision: VerdictDecision, action: CredentialAction) -> ExecutionEvidence {
    ExecutionEvidence::new(
        EnforcementPoint::PreTransmission,
        TransmissionEvidence::NotForwarded,
        observed_mode(decision, action),
    )
}

/// Evidence for a rule that refused the request before any credential verdict
/// existed: the egress denylist or network allowlist, an in-tunnel forged
/// `Host`, a plaintext downgrade to an LLM host, or a gateway `tools/call`
/// deny.
///
/// [`EnforcementMode::Enforce`] unconditionally: none of these rules has an
/// observe mode in this proxy — one that matches is applied, and the 403 (or
/// JSON-RPC error envelope) written instead of a dial is the proof.
pub const fn not_forwarded_by_rule() -> ExecutionEvidence {
    ExecutionEvidence::new(
        EnforcementPoint::PreTransmission,
        TransmissionEvidence::NotForwarded,
        EnforcementMode::Enforce,
    )
}

/// Evidence for a request the **probe protocol** terminated, rather than the
/// policy.
///
/// A protection probe's request is answered here and never relayed, whatever
/// the verdict (see [`crate::probe_adjudication`]). Recording that as
/// [`TransmissionEvidence::NotForwarded`] would be true about the bytes and a
/// lie about the cause: under `redact_only` the verdict is transforming, so the
/// four conditions of ADR 0032 §8 would all hold and a probe would manufacture
/// a "prevented transmission" for traffic the policy would in fact have
/// forwarded in redacted form. Every probe run would inflate the one metric the
/// probe exists to measure.
///
/// [`TransmissionEvidence::NotRecorded`] is the honest answer: this path proves
/// nothing in either direction, and `NotRecorded` is defined so that it never
/// can. The enforcement point is still recorded, because that part *was*
/// observed.
pub const fn terminated_by_probe_protocol(decision: VerdictDecision, action: CredentialAction) -> ExecutionEvidence {
    ExecutionEvidence::new(
        EnforcementPoint::PreTransmission,
        TransmissionEvidence::NotRecorded,
        observed_mode(decision, action),
    )
}

/// Evidence for bytes the proxy resolved to forward, plus the authorization to
/// dial.
///
/// `reinspection` is `Some(true)` when the bytes that will go were re-scanned
/// and found free of credentials, `Some(false)` when they still carry one, and
/// `None` when this proxy has no scanner and therefore cannot say. It mirrors
/// [`Interceptor::forwarded_payload_is_clean`](crate::intercept::Interceptor::forwarded_payload_is_clean)
/// exactly, and like it is about **bytes, not about the decision**: a redaction
/// that failed to scrub reports `ForwardedCarryingSensitiveValue` and must not
/// read as protection.
///
/// Recorded at the moment the proxy resolves to forward, which is before the
/// dial and therefore before transmission is strictly observable. If the dial
/// or the write then fails, this over-states transmission — deliberately, since
/// that is the only direction that is safe: an over-stated transmission can
/// never turn a forwarded action into a prevented one, whereas the converse
/// would invent a block that never happened.
#[must_use = "the authorization is the only key to the dial this evidence describes"]
pub fn forwarded(
    decision: VerdictDecision,
    action: CredentialAction,
    reinspection: Option<bool>,
) -> (ExecutionEvidence, ForwardAuthorized) {
    let transmission = match reinspection {
        Some(true) => TransmissionEvidence::ForwardedClean,
        Some(false) => TransmissionEvidence::ForwardedCarryingSensitiveValue,
        None => TransmissionEvidence::ForwardedNotInspected,
    };
    let evidence = ExecutionEvidence::new(
        EnforcementPoint::PreTransmission,
        transmission,
        observed_mode(decision, action),
    );
    (evidence, ForwardAuthorized(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECISIONS: [VerdictDecision; 4] = [
        VerdictDecision::Forward,
        VerdictDecision::ForwardRedacted,
        VerdictDecision::Block,
        VerdictDecision::AlertAndForward,
    ];
    const ACTIONS: [CredentialAction; 3] = [
        CredentialAction::Block,
        CredentialAction::RedactOnly,
        CredentialAction::AlertOnly,
    ];

    /// The invariant the whole module exists for, stated as a sweep: the only
    /// function that mints a dial authorization can never hand back evidence of
    /// non-transmission. Because that function is the *only* way to obtain a
    /// [`ForwardAuthorized`], and the dials take one by value, this is
    /// equivalent to "no dial happens while claiming the bytes stayed here".
    #[test]
    fn authorizing_a_dial_never_yields_non_transmission_evidence() {
        for decision in DECISIONS {
            for action in ACTIONS {
                for reinspection in [Some(true), Some(false), None] {
                    let (evidence, _authorized) = forwarded(decision, action, reinspection);
                    assert!(
                        !evidence.transmission.proves_non_transmission(),
                        "{decision:?}/{action:?}/{reinspection:?} authorized a dial while claiming the payload was withheld"
                    );
                    assert!(
                        evidence.transmission.proves_transmission(),
                        "{decision:?}/{action:?}/{reinspection:?} authorized a dial without recording that bytes went"
                    );
                    assert!(
                        !evidence.establishes_non_transmission(),
                        "{decision:?}/{action:?}/{reinspection:?} would have counted as a prevented transmission"
                    );
                }
            }
        }
    }

    /// A successful redaction is the case the `CredentialLeakBlocked` name got
    /// wrong. The scrubbed bytes *are* forwarded, so the evidence must read as
    /// a transformed transmission.
    #[test]
    fn a_clean_redaction_records_transmitted_not_prevented() {
        let (evidence, _authorized) = forwarded(
            VerdictDecision::ForwardRedacted,
            CredentialAction::RedactOnly,
            Some(true),
        );
        assert_eq!(evidence.transmission, TransmissionEvidence::ForwardedClean);
        assert!(evidence.transmission.proves_transmission());
        assert!(!evidence.establishes_non_transmission());
    }

    /// A redaction that failed to scrub is not protection either — the
    /// evidence is about the bytes, not about what the decision meant to do.
    #[test]
    fn a_redaction_that_did_not_scrub_records_the_payload_still_carrying_a_value() {
        let (evidence, _authorized) = forwarded(
            VerdictDecision::ForwardRedacted,
            CredentialAction::RedactOnly,
            Some(false),
        );
        assert_eq!(
            evidence.transmission,
            TransmissionEvidence::ForwardedCarryingSensitiveValue
        );
        assert!(!evidence.establishes_non_transmission());
    }

    /// An uninspected payload must never read as clean.
    #[test]
    fn an_uninspected_forward_says_so() {
        let (evidence, _authorized) = forwarded(VerdictDecision::Forward, CredentialAction::RedactOnly, None);
        assert_eq!(evidence.transmission, TransmissionEvidence::ForwardedNotInspected);
    }

    /// The single positive case in the crate: an applied refusal, decided
    /// before the dial.
    #[test]
    fn an_enforced_refusal_is_the_only_shape_that_establishes_non_transmission() {
        let evidence = not_forwarded(VerdictDecision::Block, CredentialAction::Block);
        assert_eq!(evidence.transmission, TransmissionEvidence::NotForwarded);
        assert_eq!(evidence.enforcement_point, EnforcementPoint::PreTransmission);
        assert!(evidence.establishes_non_transmission());
    }

    /// A fail-closed refusal under `alert_only` really was applied, so it must
    /// still count. Reading the mode off the configured action instead of the
    /// observed decision would have silently discarded this prevention.
    #[test]
    fn a_fail_closed_refusal_under_alert_only_is_still_an_applied_refusal() {
        assert_eq!(
            observed_mode(VerdictDecision::Block, CredentialAction::AlertOnly),
            EnforcementMode::Enforce
        );
        assert!(not_forwarded(VerdictDecision::Block, CredentialAction::AlertOnly).establishes_non_transmission());
    }

    /// Dry-run must never produce prevention evidence. `AlertAndForward` is
    /// the dry-run decision, and it stays `Observe` under every configured
    /// action — so even if a future branch withheld such a request, the
    /// evidence could not be counted.
    #[test]
    fn an_observed_decision_never_establishes_non_transmission() {
        for action in ACTIONS {
            assert_eq!(
                observed_mode(VerdictDecision::AlertAndForward, action),
                EnforcementMode::Observe,
                "a recorded-but-unapplied decision is dry-run whatever the configured action"
            );
            assert!(
                !not_forwarded(VerdictDecision::AlertAndForward, action).establishes_non_transmission(),
                "a dry-run decision produced prevention evidence under {action:?}"
            );
        }
        assert_eq!(
            observed_mode(VerdictDecision::Forward, CredentialAction::AlertOnly),
            EnforcementMode::Observe
        );
        assert!(!not_forwarded(VerdictDecision::Forward, CredentialAction::AlertOnly).establishes_non_transmission());
    }

    /// An egress refusal is applied unconditionally — there is no observe mode
    /// for the denylist — so it is genuine prevention evidence.
    #[test]
    fn a_rule_refusal_establishes_non_transmission() {
        assert!(not_forwarded_by_rule().establishes_non_transmission());
    }

    /// The trap this module was written to avoid: a probe under `redact_only`
    /// satisfies every other condition of ADR 0032 §8, so attributing its
    /// non-transmission to the policy would let a measurement tool inflate the
    /// very metric it measures.
    #[test]
    fn a_probe_terminated_request_proves_nothing_in_either_direction() {
        for action in ACTIONS {
            for decision in DECISIONS {
                let evidence = terminated_by_probe_protocol(decision, action);
                assert!(
                    !evidence.establishes_non_transmission(),
                    "{decision:?}/{action:?}: the probe protocol, not the policy, withheld these bytes"
                );
                assert!(
                    !evidence.transmission.proves_transmission(),
                    "{decision:?}/{action:?}: nothing was forwarded either"
                );
            }
        }
        // Specifically the redacting case, which is the one that would have
        // passed all four conditions had `NotForwarded` been used.
        let evidence = terminated_by_probe_protocol(VerdictDecision::ForwardRedacted, CredentialAction::RedactOnly);
        assert_eq!(evidence.transmission, TransmissionEvidence::NotRecorded);
        assert_eq!(evidence.mode, EnforcementMode::Enforce);
    }

    /// Every decision point in this crate is pre-transmission — the proxy
    /// decides before its own dial, by definition of where it sits. If a
    /// constructor ever reported otherwise, condition 1 would fail silently.
    #[test]
    fn every_constructor_records_a_pre_transmission_decision() {
        let mut points = alloc_points();
        points.push(not_forwarded_by_rule().enforcement_point);
        for point in points {
            assert_eq!(point, EnforcementPoint::PreTransmission);
        }
    }

    fn alloc_points() -> Vec<EnforcementPoint> {
        let mut out = Vec::new();
        for decision in DECISIONS {
            for action in ACTIONS {
                out.push(not_forwarded(decision, action).enforcement_point);
                out.push(terminated_by_probe_protocol(decision, action).enforcement_point);
                out.push(forwarded(decision, action, Some(true)).0.enforcement_point);
            }
        }
        out
    }
}
