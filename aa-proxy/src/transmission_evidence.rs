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
//! Every route to the wire — [`ProxyServer::dial_upstream_tls`], the plain-HTTP
//! dial, and the transparent tunnel — takes a [`ForwardAuthorized`] by value.
//! That token has a private field and is minted in exactly one place:
//! [`ForwardObservation::persist`], **after** the observation it was created
//! with has been handed to the sink.
//!
//! The binding matters more than the unforgeability. An earlier shape issued
//! the token alongside the evidence and left the two separable, so a branch
//! could hold a genuine token, persist some *other* evidence — say a
//! hand-built `NotForwarded` — and still dial: a manufactured prevented
//! transmission for bytes that went on the wire, with nothing to catch it.
//! `persist` closes that by never taking evidence as a parameter. The caller
//! supplies the identifying fields of the record; the evidence written is the
//! observation's own. So the record that reaches the sink and the
//! authorization that reaches the dial necessarily describe the same
//! observation.
//!
//! What this does **not** claim: it does not stop a branch from writing an
//! unrelated second record through [`ProxyServer::emit_audit_entry`], which the
//! refusal branches still need. It guarantees that *the record a dial was
//! authorized by* says the bytes went.
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
//! [`ProxyServer::emit_audit_entry`]: crate::proxy::ProxyServer

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;

use aa_core::policy::EnforcementMode;
use aa_core::types::sensitive_data::{EnforcementPoint, ExecutionEvidence, TransmissionEvidence};
use aa_security::CredentialFinding;

use crate::audit_jsonl::{record_dropped_entry, ProxyAuditDecision, ProxyAuditEntry};
use crate::config::CredentialAction;
use crate::intercept::VerdictDecision;

/// Permission to dial upstream for one request.
///
/// Carries no data: its whole value is that it cannot be constructed outside
/// this module, and the only place that produces one is
/// [`ForwardObservation::persist`], after that observation has been handed to
/// the sink. A branch that observed non-transmission has no way to obtain one,
/// and a branch that persisted a *different* observation has no way to obtain
/// one either.
#[must_use = "a dial authorization exists only to be handed to the dial it authorizes"]
pub struct ForwardAuthorized(());

/// The identifying half of a decision record: everything a
/// [`ProxyAuditEntry`] carries **except** the execution evidence.
///
/// The evidence is deliberately absent. It is supplied by the observation that
/// persists the record, so no caller is in a position to pair one observation's
/// authorization with another observation's evidence.
pub struct DecisionRecord {
    /// Target host, no port.
    pub host: String,
    /// HTTP method of the intercepted request.
    pub method: String,
    /// Request target, **already redacted** by the caller (AAASM-4738).
    pub path: String,
    /// What the proxy resolved to do.
    pub decision: ProxyAuditDecision,
    /// Per-match scanner output.
    pub findings: Vec<CredentialFinding>,
    /// Post-scan body, when the caller has one it is willing to persist.
    pub redacted_body: Option<String>,
    /// Correlation id when this request was a protection probe's own traffic.
    ///
    /// Probe traffic is synthetic: its refusals are real refusals of a request
    /// that was never going to be a leak. A consumer computing a prevention
    /// rate has to be able to exclude it, and can only do that if the record
    /// says so (AAASM-5359/5360).
    pub probe_correlation: Option<String>,
}

impl DecisionRecord {
    /// Attach `execution` and hand the finished entry to the sink.
    ///
    /// `try_send` rather than `send`: a slow JSONL writer must not stall an
    /// intercepted request. Drops are counted so a lossy period is visible
    /// rather than inferred from a gap.
    pub(crate) fn send(self, sink: Option<&mpsc::Sender<ProxyAuditEntry>>, execution: ExecutionEvidence) {
        let Some(tx) = sink else { return };
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let entry = ProxyAuditEntry {
            ts_ms,
            agent_id: None,
            host: self.host,
            method: self.method,
            path: self.path,
            decision: self.decision,
            execution,
            probe_correlation: self.probe_correlation,
            credential_findings: self.findings,
            redacted_body: self.redacted_body,
        };
        if let Err(e) = tx.try_send(entry) {
            let dropped = record_dropped_entry();
            tracing::warn!(
                error = %e,
                dropped_total = dropped,
                "proxy audit jsonl channel full or closed, dropping entry",
            );
        }
    }
}

/// An observation that the proxy resolved to forward these bytes, not yet
/// recorded.
///
/// Produced only by [`forwarded`]. Holds its evidence privately and offers no
/// way to extract the dial authorization except through
/// [`persist`](Self::persist).
#[must_use = "an unpersisted forwarding observation is an unrecorded decision, and yields no dial key"]
pub struct ForwardObservation {
    evidence: ExecutionEvidence,
}

impl ForwardObservation {
    /// What was observed. Read-only — for logging and assertions, never as an
    /// input to the record.
    pub fn evidence(&self) -> ExecutionEvidence {
        self.evidence
    }

    /// Persist this observation and take the key to the wire.
    ///
    /// `record` is `None` for a branch with no decision event to write — a
    /// clean body decided nothing, and inventing an event for it would change
    /// what the audit trail counts. The key is issued either way, because the
    /// invariant is about *what a persisted record says*, not about forcing a
    /// record to exist for traffic there was no decision about.
    ///
    /// The evidence written is [`self.evidence`](Self::evidence). It is not a
    /// parameter, and that is the whole point.
    pub fn persist(
        self,
        sink: Option<&mpsc::Sender<ProxyAuditEntry>>,
        record: Option<DecisionRecord>,
    ) -> ForwardAuthorized {
        if let Some(record) = record {
            record.send(sink, self.evidence);
        }
        ForwardAuthorized(())
    }
}

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

/// Observe that the proxy resolved to forward these bytes.
///
/// Returns the observation, not a dial key: the key comes from
/// [`ForwardObservation::persist`], so the only route to the wire runs through
/// having recorded this observation.
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
pub fn forwarded(
    decision: VerdictDecision,
    action: CredentialAction,
    reinspection: Option<bool>,
) -> ForwardObservation {
    let transmission = match reinspection {
        Some(true) => TransmissionEvidence::ForwardedClean,
        Some(false) => TransmissionEvidence::ForwardedCarryingSensitiveValue,
        None => TransmissionEvidence::ForwardedNotInspected,
    };
    ForwardObservation {
        evidence: ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            transmission,
            observed_mode(decision, action),
        ),
    }
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
                    let evidence = forwarded(decision, action, reinspection).evidence();
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
        let evidence = forwarded(
            VerdictDecision::ForwardRedacted,
            CredentialAction::RedactOnly,
            Some(true),
        )
        .evidence();
        assert_eq!(evidence.transmission, TransmissionEvidence::ForwardedClean);
        assert!(evidence.transmission.proves_transmission());
        assert!(!evidence.establishes_non_transmission());
    }

    /// A redaction that failed to scrub is not protection either — the
    /// evidence is about the bytes, not about what the decision meant to do.
    #[test]
    fn a_redaction_that_did_not_scrub_records_the_payload_still_carrying_a_value() {
        let evidence = forwarded(
            VerdictDecision::ForwardRedacted,
            CredentialAction::RedactOnly,
            Some(false),
        )
        .evidence();
        assert_eq!(
            evidence.transmission,
            TransmissionEvidence::ForwardedCarryingSensitiveValue
        );
        assert!(!evidence.establishes_non_transmission());
    }

    /// An uninspected payload must never read as clean.
    #[test]
    fn an_uninspected_forward_says_so() {
        let evidence = forwarded(VerdictDecision::Forward, CredentialAction::RedactOnly, None).evidence();
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
                out.push(forwarded(decision, action, Some(true)).evidence().enforcement_point);
            }
        }
        out
    }
}
