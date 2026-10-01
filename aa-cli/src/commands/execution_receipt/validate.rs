//! The receipt's truth-downgrade validation rules (AAASM-6166).
//!
//! [`defects`] answers a question the seal cannot: not "has the byte content
//! changed since it was written" but "even taking the content at face value,
//! is it internally coherent with the evidence discipline ADR 0033 §6 and
//! `aa_isolation::report` already enforce elsewhere". A receipt can carry a
//! perfectly holding seal and still lie — a hand-built body claiming
//! `denied_before_execution` on `setup_only` evidence, freshly re-sealed, has
//! a seal that holds and a claim nothing backs. [`super::verify::verify`] runs
//! both checks, always, and reports them separately.
use super::schema::{DegradedKind, DomainOutcome, ReceiptEnvelope};
use super::text::FieldName;

/// A defect [`defects`] found in a receipt's body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptDefect {
    /// The receipt declares a schema this build does not read.
    #[error("the receipt declares schema `{found}`, which this build does not read")]
    UnknownSchema {
        /// The schema string found.
        found: String,
    },
    /// A field carries a token this build's vocabulary does not recognize.
    ///
    /// Deliberately **not** treated as "the weakest possible value" — several
    /// of the upstream enums this token space mirrors
    /// (`aa_isolation::ControlState`, `UnmeasuredReason`) are
    /// `#[non_exhaustive]`, so a newer build's receipt read by an older one is
    /// a real, not hypothetical, case. There is no way to know which value an
    /// unrecognized token would have matched, so this fails closed rather than
    /// guessing a weak reading.
    #[error("`{field}` carries the token `{token}`, which this build does not recognise")]
    UnrecognizedToken {
        /// The field that carried it.
        field: &'static str,
        /// The token found.
        token: String,
    },
    /// A domain claims coverage on evidence that never reached runtime.
    #[error("domain `{domain}` claims `{claim}` on evidence graded `{basis}`")]
    CoverageWithoutRuntimeEvidence {
        /// The domain.
        domain: String,
        /// The claim term.
        claim: String,
        /// The evidence basis.
        basis: String,
    },
    /// A domain claims prevention with no decision record behind it.
    #[error("domain `{domain}` claims prevention with no decision record behind it")]
    PreventionWithoutDecision {
        /// The domain.
        domain: String,
    },
    /// A domain's prevention flag does not match its recorded evidence grade.
    #[error("domain `{domain}`'s prevention flag does not match its recorded evidence grade")]
    PreventionFlagInconsistent {
        /// The domain.
        domain: String,
    },
    /// A domain claims prevention while also carrying a degraded condition.
    #[error("domain `{domain}` claims prevention and carries a degraded condition")]
    PreventionOverDegradedDomain {
        /// The domain.
        domain: String,
    },
    /// A domain asserts coverage although no execution boundary ran.
    #[error("domain `{domain}` asserts coverage although no execution boundary ran")]
    CoverageWithoutBackend {
        /// The domain.
        domain: String,
    },
    /// A domain's state cannot carry its claim.
    #[error("domain `{domain}`'s state `{state}` cannot carry the claim `{claim}`")]
    StateClaimIncoherent {
        /// The domain.
        domain: String,
        /// The state token.
        state: String,
        /// The claim token.
        claim: String,
    },
    /// The receipt does not name every capability domain.
    #[error("the receipt records {found} domains; every one of the {expected} capability domains must be present")]
    DomainMissing {
        /// How many domains are expected.
        expected: usize,
        /// How many were found.
        found: usize,
    },
    /// A withheld field was not recorded in `withheld_fields`.
    #[error("`{field:?}` was withheld and is not recorded in `withheld_fields`")]
    WithholdingUnrecorded {
        /// The field.
        field: FieldName,
    },
    /// The recorded start is after the recorded end.
    #[error("the recorded start is after the recorded end")]
    TimelineInverted,
    /// A receipt carrying a workspace-transaction binding dropped the
    /// non-transactional-scope disclaimer, or dropped part of it
    /// (AAASM-6162).
    #[error("the workspace binding is missing the scope disclaimer token(s): {missing:?}")]
    WorkspaceScopeDisclaimerMissing {
        /// The [`super::schema::NOT_TRANSACTIONAL`] tokens absent from
        /// `workspace.not_transactional`.
        missing: Vec<String>,
    },
}

/// Whether `claim` asserts coverage, mirroring
/// `aa_core::attestation::ClaimTerm::asserts_coverage`.
fn claim_asserts_coverage(claim: &str) -> Option<bool> {
    match claim {
        "observed" | "detected" | "evaluated" | "denied_before_execution" | "redacted" | "approval_required" => {
            Some(true)
        }
        "degraded" | "unmeasured" | "experimental" | "planned" | "unsupported" => Some(false),
        _ => None,
    }
}

/// Whether `claim` is the one prevention term.
fn claim_is_prevention(claim: &str) -> Option<bool> {
    if claim == "denied_before_execution" {
        return Some(true);
    }
    claim_asserts_coverage(claim).map(|_| false)
}

/// The evidence-basis ladder rank, mirroring
/// `aa_isolation::report::EvidenceBasis`'s declared (and derived `Ord`) order.
fn evidence_basis_rank(basis: &str) -> Option<u8> {
    match basis {
        "none" => Some(0),
        "setup_only" => Some(1),
        "runtime_without_decision" => Some(2),
        "decision" => Some(3),
        _ => None,
    }
}

fn state_asserts_coverage(state: &str) -> Option<bool> {
    match state {
        "unmeasured" | "unsupported" => Some(false),
        "prevention" | "observe_only" | "degraded" => Some(true),
        _ => None,
    }
}

/// Every defect found in `envelope`'s body, in rule order.
///
/// Called only from [`super::verify::verify`] (AAASM-6162 self-review:
/// `project.rs` does not call this at construction time, despite an earlier
/// version of this doc claiming it does — a sealed receipt is written with
/// no defect check, and only a later `aasm receipt verify` run catches one).
pub fn defects(envelope: &ReceiptEnvelope) -> Vec<ReceiptDefect> {
    let mut out = Vec::new();
    let body = &envelope.body;

    // R0: completeness.
    if body.domains.len() != aa_isolation::CapabilityDomain::ALL.len() {
        out.push(ReceiptDefect::DomainMissing {
            expected: aa_isolation::CapabilityDomain::ALL.len(),
            found: body.domains.len(),
        });
    }

    if envelope.schema != super::schema::RECEIPT_SCHEMA {
        out.push(ReceiptDefect::UnknownSchema {
            found: envelope.schema.clone(),
        });
    }

    // R7: timeline.
    if body.execution.started_at_unix_secs > body.execution.ended_at_unix_secs {
        out.push(ReceiptDefect::TimelineInverted);
    }

    for domain in &body.domains {
        check_domain(domain, body, &mut out);
    }

    // R6: withholding is recorded.
    check_withholdings(body, &mut out);

    // R8 (AAASM-6162): a workspace binding must carry the full
    // non-transactional-scope disclaimer — compared as a set, never by
    // length, so a receipt that swaps one token for a duplicate of another
    // still fails.
    if let Some(workspace) = &body.workspace {
        let present: std::collections::BTreeSet<&str> = workspace
            .not_transactional
            .iter()
            .filter_map(super::text::ReceiptText::as_str)
            .collect();
        let missing: Vec<String> = super::schema::NOT_TRANSACTIONAL
            .iter()
            .filter(|token| !present.contains(*token))
            .map(|token| token.to_string())
            .collect();
        if !missing.is_empty() {
            out.push(ReceiptDefect::WorkspaceScopeDisclaimerMissing { missing });
        }
    }

    out
}

fn check_domain(domain: &DomainOutcome, body: &super::schema::ReceiptBody, out: &mut Vec<ReceiptDefect>) {
    let Some(domain_token) = domain.domain.as_str() else {
        return;
    };
    let domain_token = domain_token.to_string();

    let Some(claim) = domain.claim.as_str() else {
        return;
    };
    let Some(basis) = domain.evidence_basis.as_str() else {
        return;
    };
    let Some(state) = domain.state.as_str() else {
        return;
    };

    let Some(asserts_coverage) = claim_asserts_coverage(claim) else {
        out.push(ReceiptDefect::UnrecognizedToken {
            field: "domains[].claim",
            token: claim.to_string(),
        });
        return;
    };
    let Some(basis_rank) = evidence_basis_rank(basis) else {
        out.push(ReceiptDefect::UnrecognizedToken {
            field: "domains[].evidence_basis",
            token: basis.to_string(),
        });
        return;
    };
    let Some(state_covers) = state_asserts_coverage(state) else {
        out.push(ReceiptDefect::UnrecognizedToken {
            field: "domains[].state",
            token: state.to_string(),
        });
        return;
    };
    let is_prevention = match claim_is_prevention(claim) {
        Some(v) => v,
        None => return,
    };

    // R1: coverage needs a runtime fact.
    if asserts_coverage && basis_rank < evidence_basis_rank("runtime_without_decision").unwrap() {
        out.push(ReceiptDefect::CoverageWithoutRuntimeEvidence {
            domain: domain_token.clone(),
            claim: claim.to_string(),
            basis: basis.to_string(),
        });
    }

    // R2: prevention needs a decision, and the flag must agree.
    if is_prevention {
        if basis_rank < evidence_basis_rank("decision").unwrap() {
            out.push(ReceiptDefect::PreventionWithoutDecision {
                domain: domain_token.clone(),
            });
        } else if !domain.prevention_supported {
            out.push(ReceiptDefect::PreventionFlagInconsistent {
                domain: domain_token.clone(),
            });
        }
    }
    // R2b: flag coherence, independent of the claim term.
    if domain.prevention_supported && basis_rank < evidence_basis_rank("decision").unwrap() {
        out.push(ReceiptDefect::PreventionFlagInconsistent {
            domain: domain_token.clone(),
        });
    }

    // R3: degradation caps the claim.
    let domain_degraded = body.degraded.iter().any(|d| {
        d.domain.as_ref().and_then(super::text::ReceiptText::as_str) == Some(domain_token.as_str())
            && matches!(
                d.kind,
                DegradedKind::ControlShortfall
                    | DegradedKind::ControlUnsupported
                    | DegradedKind::NotMeasured
                    | DegradedKind::FieldWithheld
            )
    });
    if domain_degraded && is_prevention {
        out.push(ReceiptDefect::PreventionOverDegradedDomain {
            domain: domain_token.clone(),
        });
    }

    // R4: no backend, no coverage.
    if body.backend.is_none() && asserts_coverage {
        out.push(ReceiptDefect::CoverageWithoutBackend {
            domain: domain_token.clone(),
        });
    }

    // R5: state/claim coherence.
    if !state_covers && asserts_coverage {
        out.push(ReceiptDefect::StateClaimIncoherent {
            domain: domain_token,
            state: state.to_string(),
            claim: claim.to_string(),
        });
    }
}

fn check_withholdings(body: &super::schema::ReceiptBody, out: &mut Vec<ReceiptDefect>) {
    let mut withheld_here: Vec<FieldName> = Vec::new();

    let mut note = |field: FieldName, text: &super::text::ReceiptText| {
        if text.is_withheld() {
            withheld_here.push(field);
        }
    };

    note(FieldName::AssertedIdentityAgentId, &body.asserted_identity.agent_id);
    if let Some(team) = &body.asserted_identity.team_id {
        note(FieldName::AssertedIdentityTeamId, team);
    }
    for lineage in &body.asserted_identity.lineage {
        note(FieldName::AssertedIdentityLineage, lineage);
    }
    if let Some(source) = &body.policy.source {
        note(FieldName::PolicySource, source);
    }
    for unmapped in &body.policy.unmapped {
        note(FieldName::ResidualPolicyGap, unmapped);
    }
    if let Some(backend) = &body.backend {
        note(FieldName::BackendProvenance, &backend.provenance_source);
    }
    if let Some(detail) = &body.execution.no_code_detail {
        note(FieldName::ExitDetail, detail);
    }
    for domain in &body.domains {
        if let Some(detail) = &domain.unmeasured_detail {
            note(FieldName::UnmeasuredDetail, detail);
        }
        for gap in &domain.residual_policy_gaps {
            note(FieldName::ResidualPolicyGap, gap);
        }
    }
    for degraded in &body.degraded {
        note(FieldName::DegradedDetail, &degraded.detail);
    }
    for name in body
        .credentials
        .removed
        .iter()
        .chain(&body.credentials.delegated)
        .chain(&body.credentials.ambient_unremoved)
    {
        note(FieldName::CredentialName, name);
    }

    withheld_here.sort();
    withheld_here.dedup();

    for field in withheld_here {
        if !body.withheld_fields.contains(&field) {
            out.push(ReceiptDefect::WithholdingUnrecorded { field });
        }
    }
}
