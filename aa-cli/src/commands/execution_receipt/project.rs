//! Projections from real `aa-isolation`/`aa-policy` types into a
//! [`ReceiptBody`] (AAASM-6166).
//!
//! # Why a projection rather than `#[derive(Serialize)]` on the real types
//!
//! `aa-cli/Cargo.toml` declares `aa-isolation` with no `serde` feature, and
//! this module keeps it off. Three independent reasons, all named honestly
//! here rather than hidden behind a `#[derive]`:
//!
//! 1. **Redaction must cover the digest input, not just the stored fields.**
//!    `ExecutionSpec` holds the full program path and argv;
//!    `RequirementScope::Selectors` holds path globs; `LeaseBasis` holds
//!    free-text reason/policy-rule/approval-ref strings. Serializing the real
//!    types to hash them would put unredacted argv one debug flag from an
//!    output stream — the digest input has to be redacted exactly as the
//!    stored fields are.
//! 2. **`aa_isolation`'s own `lib.rs` documents enabling `serde` as "a
//!    decision to expose a wire contract"** the crate is not ready to make —
//!    several sibling tickets are still reshaping these types.
//! 3. **Non-UTF-8 paths.** `ExecutionSpec::working_dir` is a `PathBuf`;
//!    serde's `Serialize` impl for `PathBuf` fails on non-UTF-8 content, and
//!    nothing upstream of this module checks it — `working_dir_digest` is
//!    computed from the path's raw bytes instead, which never fails.
//!
//! # The residual this cannot close
//!
//! A field added to `ExecutionSpec`/`CapabilityLease`/`RequirementScope`
//! later is not in this projection's digest until someone adds it here — the
//! mirror-struct destructure below only catches a field being *dropped* from
//! this module's own local extraction, the same defect class
//! `run.rs::IsolationPlan::base_spec`'s `BoundLaunchFields` trick closes for
//! itself. It cannot, and does not claim to, catch a field never extracted in
//! the first place.
use std::os::unix::ffi::OsStrExt as _;

use aa_isolation::{
    CapabilityLease, CredentialPosture, EnforcementEvidence, ExecutionSpec, ExitDisposition, IdentityRef,
    IsolationBackend, IsolationReport, RequirementPosture, RequirementScope,
};
use aa_policy::resolve::PolicyResolution;

use super::canonical::{digest_of, CanonicalError, Digest};
use super::host;
use super::schema::{
    AssertedIdentity, BackendBinding, ConsideredBinding, CredentialNames, DegradedCondition, DegradedKind,
    DomainOutcome, EvidenceRef, ExecutionOutcome, LeaseBinding, LeaseProjection, PolicyBinding, ProducerIdentity,
    ReceiptBody, SpecBinding, SpecProjection, TerminationRecord,
};
// `super::schema::TerminationRecord` above is the *stored* shape;
// `TerminationInput` below (defined in this module) is the *raw* shape
// `run_confined` hands in.
use super::text::{FieldName, ReceiptText};

/// Everything `run_confined` knows about one run that this module needs and
/// cannot re-derive.
pub struct ReceiptContext<'a> {
    /// This launch's session/trace ids.
    pub session: &'a aa_isolation::SessionRef,
    /// The spec that was launched.
    pub spec: &'a ExecutionSpec,
    /// The post-run isolation report (already `.with_evidence`-joined).
    pub report: &'a IsolationReport,
    /// The runtime evidence the backend produced.
    pub evidence: &'a EnforcementEvidence,
    /// The backend the launch ran under.
    pub backend: &'a dyn IsolationBackend,
    /// The effective policy this launch resolved.
    pub policy: &'a PolicyResolution,
    /// When the launch started.
    pub started_at: std::time::SystemTime,
    /// When the launch ended.
    pub ended_at: std::time::SystemTime,
    /// How the backend reported the child ended.
    pub disposition: &'a ExitDisposition,
    /// How the launch actually ended, from the supervisor's own knowledge —
    /// not re-derived from `disposition` alone, because only the supervisor
    /// knows whether a deadline or an operator signal was involved.
    pub termination: TerminationInput,
}

/// Raw termination facts, as `run_confined` observes them — screened into a
/// [`TerminationRecord`] by [`execution_outcome`] rather than by the caller,
/// so `run.rs` never has to import this module's redaction types itself.
#[derive(Debug, Clone)]
pub enum TerminationInput {
    /// The child exited on its own, with no ceiling and no forwarded signal.
    SelfExited,
    /// The wall-clock ceiling was exceeded.
    WallClockCeilingExceeded {
        /// The ceiling, in seconds.
        ceiling_secs: u64,
        /// Whether the termination request was delivered.
        termination_delivered: bool,
        /// The backend's own detail, when delivery failed.
        detail: Option<String>,
    },
    /// An operator signal (SIGTERM/SIGINT) was forwarded.
    OperatorRequested {
        /// Whether the forward was delivered successfully.
        forwarded: bool,
    },
}

fn unix_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build this run's [`ReceiptBody`].
pub fn body_for_run(ctx: &ReceiptContext<'_>) -> Result<ReceiptBody, CanonicalError> {
    let mut withheld_fields: Vec<FieldName> = Vec::new();
    let mut degraded: Vec<DegradedCondition> = Vec::new();

    let asserted_identity = identity_binding(ctx.spec.identity(), &mut withheld_fields);
    let policy = policy_binding(ctx.policy, ctx.report, &mut withheld_fields);
    let spec = spec_binding(ctx.spec)?;

    let backend = ctx
        .report
        .backend()
        .map(|identity| backend_binding(identity, ctx.backend, ctx.report.selection(), &mut withheld_fields));

    let host = host::facts(ctx.backend);
    if backend.is_some() {
        degraded.push(DegradedCondition {
            domain: None,
            kind: DegradedKind::FactUnavailable,
            detail: ReceiptText::token("runtime_image: no backend computes a guest/runtime-image digest today"),
        });
    }

    let leases = ctx
        .spec
        .leases()
        .iter()
        .map(lease_binding)
        .collect::<Result<Vec<_>, _>>()?;

    let domains = ctx
        .report
        .domains()
        .iter()
        .map(|projection| domain_outcome(projection, ctx.evidence, &mut withheld_fields, &mut degraded))
        .collect::<Vec<_>>();

    let credentials = credential_names(ctx.spec.credentials(), &mut withheld_fields);
    if ctx.spec.credentials().has_unremoved_ambient_authority() {
        degraded.push(DegradedCondition {
            domain: Some(ReceiptText::token("credential")),
            kind: DegradedKind::UnremovedAmbientAuthority,
            detail: ReceiptText::token("ambient authority reaches the child that policy wanted removed"),
        });
    }

    let execution = execution_outcome(ctx, &mut withheld_fields);

    let evidence_refs = ctx
        .evidence
        .records()
        .iter()
        .map(evidence_ref)
        .collect::<Result<Vec<_>, _>>()?;

    withheld_fields.sort();
    withheld_fields.dedup();

    Ok(ReceiptBody {
        run_id: ctx.session.session_id.clone(),
        trace_id: ctx.session.trace_id.clone(),
        recorded_at_unix_secs: unix_secs(std::time::SystemTime::now()),
        asserted_identity,
        producer: ProducerIdentity::current(),
        policy,
        spec,
        backend,
        host,
        runtime_image: None,
        leases,
        domains,
        credentials,
        workspace: None,
        execution,
        degraded,
        withheld_fields,
        evidence_refs,
    })
}

fn identity_binding(identity: &IdentityRef, withheld: &mut Vec<FieldName>) -> AssertedIdentity {
    let agent_id = ReceiptText::screened(&identity.agent_id);
    if agent_id.is_withheld() {
        withheld.push(FieldName::AssertedIdentityAgentId);
    }
    let team_id = identity.team_id.as_deref().map(ReceiptText::screened);
    if team_id.as_ref().is_some_and(ReceiptText::is_withheld) {
        withheld.push(FieldName::AssertedIdentityTeamId);
    }
    let lineage: Vec<ReceiptText> = identity
        .lineage
        .iter()
        .map(|a| {
            let t = ReceiptText::screened(a);
            if t.is_withheld() {
                withheld.push(FieldName::AssertedIdentityLineage);
            }
            t
        })
        .collect();
    AssertedIdentity {
        agent_id,
        team_id,
        depth: identity.depth(),
        lineage,
    }
}

fn policy_binding(
    resolution: &PolicyResolution,
    report: &IsolationReport,
    withheld: &mut Vec<FieldName>,
) -> PolicyBinding {
    use aa_core::integration::policy_posture::PolicyPosture;

    let (source, canonical_digest) = match resolution {
        PolicyResolution::Enforced { source, canonical, .. }
        | PolicyResolution::Permissive { source, canonical, .. } => {
            let digest = canonical_json_of_policy(canonical);
            (Some(source.display().to_string()), digest)
        }
        PolicyResolution::Unconfigured(_) | PolicyResolution::LoadFailed { .. } => (None, None),
    };

    let source = source.map(|s| {
        let t = ReceiptText::screened(&s);
        if t.is_withheld() {
            withheld.push(FieldName::PolicySource);
        }
        t
    });

    let resolution_token = match resolution.posture() {
        PolicyPosture::Resolved { state, .. } => state.token(),
        PolicyPosture::Unknown { .. } => "unknown",
    };

    let unmapped: Vec<ReceiptText> = report
        .unmapped_policy()
        .iter()
        .map(|s| {
            let t = ReceiptText::screened(s);
            if t.is_withheld() {
                withheld.push(FieldName::ResidualPolicyGap);
            }
            t
        })
        .collect();

    PolicyBinding {
        canonical_digest,
        source,
        resolution: ReceiptText::token(resolution_token),
        unmapped,
    }
}

fn canonical_json_of_policy(doc: &aa_security::policy::PolicyDocument) -> Option<Digest> {
    // `aa_security::policy::PolicyDocument` already derives `Serialize`
    // (`aa-security` is depended on with the `serde` feature) — safe to
    // digest directly: it is the validated canonical AST, not raw operator
    // text, and carries no credential-shaped free text of its own.
    digest_of(doc).ok()
}

fn spec_binding(spec: &ExecutionSpec) -> Result<SpecBinding, CanonicalError> {
    // The mirror-struct/E0027 trick `run.rs::IsolationPlan::base_spec` uses:
    // every field extracted from `spec` here must be named again in the
    // destructure below, or adding a field to this local struct without
    // consuming it is a compile error rather than a silent drop. It cannot
    // catch a field never extracted from `ExecutionSpec` in the first place
    // — see this module's doc comment.
    struct Extracted {
        program: String,
        args: Vec<String>,
        working_dir: Option<std::path::PathBuf>,
        identity_agent_id: String,
        identity_team_id: Option<String>,
        identity_lineage: Vec<String>,
        required_count: usize,
        optional_count: usize,
        degrade_if_unavailable_count: usize,
        lease_ids: Vec<String>,
    }

    let mut required_count = 0usize;
    let mut optional_count = 0usize;
    let mut degrade_if_unavailable_count = 0usize;
    for req in spec.requirements() {
        match req.posture() {
            RequirementPosture::Required => required_count += 1,
            RequirementPosture::Optional => optional_count += 1,
            RequirementPosture::DegradeIfUnavailable => degrade_if_unavailable_count += 1,
        }
    }

    let extracted = Extracted {
        program: spec.program().to_string(),
        args: spec.args().to_vec(),
        working_dir: spec.working_dir().map(std::path::Path::to_path_buf),
        identity_agent_id: spec.identity().agent_id.clone(),
        identity_team_id: spec.identity().team_id.clone(),
        identity_lineage: spec.identity().lineage.clone(),
        required_count,
        optional_count,
        degrade_if_unavailable_count,
        lease_ids: spec.leases().iter().map(|l| l.id().as_str().to_string()).collect(),
    };
    let Extracted {
        program,
        args,
        working_dir,
        identity_agent_id,
        identity_team_id,
        identity_lineage,
        required_count,
        optional_count,
        degrade_if_unavailable_count,
        lease_ids,
    } = extracted;

    let program_basename = std::path::Path::new(&program)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.clone());

    let projection = SpecProjection {
        program: program.clone(),
        arg_count: args.len(),
        working_dir_present: working_dir.is_some(),
        identity_agent_id,
        identity_team_id,
        identity_lineage,
        required_count,
        optional_count,
        degrade_if_unavailable_count,
        lease_ids,
    };
    let digest = digest_of(&projection)?;

    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.clone());
    argv.extend(args.iter().cloned());
    let argv_digest = digest_of(&argv)?;

    let working_dir_digest = working_dir.map(|dir| Digest::of_canonical(&hex_of_bytes(dir.as_os_str().as_bytes())));

    Ok(SpecBinding {
        digest,
        program: ReceiptText::screened(&program_basename),
        arg_count: args.len(),
        argv_digest,
        working_dir_digest,
        required_count,
        optional_count,
        degrade_if_unavailable_count,
    })
}

fn hex_of_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn backend_binding(
    identity: &aa_isolation::BackendIdentity,
    backend: &dyn IsolationBackend,
    selection: Option<&aa_isolation::BackendSelection>,
    withheld: &mut Vec<FieldName>,
) -> BackendBinding {
    let capabilities = backend.capabilities();
    let platform_boundary = host::platform_boundary_token(capabilities.platform_boundary());

    let provenance_source = ReceiptText::screened(&identity.provenance.source);
    if provenance_source.is_withheld() {
        withheld.push(FieldName::BackendProvenance);
    }

    let (selection_mode, considered) = match selection {
        Some(sel) => (
            Some(ReceiptText::token(match sel.mode {
                aa_isolation::SelectionMode::Explicit => "explicit",
                aa_isolation::SelectionMode::Automatic => "automatic",
                aa_isolation::SelectionMode::Default => "default",
            })),
            sel.considered
                .iter()
                .map(|c| ConsideredBinding {
                    id: ReceiptText::screened(&c.id),
                    verdict: ReceiptText::token(c.verdict.as_str()),
                    unmet_domains: c.unmet_domains.iter().map(|d| ReceiptText::token(d.as_str())).collect(),
                })
                .collect(),
        ),
        None => (None, Vec::new()),
    };

    BackendBinding {
        id: ReceiptText::screened(&identity.id),
        version: ReceiptText::screened(&identity.version),
        provenance_source,
        provenance_license: ReceiptText::screened(&identity.provenance.license),
        provenance_modified: identity.provenance.modified,
        platform_boundary: ReceiptText::token(platform_boundary),
        selection_mode,
        considered,
    }
}

fn lease_binding(lease: &CapabilityLease) -> Result<LeaseBinding, CanonicalError> {
    let scope_shape = match lease.scope() {
        RequirementScope::Whole => "whole",
        RequirementScope::Selectors(_) => "selectors",
        RequirementScope::Limits(_) => "limits",
    };
    let scope_selector_count = match lease.scope() {
        RequirementScope::Selectors(sel) => sel.len(),
        _ => 0,
    };
    let revocation = match lease.revocation() {
        aa_isolation::RevocationState::Active { generation } => format!("active:{generation}"),
        aa_isolation::RevocationState::Revoked { generation, .. } => format!("revoked:{generation}"),
    };
    // The basis digests reason/policy_rule/approval_ref together — never
    // stored, never in the lease's own digest input as text, only as this
    // sub-digest. Mirrors `report::DomainAuthoritySummary`'s existing rule.
    let basis_digest = {
        let basis = lease.basis();
        let projected = (
            basis.reason.clone(),
            basis.policy_rule.clone(),
            basis.approval_ref.clone(),
        );
        digest_of(&projected)?.as_str().to_string()
    };

    let projection = LeaseProjection {
        id: lease.id().as_str().to_string(),
        schema_version: lease.schema_version(),
        subject_agent_id: lease.subject().agent_id.clone(),
        domain: lease.domain().as_str(),
        scope_shape,
        scope_selector_count,
        not_before_unix_secs: unix_secs(lease.not_before()),
        expires_at_unix_secs: unix_secs(lease.expires_at()),
        delegation: match lease.delegation() {
            aa_isolation::DelegationRule::NotDelegable => "not_delegable",
            aa_isolation::DelegationRule::DelegableWithNarrowerScope => "delegable_with_narrower_scope",
        },
        revocation,
        basis_digest,
    };
    let digest = digest_of(&projection)?;

    let (derived_from_lease_id, inheritance_mode) = match lease.provenance() {
        Some(p) => (
            Some(ReceiptText::screened(p.parent_lease.as_str())),
            Some(ReceiptText::token(match p.inheritance_mode {
                aa_isolation::InheritanceMode::None => "none",
                aa_isolation::InheritanceMode::Same => "same",
                aa_isolation::InheritanceMode::Narrower => "narrower",
                aa_isolation::InheritanceMode::IndependentlyApproved => "independently_approved",
            })),
        ),
        None => (None, None),
    };

    Ok(LeaseBinding {
        lease_id: ReceiptText::screened(lease.id().as_str()),
        digest,
        domain: ReceiptText::token(lease.domain().as_str()),
        derived_from_lease_id,
        inheritance_mode,
    })
}

fn domain_outcome(
    projection: &aa_isolation::DomainProjection,
    evidence: &EnforcementEvidence,
    withheld: &mut Vec<FieldName>,
    degraded: &mut Vec<DegradedCondition>,
) -> DomainOutcome {
    let domain = projection.domain;

    let (unmeasured_reason, unmeasured_detail) = match &projection.state {
        aa_isolation::ControlState::Unmeasured { reason } => {
            let detail = match reason {
                aa_isolation::UnmeasuredReason::Inconclusive { detail } => {
                    let t = ReceiptText::screened(detail);
                    if t.is_withheld() {
                        withheld.push(FieldName::UnmeasuredDetail);
                    }
                    Some(t)
                }
                _ => None,
            };
            (Some(ReceiptText::token(reason.as_str())), detail)
        }
        _ => (None, None),
    };

    if projection.state.is_shortfall() {
        degraded.push(DegradedCondition {
            domain: Some(ReceiptText::token(domain.as_str())),
            kind: DegradedKind::ControlShortfall,
            detail: ReceiptText::token("achieved control fell short of what policy asked"),
        });
    }
    if matches!(projection.state, aa_isolation::ControlState::Unmeasured { .. }) {
        degraded.push(DegradedCondition {
            domain: Some(ReceiptText::token(domain.as_str())),
            kind: DegradedKind::NotMeasured,
            detail: ReceiptText::token("nothing looked at this domain"),
        });
    }

    let residual_policy_gaps: Vec<ReceiptText> = projection
        .residual_policy_gaps
        .iter()
        .map(|g| {
            let t = ReceiptText::screened(g);
            if t.is_withheld() {
                withheld.push(FieldName::ResidualPolicyGap);
            }
            t
        })
        .collect();

    DomainOutcome {
        domain: ReceiptText::token(domain.as_str()),
        requested: ReceiptText::token(projection.requested.as_str()),
        state: ReceiptText::token(projection.state.as_str()),
        claim: ReceiptText::token(projection.claim.as_str()),
        evidence_basis: ReceiptText::token(projection.evidence.as_str()),
        unmeasured_reason,
        unmeasured_detail,
        residual_policy_gaps,
        prevention_supported: evidence.supports_prevention_claim(domain),
        independently_verified: evidence.is_independently_verified(domain),
    }
}

fn credential_names(posture: &CredentialPosture, withheld: &mut Vec<FieldName>) -> CredentialNames {
    let mut screen = |names: &[String]| -> Vec<ReceiptText> {
        names
            .iter()
            .map(|n| {
                let t = ReceiptText::screened(n);
                if t.is_withheld() {
                    withheld.push(FieldName::CredentialName);
                }
                t
            })
            .collect()
    };
    CredentialNames {
        removed: screen(&posture.removed),
        delegated: screen(&posture.delegated),
        ambient_unremoved: screen(&posture.ambient_unremoved),
    }
}

fn execution_outcome(ctx: &ReceiptContext<'_>, withheld: &mut Vec<FieldName>) -> ExecutionOutcome {
    // `ExitDisposition` is `#[non_exhaustive]` upstream. `.code()` already
    // encodes the exact same match with a wildcard-safe `None` for every
    // unrecognized future variant, so calling it rather than re-matching
    // keeps this in sync with that type's own definition of "no code".
    let exit_code = ctx.disposition.code();
    let no_code_detail = match ctx.disposition {
        ExitDisposition::NoCode { detail } => {
            let t = ReceiptText::screened(detail);
            if t.is_withheld() {
                withheld.push(FieldName::ExitDetail);
            }
            Some(t)
        }
        _ => None,
    };

    let termination = match &ctx.termination {
        TerminationInput::SelfExited => TerminationRecord::SelfExited,
        TerminationInput::WallClockCeilingExceeded {
            ceiling_secs,
            termination_delivered,
            detail,
        } => TerminationRecord::WallClockCeilingExceeded {
            ceiling_secs: *ceiling_secs,
            termination_delivered: *termination_delivered,
            detail: detail.as_deref().map(|d| {
                let t = ReceiptText::screened(d);
                if t.is_withheld() {
                    withheld.push(FieldName::EvidenceRefDetail);
                }
                t
            }),
        },
        TerminationInput::OperatorRequested { forwarded } => {
            TerminationRecord::OperatorRequested { forwarded: *forwarded }
        }
    };

    ExecutionOutcome {
        started_at_unix_secs: unix_secs(ctx.started_at),
        ended_at_unix_secs: unix_secs(ctx.ended_at),
        exit_code,
        no_code_detail,
        termination,
    }
}

fn evidence_ref(record: &aa_isolation::EvidenceRecord) -> Result<EvidenceRef, CanonicalError> {
    Ok(EvidenceRef {
        kind: ReceiptText::token(match record.kind {
            aa_isolation::EvidenceKind::Configured => "configured",
            aa_isolation::EvidenceKind::Installed => "installed",
            aa_isolation::EvidenceKind::Exercised => "exercised",
            aa_isolation::EvidenceKind::IndependentVerification => "independent_verification",
            aa_isolation::EvidenceKind::Decision => "decision",
        }),
        domain: record.domain.map(|d| ReceiptText::token(d.as_str())),
        claim: ReceiptText::token(record.claim.as_str()),
        detail_digest: digest_of(&record.detail)?,
    })
}
