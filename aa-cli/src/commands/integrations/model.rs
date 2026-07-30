//! The one model behind both renderings of `aasm integrations` output.
//!
//! # Why these types exist at all
//!
//! The DI-API already answers in projected wire types
//! (`aa_proto::assembly::devint::v1`), and it would be shorter to print those
//! directly and serialize them separately. That is exactly the mistake this
//! module avoids: two renderings built independently from the same source drift,
//! and the first thing to drift is the thing nobody looks at — the JSON a
//! script depends on.
//!
//! So every command converts the wire response into one of the structs below
//! **once**, and both the human table and `--output json` are produced from
//! that struct (see [`super::render::Report`]). A field a human can see is a
//! field a script can read, by construction rather than by discipline.
//!
//! # Why converting is not just `#[derive(Serialize)]` on the wire types
//!
//! Two reasons. The wire types are prost-generated and carry no serde derives,
//! so a stable JSON shape would depend on prost's field naming. And the CLI
//! needs *derived* facts the wire deliberately does not carry — evidence split
//! into exercised and read-back, the protection ladder with its limitations,
//! the assertions a verification establishes. Deriving them here, from the
//! service's own answer, keeps ADR 0030 forbidden design 10 intact: nothing
//! below computes or upgrades a protection state, it only rearranges what the
//! service already decided.
//!
//! # What cannot be here
//!
//! Nothing in this module can hold a rendered settings body, an environment
//! value, a policy document or a capability token, because nothing it is built
//! from can. The wire types have no field for them (§5.5) and these types are
//! built only from those. That is the whole no-sensitive-data argument, and it
//! is a property of the shape rather than of a redaction pass.

use serde::Serialize;

use aa_proto::assembly::devint::v1 as wire;

/// The runtime this command talked to.
///
/// Present on every report so a machine-readable answer always says which core
/// produced it — a status without its provenance invites being cached and
/// re-read as though it were still true.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    /// The negotiated DI-API version.
    pub di_api_version: u32,
    /// The running core's version.
    pub core_version: String,
    /// Whether some verbs are unavailable at the negotiated version.
    pub degraded: bool,
    /// Which verbs, when degraded.
    pub unavailable_verbs: Vec<String>,
    /// Whether this invocation started the runtime.
    pub started_by_this_command: bool,
}

impl RuntimeInfo {
    /// Snapshot what the session negotiated.
    pub fn from_session(session: &super::session::Session) -> Self {
        let negotiated = session.client.negotiated();
        Self {
            di_api_version: negotiated.di_api_version,
            core_version: negotiated.core_version.clone(),
            degraded: negotiated.degraded,
            unavailable_verbs: negotiated.unavailable_verbs.clone(),
            started_by_this_command: session.started_runtime,
        }
    }
}

/// One declared integration mechanism.
#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    /// The mechanism.
    pub capability: String,
    /// `supported` | `unsupported` | `absent`.
    pub support: String,
    /// The adapter's reason, when it declared one.
    pub reason: String,
}

impl From<&wire::CapabilityView> for Capability {
    fn from(view: &wire::CapabilityView) -> Self {
        Self {
            capability: view.capability.clone(),
            support: view.support.clone(),
            reason: view.reason.clone(),
        }
    }
}

/// One row of `aasm integrations list`.
#[derive(Debug, Clone, Serialize)]
pub struct ToolRow {
    /// Stable id, the one every other command takes as `<tool>`.
    pub tool_id: String,
    /// Name to show a user.
    pub display_name: String,
    /// Whether the tool was found on this host.
    pub detected: bool,
    /// The version found, when one was.
    pub detected_version: Option<String>,
    /// How that version compares to the adapter's supported range.
    pub compatibility: String,
    /// The adapter's static build-time ceiling. A ceiling is not a measurement.
    pub adapter_ceiling: String,
    /// Every mechanism the adapter declares.
    pub capabilities: Vec<Capability>,
    /// Where the integration is in its lifecycle, when it has one.
    pub lifecycle_phase: Option<String>,
    /// `ladder` | `drifted` | `degraded` | `incompatible`, when known.
    pub integration_state: Option<String>,
    /// The rung the evidence supports, when known.
    pub achieved_level: Option<String>,
    /// Drift and degradation, in words a user can act on.
    pub warnings: Vec<String>,
}

/// The `list` report.
#[derive(Debug, Clone, Serialize)]
pub struct ToolListReport {
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// One row per tool the linked adapters know about, detected or not.
    pub tools: Vec<ToolRow>,
}

/// One step of a plan, projected for review.
#[derive(Debug, Clone, Serialize)]
pub struct StepRow {
    /// Stable identifier.
    pub id: String,
    /// One line for a human.
    pub summary: String,
    /// The kind of mutation.
    pub action_kind: String,
    /// `required` | `optional`.
    pub requirement: String,
    /// `user` | `privileged_host`.
    pub privilege: String,
    /// The sentence the user must agree to, for privileged steps only.
    pub consent_prompt: Option<String>,
    /// Which settings surface, when the step names one.
    pub settings_scope: Option<String>,
    /// The keys AASM claims — the only keys drift is defined over.
    pub managed_keys: Vec<String>,
    /// Files the step names. Paths, never contents.
    pub artifact_paths: Vec<String>,
    /// SHA-256 of what will be written.
    pub content_sha256: Option<String>,
    /// Whether the step carries an automated reversal.
    pub reversible: bool,
}

impl From<&wire::StepView> for StepRow {
    fn from(view: &wire::StepView) -> Self {
        Self {
            id: view.id.clone(),
            summary: view.summary.clone(),
            action_kind: view.action_kind.clone(),
            requirement: view.requirement.clone(),
            privilege: view.privilege.clone(),
            consent_prompt: non_empty(&view.consent_prompt),
            settings_scope: non_empty(&view.settings_scope),
            managed_keys: view.managed_keys.clone(),
            artifact_paths: view.artifact_paths.clone(),
            content_sha256: non_empty(&view.content_sha256),
            reversible: view.reversible,
        }
    }
}

/// A mechanism this tool cannot use, with the adapter's reason.
#[derive(Debug, Clone, Serialize)]
pub struct UnsupportedRow {
    /// The mechanism.
    pub capability: String,
    /// Why.
    pub reason: String,
}

impl From<&wire::UnsupportedMechanismView> for UnsupportedRow {
    fn from(view: &wire::UnsupportedMechanismView) -> Self {
        Self {
            capability: view.capability.clone(),
            reason: view.reason.clone(),
        }
    }
}

/// The `plan` report, and the preview half of `install`.
#[derive(Debug, Clone, Serialize)]
pub struct PlanReport {
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// The lifecycle schema this plan was authored against.
    pub schema_version: u32,
    /// The id `install` refers to.
    pub plan_id: String,
    /// The tool.
    pub tool_id: String,
    /// The profile chosen.
    pub profile: String,
    /// The settings surface every settings step writes.
    pub settings_scope: String,
    /// The policy profile, by reference. Never the document.
    pub policy_profile: Option<PolicyProfileRow>,
    /// The level this plan intends to reach.
    pub planned_level: String,
    /// The adapter's build-time ceiling.
    pub adapter_ceiling: String,
    /// The material changes, in execution order.
    pub steps: Vec<StepRow>,
    /// Mechanisms this tool cannot use.
    pub unsupported: Vec<UnsupportedRow>,
    /// Anything else to read before approving.
    pub warnings: Vec<String>,
    /// The consent sentences of every privileged step, gathered so the
    /// permissions a user is being asked for are one list rather than something
    /// they must reconstruct by scanning the steps.
    pub required_permissions: Vec<String>,
    /// Whether this report describes a dry run that changed nothing.
    pub mutated: bool,
}

/// A policy profile named by reference.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyProfileRow {
    /// Its id.
    pub id: String,
    /// Name to show a user.
    pub display_name: String,
    /// Content digest, for comparison without disclosure.
    pub digest: String,
}

impl PlanReport {
    /// Build the report from the service's plan.
    pub fn from_view(runtime: RuntimeInfo, view: &wire::PlanView) -> Self {
        let steps: Vec<StepRow> = view.steps.iter().map(StepRow::from).collect();
        Self {
            runtime,
            schema_version: view.schema_version,
            plan_id: view.plan_id.clone(),
            tool_id: view.tool_id.clone(),
            profile: view.profile.clone(),
            settings_scope: view.settings_scope.clone(),
            policy_profile: view.policy_profile.as_ref().map(|p| PolicyProfileRow {
                id: p.id.clone(),
                display_name: p.display_name.clone(),
                digest: p.digest.clone(),
            }),
            planned_level: view.planned_level.clone(),
            adapter_ceiling: view.adapter_ceiling.clone(),
            required_permissions: steps.iter().filter_map(|s| s.consent_prompt.clone()).collect(),
            steps,
            unsupported: view.unsupported.iter().map(UnsupportedRow::from).collect(),
            warnings: view.warnings.clone(),
            mutated: false,
        }
    }
}

/// What one step did when the plan was applied.
#[derive(Debug, Clone, Serialize)]
pub struct StepOutcomeRow {
    /// The step.
    pub step_id: String,
    /// `applied` | `skipped` | `failed`.
    pub outcome: String,
    /// Fingerprint of what was written, when one could be taken.
    pub fingerprint: Option<String>,
}

/// The `install` report.
#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    /// The plan that was applied.
    pub plan: PlanReport,
    /// The receipt now on record.
    pub receipt_id: String,
    /// When, seconds since the Unix epoch.
    pub applied_at_unix_secs: u64,
    /// Per-step outcomes.
    pub steps: Vec<StepOutcomeRow>,
    /// The level the plan intended.
    pub planned_level: String,
    /// The level actually reached.
    pub achieved_level: String,
    /// Whether anything on the host changed. `false` on a repeat install whose
    /// target already holds exactly what the plan describes — the observable
    /// half of idempotence.
    pub mutated: bool,
}

/// One observation behind a protection claim.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceRow {
    /// The mechanism this is evidence about.
    pub mechanism: String,
    /// `read_back` | `exercised` | `host_attested` | `absent`.
    pub kind: String,
    /// The kind's discriminating value.
    pub outcome: String,
    /// When, seconds since the Unix epoch.
    pub observed_at_unix_secs: u64,
    /// Human-readable detail.
    pub detail: String,
}

impl From<&wire::EvidenceView> for EvidenceRow {
    fn from(view: &wire::EvidenceView) -> Self {
        Self {
            mechanism: view.mechanism.clone(),
            kind: view.kind.clone(),
            outcome: view.outcome.clone(),
            observed_at_unix_secs: view.observed_at_unix_secs,
            detail: view.detail.clone(),
        }
    }
}

/// One rung of the protection ladder, with what it does not cover.
///
/// Every rung is listed on every status read, including the ones that are not
/// available — product brief §7.4: "the level must be **named and reported as
/// unavailable**, not hidden. Silence here reads as 'there is nothing above
/// what I have'."
#[derive(Debug, Clone, Serialize)]
pub struct LevelRow {
    /// The rung.
    pub level: String,
    /// Whether the evidence currently supports it.
    pub achieved: bool,
    /// Whether this host can reach it at all.
    pub available: bool,
    /// What it does not protect, or why it is unavailable.
    pub limitation: String,
}

/// The `status` report.
#[derive(Debug, Clone, Serialize)]
pub struct StatusReport {
    /// Which runtime answered — the connectivity half of "evidence-backed".
    pub runtime: RuntimeInfo,
    /// The tool.
    pub tool_id: String,
    /// Where the integration is in its lifecycle.
    pub phase: String,
    /// `ladder` | `drifted` | `degraded` | `incompatible`.
    pub state: String,
    /// The rung the evidence supports.
    pub achieved_level: String,
    /// The rung the applied plan intended.
    pub planned_level: String,
    /// The adapter's build-time ceiling.
    pub adapter_ceiling: String,
    /// How the tool version compares to the adapter's range.
    pub compatibility: String,
    /// When this status was derived. The claim is "verified at T", not "true
    /// now", and dropping this field is how a consumer over-reads it.
    pub observed_at_unix_secs: u64,
    /// Why the state is overriding, when it is.
    pub state_reason: Option<String>,
    /// Which side to fix.
    pub state_remediation: Option<String>,
    /// AASM-owned artifacts that no longer match.
    pub drift_mismatched: Vec<String>,
    /// Whether `aasm integrations repair` has something to do.
    pub repair_available: bool,
    /// The next rung up and why it is not active.
    pub next_level: Option<LevelRow>,
    /// Traffic that was produced and adjudicated. The only evidence that can
    /// justify a claim about behaviour.
    pub exercised_evidence: Vec<EvidenceRow>,
    /// Configuration read back and compared. Justifies at most `integrated`.
    pub read_back_evidence: Vec<EvidenceRow>,
    /// Checks that could not be made, recorded so the gap is legible.
    pub absent_evidence: Vec<EvidenceRow>,
    /// When the last verification ran, when one has.
    pub last_verified_at_unix_secs: Option<u64>,
    /// The whole ladder, including the rungs this host cannot reach.
    pub levels: Vec<LevelRow>,
    /// Mechanisms the adapter cannot substantiate.
    pub unsupported: Vec<UnsupportedRow>,
}

impl StatusReport {
    /// Build the report from the service's status and the tool's capability
    /// declaration.
    ///
    /// `summary` supplies the declared mechanisms, which is where the honest
    /// answer for `host_enforced` comes from — the adapter's own sentence,
    /// rather than a string this CLI made up.
    pub fn from_view(runtime: RuntimeInfo, view: &wire::StatusView, summary: Option<&wire::ToolSummary>) -> Self {
        let split = |kind: &str| -> Vec<EvidenceRow> {
            view.evidence
                .iter()
                .filter(|e| e.kind == kind)
                .map(EvidenceRow::from)
                .collect()
        };
        let exercised_evidence = split("exercised");
        let read_back_evidence = split("read_back");
        let absent_evidence = split("absent");

        let last_verified = view
            .evidence
            .iter()
            .filter(|e| e.kind == "exercised" || e.kind == "read_back")
            .map(|e| e.observed_at_unix_secs)
            .max();

        let unsupported: Vec<UnsupportedRow> = summary
            .map(|s| {
                s.capabilities
                    .iter()
                    .filter(|c| c.support == "unsupported")
                    .map(|c| UnsupportedRow {
                        capability: c.capability.clone(),
                        reason: c.reason.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            tool_id: view.tool_id.clone(),
            phase: view.phase.clone(),
            state: view.state.clone(),
            achieved_level: view.achieved_level.clone(),
            planned_level: view.planned_level.clone(),
            adapter_ceiling: view.adapter_ceiling.clone(),
            compatibility: view.compatibility.clone(),
            observed_at_unix_secs: view.observed_at_unix_secs,
            state_reason: non_empty(&view.state_reason),
            state_remediation: non_empty(&view.state_remediation),
            repair_available: !view.drift_mismatched.is_empty(),
            drift_mismatched: view.drift_mismatched.clone(),
            next_level: view.next_level.as_ref().map(|n| LevelRow {
                achieved: false,
                available: !n.blocked_because.to_ascii_lowercase().contains("unavailable"),
                level: n.level.clone(),
                limitation: n.blocked_because.clone(),
            }),
            levels: ladder(&view.achieved_level, &unsupported),
            exercised_evidence,
            read_back_evidence,
            absent_evidence,
            last_verified_at_unix_secs: last_verified,
            unsupported,
            runtime,
        }
    }
}

/// Rung order, lowest first. Mirrors `ProtectionLevel`'s own ordering, which is
/// load-bearing there and must not be re-derived differently here.
const LADDER: [&str; 6] = [
    "not_installed",
    "detected_not_integrated",
    "partially_integrated",
    "integrated",
    "gateway_protected",
    "host_enforced",
];

/// The three rungs a user is asked to reason about, each with its honest limit.
///
/// The limitation strings are the product brief's §7.1–§7.3 "honest limit" rows.
/// They are stated unconditionally rather than only when a rung is missed,
/// because a user reading `Gateway Protected ✓` needs to know what it still
/// does not cover.
fn ladder(achieved: &str, unsupported: &[UnsupportedRow]) -> Vec<LevelRow> {
    let rank = |name: &str| LADDER.iter().position(|l| *l == name);
    let reached = |name: &str| match (rank(achieved), rank(name)) {
        (Some(a), Some(b)) => a >= b,
        _ => false,
    };
    let host_reason = unsupported
        .iter()
        .find(|u| u.capability == "host_enforcement")
        .map(|u| u.reason.clone())
        .unwrap_or_else(|| "unavailable on this platform".to_string());

    vec![
        LevelRow {
            level: "integrated".to_string(),
            achieved: reached("integrated"),
            available: true,
            limitation: "constrains the tool's startup posture; claims nothing about traffic \
                         and nothing about host-level bypass"
                .to_string(),
        },
        LevelRow {
            level: "gateway_protected".to_string(),
            achieved: reached("gateway_protected"),
            available: true,
            limitation: "protects the paths it sees; an unmanaged launch, a hardcoded endpoint \
                         or a pinned client is outside its scope"
                .to_string(),
        },
        LevelRow {
            level: "host_enforced".to_string(),
            achieved: reached("host_enforced"),
            available: false,
            limitation: host_reason,
        },
    ]
}

/// One machine-readable claim a verification either established or did not.
#[derive(Debug, Clone, Serialize)]
pub struct Assertion {
    /// Stable id a script can branch on.
    pub id: String,
    /// Whether it holds.
    pub holds: bool,
    /// What was observed.
    pub detail: String,
}

/// The `verify` report.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// The tool.
    pub tool_id: String,
    /// When the pass ran.
    pub verified_at_unix_secs: u64,
    /// `passed` | `partially_passed` | `failed` | `unverifiable`.
    pub outcome: String,
    /// What could not be established.
    pub missing: Vec<String>,
    /// Why, for a failure.
    pub reason: Option<String>,
    /// Whether the protected path was actually exercised. **The** question the
    /// command exists to answer: settings that exist are not protection, and a
    /// pass that never exercised anything is not a pass.
    pub protected_path_exercised: bool,
    /// The individual claims, for a script.
    pub assertions: Vec<Assertion>,
    /// Everything observed.
    pub evidence: Vec<EvidenceRow>,
}

impl VerifyReport {
    /// Build the report, deriving the assertions from the service's evidence.
    pub fn from_view(runtime: RuntimeInfo, tool_id: &str, view: &wire::VerificationView) -> Self {
        let exercised: Vec<&wire::EvidenceView> = view.evidence.iter().filter(|e| e.kind == "exercised").collect();
        // "Protective" is the same rule `ExerciseOutcome::is_protective` uses in
        // the core. `observed_only` is deliberately excluded: observing is not
        // protecting, and showing it as protection is the single most likely way
        // for this product to lie (product brief §6.2).
        let protective = exercised
            .iter()
            .any(|e| e.outcome == "redacted" || e.outcome == "blocked");
        let leaked = exercised.iter().any(|e| e.outcome == "leaked");
        let read_back_matched = view
            .evidence
            .iter()
            .any(|e| e.kind == "read_back" && e.outcome == "matched");

        let assertions = vec![
            Assertion {
                id: "protection_test_ran".to_string(),
                holds: !exercised.is_empty(),
                detail: if exercised.is_empty() {
                    "no probe traffic was produced".to_string()
                } else {
                    format!("{} probe observation(s) were adjudicated by the core", exercised.len())
                },
            },
            Assertion {
                id: "protected_path_exercised".to_string(),
                holds: protective,
                detail: if protective {
                    "the synthetic secret was redacted or the request was blocked".to_string()
                } else {
                    "nothing protective was observed on the model-bound path".to_string()
                },
            },
            Assertion {
                id: "no_secret_reached_the_provider".to_string(),
                holds: !leaked,
                detail: if leaked {
                    "the synthetic secret reached the provider unprotected".to_string()
                } else {
                    "no probe was observed reaching a provider unprotected".to_string()
                },
            },
            Assertion {
                id: "configuration_reads_back_as_written".to_string(),
                holds: read_back_matched,
                detail: if read_back_matched {
                    "the managed keys equal what the receipt records".to_string()
                } else {
                    "no matching read-back was recorded".to_string()
                },
            },
        ];

        Self {
            runtime,
            tool_id: tool_id.to_string(),
            verified_at_unix_secs: view.verified_at_unix_secs,
            outcome: view.outcome.clone(),
            missing: view.missing.clone(),
            reason: non_empty(&view.reason),
            protected_path_exercised: protective,
            assertions,
            evidence: view.evidence.iter().map(EvidenceRow::from).collect(),
        }
    }

    /// Whether this verification establishes protection.
    ///
    /// Both halves are required, and the second is the one that stops a vacuous
    /// pass: an outcome of `passed` with nothing exercised is a statement about
    /// configuration wearing a measurement's clothes (ADR 0030 forbidden
    /// design 4).
    pub fn established_protection(&self) -> bool {
        self.outcome == "passed" && self.protected_path_exercised
    }
}

/// The `repair` report.
#[derive(Debug, Clone, Serialize)]
pub struct RepairReport {
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// The tool.
    pub tool_id: String,
    /// Whether this was a preview that changed nothing.
    pub dry_run: bool,
    /// AASM-owned artifacts that drifted, from the status read before repairing.
    pub drifted: Vec<String>,
    /// What was restored.
    pub repaired: Vec<String>,
    /// What could not be, with the reason — including the user's own changes,
    /// which are reported rather than silently left, because "we did not touch
    /// your edits" is information the user needs.
    pub unresolved: Vec<UnsupportedRow>,
    /// The status after the repair, when one ran.
    pub status: Option<Box<StatusReport>>,
}

/// The `remove` report.
#[derive(Debug, Clone, Serialize)]
pub struct RemoveReport {
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// The tool.
    pub tool_id: String,
    /// Whether this was a preview that changed nothing.
    pub dry_run: bool,
    /// The id the executing call refers to.
    pub plan_id: String,
    /// The restoration actions, in order.
    pub steps: Vec<StepRow>,
    /// What removal knowingly leaves behind.
    pub residual: Vec<String>,
    /// Anything else to read first.
    pub warnings: Vec<String>,
}

impl RemoveReport {
    /// Build the report from the service's removal plan.
    pub fn from_view(runtime: RuntimeInfo, view: &wire::RemovalView, dry_run: bool) -> Self {
        Self {
            runtime,
            tool_id: view.tool_id.clone(),
            dry_run,
            plan_id: view.plan_id.clone(),
            steps: view.steps.iter().map(StepRow::from).collect(),
            residual: view.residual.clone(),
            warnings: view.warnings.clone(),
        }
    }
}

/// `None` for an empty proto string, so JSON says `null` rather than `""`.
///
/// proto3 has no optional scalar, so "absent" and "empty" are the same value on
/// the wire. Collapsing them here means a script can test for a field's
/// presence instead of comparing against `""`.
fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> RuntimeInfo {
        RuntimeInfo {
            di_api_version: 2,
            core_version: "0.0.1".to_string(),
            degraded: false,
            unavailable_verbs: Vec::new(),
            started_by_this_command: false,
        }
    }

    fn evidence(kind: &str, outcome: &str) -> wire::EvidenceView {
        wire::EvidenceView {
            mechanism: "managed_settings".to_string(),
            kind: kind.to_string(),
            outcome: outcome.to_string(),
            observed_at_unix_secs: 1_700_000_000,
            detail: "detail".to_string(),
        }
    }

    fn verification(outcome: &str, evidence_views: Vec<wire::EvidenceView>) -> wire::VerificationView {
        wire::VerificationView {
            verified_at_unix_secs: 1_700_000_000,
            outcome: outcome.to_string(),
            missing: Vec::new(),
            reason: String::new(),
            evidence: evidence_views,
        }
    }

    /// The anti-vacuous-pass rule, at the layer that decides the exit code.
    #[test]
    fn a_pass_with_nothing_exercised_does_not_establish_protection() {
        let view = verification("passed", vec![evidence("read_back", "matched")]);
        let report = VerifyReport::from_view(runtime(), "claude-code", &view);
        assert!(!report.protected_path_exercised);
        assert!(
            !report.established_protection(),
            "settings that read back are not a protection measurement"
        );
    }

    #[test]
    fn a_pass_with_protective_traffic_establishes_protection() {
        let view = verification("passed", vec![evidence("exercised", "redacted")]);
        let report = VerifyReport::from_view(runtime(), "claude-code", &view);
        assert!(report.established_protection());
    }

    /// `Observe only` audits and forwards. It is not protection, and the
    /// assertion that says so must not hold for it.
    #[test]
    fn observe_only_traffic_is_not_counted_as_protection() {
        let view = verification("passed", vec![evidence("exercised", "observed_only")]);
        let report = VerifyReport::from_view(runtime(), "claude-code", &view);
        assert!(!report.protected_path_exercised);
        assert!(!report.established_protection());
    }

    #[test]
    fn a_leaked_probe_fails_its_assertion() {
        let view = verification("failed", vec![evidence("exercised", "leaked")]);
        let report = VerifyReport::from_view(runtime(), "claude-code", &view);
        let leak = report
            .assertions
            .iter()
            .find(|a| a.id == "no_secret_reached_the_provider")
            .expect("assertion");
        assert!(!leak.holds);
    }

    fn status_view(achieved: &str) -> wire::StatusView {
        wire::StatusView {
            tool_id: "claude-code".to_string(),
            phase: "installed".to_string(),
            state: "ladder".to_string(),
            achieved_level: achieved.to_string(),
            planned_level: "gateway_protected".to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            compatibility: "compatible".to_string(),
            evidence: vec![evidence("exercised", "redacted"), evidence("read_back", "matched")],
            next_level: None,
            observed_at_unix_secs: 1_700_000_000,
            drift_mismatched: Vec::new(),
            state_reason: String::new(),
            state_remediation: String::new(),
        }
    }

    /// Product brief §7.3: the rung must be *named and reported as unavailable*,
    /// never omitted — silence reads as "there is nothing above what I have".
    #[test]
    fn host_enforced_is_always_present_and_always_unavailable() {
        let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), None);
        let host = report
            .levels
            .iter()
            .find(|l| l.level == "host_enforced")
            .expect("host_enforced must be listed even though it cannot be reached");
        assert!(!host.available);
        assert!(!host.achieved);
        assert!(!host.limitation.is_empty());
    }

    /// Product brief §7.4: exercised and read-back evidence stay separable, so
    /// a user can tell a claim about traffic from a claim about a file.
    #[test]
    fn evidence_is_split_by_how_it_was_obtained() {
        let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), None);
        assert_eq!(report.exercised_evidence.len(), 1);
        assert_eq!(report.read_back_evidence.len(), 1);
        assert!(report.absent_evidence.is_empty());
    }

    #[test]
    fn every_rung_at_or_below_the_achieved_one_is_marked_achieved() {
        let report = StatusReport::from_view(runtime(), &status_view("integrated"), None);
        let achieved: Vec<&str> = report
            .levels
            .iter()
            .filter(|l| l.achieved)
            .map(|l| l.level.as_str())
            .collect();
        assert_eq!(achieved, vec!["integrated"]);
    }

    #[test]
    fn a_host_enforcement_reason_from_the_adapter_is_preferred_over_our_own_wording() {
        let summary = wire::ToolSummary {
            tool_id: "claude-code".to_string(),
            display_name: "Claude Code".to_string(),
            detected: true,
            detected_version: "2.1.220".to_string(),
            compatibility: "compatible".to_string(),
            capabilities: vec![wire::CapabilityView {
                capability: "host_enforcement".to_string(),
                support: "unsupported".to_string(),
                reason: "macOS Endpoint Security is an explicit non-goal".to_string(),
            }],
            adapter_ceiling: "l2_enforce".to_string(),
        };
        let report = StatusReport::from_view(runtime(), &status_view("integrated"), Some(&summary));
        let host = report.levels.iter().find(|l| l.level == "host_enforced").expect("row");
        assert_eq!(host.limitation, "macOS Endpoint Security is an explicit non-goal");
    }

    #[test]
    fn an_empty_proto_string_becomes_null_rather_than_an_empty_string() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("x"), Some("x".to_string()));
    }
}
