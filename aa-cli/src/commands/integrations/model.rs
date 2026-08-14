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

use aa_runtime::devint::negotiate::DI_API_POLICY_POSTURE_SINCE;
use aa_runtime::devint::provenance::{PeerProvenance, ProvenanceStanding, ProvenanceVerdict, RuntimeMultiplicity};
use serde::Serialize;

use aa_proto::assembly::devint::v1 as wire;

use aa_runtime::devint::ApplyMutation;

use super::exit::{ChangeOutcome, Outcome};

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
    /// Which build answered, and whether it is this one (AAASM-5628).
    pub provenance: RuntimeProvenanceInfo,
}

/// Which build answered, projected for a reader — human or harness.
///
/// This block is the whole point of AAASM-5628 reaching `--output json`: a QA
/// harness records it *beside* the result, so the evidence names the process
/// that produced it instead of asserting that some runtime was reachable. Two
/// checkouts at the same `core_version` are indistinguishable without
/// `build_sha`, and two runtimes of the same build are indistinguishable
/// without `pid`.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeProvenanceInfo {
    /// The three-state result a harness should branch on: `verified` |
    /// `unverifiable` | `refuted` (AAASM-5628).
    ///
    /// Read this rather than [`Self::verdict`] when the question is "may I
    /// record a result from this connection", and read **only** this: it is the
    /// one field that folds in every reason a result may not be attributable.
    /// `unverifiable` is never to be read as verified — two peers that both
    /// carry no build identity have proved only that neither knows what it is —
    /// and it cannot read `verified` while [`Self::reachable_runtimes`] is above
    /// one, because a result from one of several runtimes is not attributable to
    /// a process whatever the identity comparison concluded.
    pub standing: String,
    /// Which specific fact the **identity comparison** produced: `verified` |
    /// `unverifiable` | `mismatch` | `executable_missing` | `not_reported`.
    ///
    /// Narrower than [`Self::standing`] on purpose. It answers "is the peer this
    /// build", which is a different question from "may this result be recorded":
    /// two runtimes compiled from one commit have identical identities, so this
    /// field reads `verified` for both of them. The population is
    /// [`Self::reachable_runtimes`], and `standing` is where the two meet.
    pub verdict: String,
    /// The sentence behind the verdict, so a log carries the reason.
    pub detail: String,
    /// The commit the runtime was built from, when it said.
    pub build_sha: Option<String>,
    /// How `build_sha` was obtained — `injected` | `checkout` | `packaged` |
    /// `absent`. Only the first three can prove a match; `absent` means the SHA
    /// is a placeholder, not an identity.
    pub build_id_source: Option<String>,
    /// What each provenance field did in the comparison, when one ran.
    ///
    /// Present so a reader can see *which* fact was absent, matched or
    /// disagreed, rather than being handed a single opaque verdict.
    pub fields: Vec<ProvenanceFieldInfo>,
    /// The process that answered.
    pub pid: Option<u32>,
    /// The executable it is serving from.
    pub executable_path: Option<String>,
    /// Whether that executable still existed when it answered.
    pub executable_present: Option<bool>,
    /// The checkout it was built from, when it said.
    pub source_path: Option<String>,
    /// When it started serving.
    pub started_at_unix_secs: Option<u64>,
    /// How many runtimes were reachable. Anything above one means this result
    /// cannot be attributed to a single process, whatever the verdict says.
    pub reachable_runtimes: usize,
}

/// One provenance field's contribution to the identity comparison.
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceFieldInfo {
    /// The field, named as it appears on the wire.
    pub field: String,
    /// `matched` | `mismatched` | `absent`.
    pub status: String,
    /// What this `aasm` is.
    pub expected: String,
    /// What the runtime reported.
    pub reported: String,
}

impl RuntimeProvenanceInfo {
    /// Project a verdict and the runtime population it was reached in.
    ///
    /// The standing is **not** `verdict.standing()`. That reports the identity
    /// comparison alone, and `--allow-unverified-runtime` lets a command past
    /// `session::guard_provenance`'s multiplicity refusal — so a run against two
    /// reachable runtimes of one build could publish
    /// `{"standing": "verified", "reachable_runtimes": 2}`, which the CLI
    /// reference tells wrappers is enough to record a result on. ADR 0030 §5.4a
    /// already ratifies "more than one runtime reachable" as a **refuted**
    /// standing — it is one of the three conditions behind exit 10 — so this
    /// only stops the JSON from contradicting it.
    ///
    /// [`Self::verdict`] is left as the identity comparison found it, because
    /// that is what it is for: the standing says whether the result may be
    /// recorded, the verdict says which fact decided, and the multiplicity
    /// sentence is folded into [`Self::detail`] so the pairing is legible rather
    /// than something a reader has to infer from `reachable_runtimes`.
    pub fn new(verdict: &ProvenanceVerdict, multiplicity: &RuntimeMultiplicity, peer: Option<&PeerProvenance>) -> Self {
        let unambiguous = multiplicity.is_unambiguous();
        Self {
            standing: if unambiguous {
                verdict.standing()
            } else {
                ProvenanceStanding::Refuted
            }
            .as_str()
            .to_string(),
            verdict: verdict.as_str().to_string(),
            detail: if unambiguous {
                verdict.detail()
            } else {
                format!("{}; {}", multiplicity.detail(), verdict.detail())
            },
            build_sha: peer.map(|p| p.identity.build_sha.clone()),
            build_id_source: peer.map(|p| p.identity.sha_source.as_str().to_string()),
            fields: verdict
                .comparison()
                .map(|c| {
                    c.fields()
                        .iter()
                        .map(|f| ProvenanceFieldInfo {
                            field: f.field.to_string(),
                            status: f.status.as_str().to_string(),
                            expected: f.expected.clone(),
                            reported: f.reported.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            pid: verdict.pid().or_else(|| peer.map(|p| p.pid)),
            executable_path: peer.map(|p| p.executable_path.clone()),
            executable_present: peer.map(|p| p.executable_present),
            source_path: peer.map(|p| p.source_path.clone()),
            started_at_unix_secs: peer.map(|p| p.started_at_unix_secs),
            reachable_runtimes: multiplicity.reachable_count(),
        }
    }
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
            provenance: RuntimeProvenanceInfo::new(
                &session.provenance,
                &session.multiplicity,
                negotiated.provenance.as_ref(),
            ),
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
    /// Whether this plan has been applied. `false` on a dry run, which is what
    /// lets the human rendering say "nothing has been changed" exactly when
    /// nothing has been.
    pub applied: bool,
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
            applied: false,
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

/// What a completed apply amounts to, on both axes.
///
/// The **single** place `install` decides them, so the exit code, the rendered
/// first line and the JSON `outcome` are three renderings of one verdict rather
/// than three independent derivations that could disagree (AAASM-5674, and the
/// shape AAASM-5499 established for `repair`/`remove`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallVerdict {
    /// What the process exits with.
    pub exit: Outcome,
    /// The ratified change outcome, when one can be stated.
    ///
    /// `None` is the *unknown* case and it is deliberately not a fifth token: a
    /// caller reading `null` cannot mistake it for a word that means something,
    /// whereas any string put here would eventually be branched on as though it
    /// were an answer.
    pub change: Option<ChangeOutcome>,
}

impl InstallVerdict {
    /// Classify from the service's own answers: how many steps it reported as
    /// failed, and what it said about mutation.
    ///
    /// Three rules, in order:
    ///
    /// 1. A step the service reported as **failed** makes the install partial.
    ///    That is a stated fact from the same authority, not an inference from
    ///    an exit code or from local state, and it outranks the mutation
    ///    outcome — a run that did not reach the end state is neither a
    ///    mutation nor a no-op, whatever it touched on the way.
    /// 2. An **authoritative** mutation outcome decides between `changed` and
    ///    `unchanged`, routed through [`ChangeOutcome::of`] so the "success
    ///    outcomes are exactly the zero exits" invariant stays a property of one
    ///    function.
    /// 3. Anything else — the peer could not say, would not say, or was never
    ///    asked — states **no** change outcome. The apply itself succeeded, so
    ///    the exit code is `0`; what did not happen is a claim about the host.
    ///
    /// Rule 3 is the whole point. There is no branch here that turns an absence
    /// into `unchanged`.
    pub fn of(failed_steps: usize, mutation: &ApplyMutation) -> Self {
        if failed_steps > 0 {
            return Self {
                exit: Outcome::InternalError,
                change: Some(ChangeOutcome::of(Outcome::InternalError, false)),
            };
        }
        match mutation {
            ApplyMutation::Failed { .. } => Self {
                exit: Outcome::InternalError,
                change: Some(ChangeOutcome::of(Outcome::InternalError, false)),
            },
            ApplyMutation::Changed | ApplyMutation::Unchanged => Self {
                exit: Outcome::Success,
                change: Some(ChangeOutcome::of(Outcome::Success, mutation.modified_the_host())),
            },
            ApplyMutation::Unsupported { .. } | ApplyMutation::Unknown(_) => Self {
                exit: Outcome::Success,
                change: None,
            },
        }
    }
}

/// The `install` report.
#[derive(Debug, Clone, Serialize)]
pub struct InstallReport {
    /// Whether this run modified anything (AAASM-5674).
    ///
    /// `None` means the runtime did not state an outcome — it is older than
    /// DI-API [`DI_API_APPLY_OUTCOME_SINCE`], it omitted the field, or it said
    /// it could not tell. [`InstallReport::outcome_unknown`] then carries why.
    /// It is **never** `unchanged`: this client does not derive the answer from
    /// the receipt id (reused across a no-op reapply), from
    /// `applied_at_unix_secs` (second-granularity and cross-process), from a
    /// pre-read status (which carries neither id) or from the exit code (which
    /// answers the other axis).
    pub outcome: Option<ChangeOutcome>,
    /// Why no outcome could be stated, when none could.
    ///
    /// Set in the same call as [`InstallReport::outcome`], so a report cannot
    /// claim an outcome while explaining its absence, or the reverse.
    pub outcome_unknown: Option<String>,
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
}

impl InstallReport {
    /// Build the report from what the runtime answered.
    ///
    /// `mutation` must come from
    /// [`Negotiated::apply_mutation`](aa_runtime::devint::Negotiated::apply_mutation),
    /// which is where the version gate lives. Passing a value read straight off
    /// `ApplyView::outcome` would skip it.
    pub fn from_applied(plan: PlanReport, applied: &wire::ApplyView, mutation: &ApplyMutation) -> (Self, Outcome) {
        let steps: Vec<StepOutcomeRow> = applied
            .steps
            .iter()
            .map(|s| StepOutcomeRow {
                step_id: s.step_id.clone(),
                outcome: s.outcome.clone(),
                fingerprint: (!s.fingerprint.is_empty()).then(|| s.fingerprint.clone()),
            })
            .collect();
        let failed = steps.iter().filter(|s| s.outcome == "failed").count();
        let verdict = InstallVerdict::of(failed, mutation);
        let report = Self {
            outcome: verdict.change,
            outcome_unknown: verdict.change.is_none().then(|| mutation.detail()),
            plan,
            receipt_id: applied.receipt_id.clone(),
            applied_at_unix_secs: applied.applied_at_unix_secs,
            steps,
            planned_level: applied.planned_level.clone(),
            achieved_level: applied.achieved_level.clone(),
        };
        (report, verdict.exit)
    }

    /// The steps the runtime reported as failed.
    pub fn failed_steps(&self) -> Vec<&StepOutcomeRow> {
        self.steps.iter().filter(|s| s.outcome == "failed").collect()
    }
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

/// What a status read established about a rung's *reachability*.
///
/// Three states, deliberately not two. Collapsing them is how AAASM-5454
/// happened: "the adapter says this host cannot" and "nobody told us anything"
/// were both rendered as a platform limitation, so the CLI asserted a fact
/// about macOS that it had never established and that was false.
///
/// There is no `Unavailable` variant, and that absence is the point. A claim
/// that a *platform* cannot do something belongs to the adapter, which is the
/// only party that looked; this client can report that claim (it arrives as
/// [`Self::Unsupported`] with the adapter's own sentence) but must never
/// manufacture one.
///
/// Reachability is also not achievement. [`Self::Available`] says a path
/// exists, never that anything was installed, exercised or measured — that is
/// what [`LevelRow::achieved`] is for, and the two must stay separate for the
/// same reason `verify` refuses a vacuous pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LevelAvailability {
    /// The adapter declares the mechanism supported on this host.
    Available,
    /// The adapter declares it unsupported, and said why.
    Unsupported,
    /// Nothing was declared, so nothing is established — in either direction.
    Unmeasured,
}

impl LevelAvailability {
    /// Whether a path to this rung exists on this host.
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
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
    /// Whether this host can reach it at all. Kept as a boolean for scripts
    /// that already branch on it, and derived from [`Self::availability`] in
    /// [`LevelRow::new`] so the two cannot disagree.
    pub available: bool,
    /// What the reading established about reachability, at full resolution.
    pub availability: LevelAvailability,
    /// What it does not protect, or why it is not active.
    pub limitation: String,
}

impl LevelRow {
    /// Build a rung, deriving `available` from `availability`.
    ///
    /// The only constructor, so a caller cannot set a boolean that contradicts
    /// the state next to it.
    fn new(
        level: impl Into<String>,
        achieved: bool,
        availability: LevelAvailability,
        limitation: impl Into<String>,
    ) -> Self {
        Self {
            level: level.into(),
            achieved,
            available: availability.is_available(),
            availability,
            limitation: limitation.into(),
        }
    }
}

/// The policy a governed launch would run under, as this reading could
/// establish it.
///
/// Built from the service's `PolicyView` and the negotiated DI-API version,
/// because those answer two different questions and only both together are
/// honest: *what did the service say*, and *could it have said anything*.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyRow {
    /// `enforced` | `permissive` | `unconfigured` | `load_failed` | `unknown`.
    pub state: String,
    /// The artifact the state came from, when there is one to name.
    pub source: Option<String>,
    /// Operator-facing detail; for `unknown`, why nothing could be established.
    pub detail: String,
    /// Whether a governed launch would be refused. `None` for `unknown` — an
    /// unanswerable question is not a "no", and rendering it as one would show
    /// a refusal nobody measured.
    pub refuses_launch: Option<bool>,
}

impl PolicyRow {
    /// Derive the row from what the service sent and what it was able to send.
    ///
    /// An absent view is **never** read as `unconfigured`. That token is itself
    /// a refusal, so treating "this peer predates the field" as "your policy is
    /// missing" would manufacture a governance finding out of a version
    /// mismatch — the precise confusion AAASM-5349 exists to remove.
    fn from_view(policy: Option<&wire::PolicyView>, di_api_version: u32) -> Self {
        match policy {
            Some(view) => Self {
                state: view.state.clone(),
                source: (!view.source.is_empty()).then(|| view.source.clone()),
                detail: view.detail.clone(),
                refuses_launch: match view.state.as_str() {
                    "unconfigured" | "load_failed" => Some(true),
                    "enforced" | "permissive" => Some(false),
                    // Includes `unknown`, and any token a newer runtime adds
                    // that this build does not recognise. Guessing either way
                    // would be a claim this client is not entitled to make.
                    _ => None,
                },
            },
            None => Self {
                state: "unknown".to_string(),
                source: None,
                detail: if di_api_version < DI_API_POLICY_POSTURE_SINCE {
                    format!(
                        "this runtime speaks DI-API {di_api_version}; the policy posture arrived in \
                         {DI_API_POLICY_POSTURE_SINCE}"
                    )
                } else {
                    format!(
                        "the runtime negotiated DI-API {di_api_version} but sent no policy view; \
                         treat this as a defect rather than as a policy state"
                    )
                },
                refuses_launch: None,
            },
        }
    }
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
    /// Which policy a governed launch would run under (AAASM-5349).
    pub policy: PolicyRow,
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

        // Resolved once, from the adapter's own declaration, and used for both
        // the ladder rung and the `next level up` row. Deriving it twice is how
        // the two came to contradict each other.
        let host_enforcement = host_enforcement_availability(summary);

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
            next_level: view.next_level.as_ref().map(|n| {
                LevelRow::new(
                    n.level.clone(),
                    false,
                    if n.level == HOST_ENFORCED_LEVEL {
                        host_enforcement
                    } else {
                        LevelAvailability::Available
                    },
                    n.blocked_because.clone(),
                )
            }),
            levels: ladder(
                &view.achieved_level,
                host_enforcement,
                host_enforcement_limitation(view, summary, host_enforcement),
            ),
            exercised_evidence,
            read_back_evidence,
            absent_evidence,
            last_verified_at_unix_secs: last_verified,
            unsupported,
            // Read before `runtime` is moved: struct-literal fields evaluate in
            // written order, and the version is what turns an absent view into
            // a nameable reason rather than a shrug.
            policy: PolicyRow::from_view(view.policy.as_ref(), runtime.di_api_version),
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

/// The DI-API's name for the endpoint-managed host-enforcement mechanism.
const HOST_ENFORCEMENT_CAPABILITY: &str = "host_enforcement";

/// The ladder rung that mechanism is the only route to.
const HOST_ENFORCED_LEVEL: &str = "host_enforced";

/// Whether this host can reach `host_enforced`, as **the adapter** answered it.
///
/// The adapter is the only party that looked at the platform, so it is the only
/// party entitled to an answer. Before AAASM-5454 this was the constant
/// `false`, which told every macOS user — the one platform where the mechanism
/// works, since AAASM-5298 — that it was impossible for them.
///
/// Anything other than a declaration this build understands resolves to
/// [`LevelAvailability::Unmeasured`]: `absent` means nobody declared anything,
/// and a token a newer runtime added is one this build must not interpret.
/// Neither is evidence that the host cannot.
fn host_enforcement_availability(summary: Option<&wire::ToolSummary>) -> LevelAvailability {
    match declared_host_enforcement(summary).map(|c| c.support.as_str()) {
        Some("supported") => LevelAvailability::Available,
        Some("unsupported") => LevelAvailability::Unsupported,
        _ => LevelAvailability::Unmeasured,
    }
}

/// The adapter's host-enforcement declaration, when the summary carries one.
fn declared_host_enforcement(summary: Option<&wire::ToolSummary>) -> Option<&wire::CapabilityView> {
    summary.and_then(|s| {
        s.capabilities
            .iter()
            .find(|c| c.capability == HOST_ENFORCEMENT_CAPABILITY)
    })
}

/// The sentence shown beside the `host_enforced` rung.
///
/// Sourced from the adapter wherever the adapter said anything, because only
/// the adapter has looked at this host. Two places carry its words: the
/// capability declaration's reason, and its evidence about the mechanism —
/// where an `absent` row's `outcome` *is* the reason it is not active, and any
/// other kind carries its own detail.
///
/// The fallbacks exist for an adapter that said neither, and none of them
/// asserts a platform limitation. That is the AAASM-5454 defect exactly: the
/// old fallback fired precisely when the mechanism **was** supported — the
/// adapter only lands in the unsupported list when it is not — so the one
/// platform that can reach the rung was the only one told it cannot.
fn host_enforcement_limitation(
    view: &wire::StatusView,
    summary: Option<&wire::ToolSummary>,
    availability: LevelAvailability,
) -> String {
    declared_host_enforcement(summary)
        .and_then(|c| non_empty(&c.reason))
        .or_else(|| {
            view.evidence
                .iter()
                .find(|e| e.mechanism == HOST_ENFORCEMENT_CAPABILITY)
                .and_then(|e| non_empty(if e.kind == "absent" { &e.outcome } else { &e.detail }))
        })
        .unwrap_or_else(|| match availability {
            // Names the command rather than a platform, and stays true whether
            // or not the rung has already been reached: it is how it is reached.
            LevelAvailability::Available => format!(
                "reachable on this host: `aasm integrations install {} --install-managed-settings` \
                 installs the endpoint-managed policy and attests it. Reaching it is one privileged \
                 file write you are asked to authorize",
                view.tool_id
            ),
            LevelAvailability::Unsupported => {
                "this integration declares host enforcement unsupported and gave no reason".to_string()
            }
            LevelAvailability::Unmeasured => {
                "nothing was declared about host enforcement for this tool, so this reading \
                 establishes neither that it can be reached nor that it cannot"
                    .to_string()
            }
        })
}

/// The three rungs a user is asked to reason about, each with its honest limit.
///
/// The limitation strings are the product brief's §7.1–§7.3 "honest limit" rows.
/// They are stated unconditionally rather than only when a rung is missed,
/// because a user reading `Gateway Protected ✓` needs to know what it still
/// does not cover.
fn ladder(achieved: &str, host_enforcement: LevelAvailability, host_limitation: String) -> Vec<LevelRow> {
    let rank = |name: &str| LADDER.iter().position(|l| *l == name);
    let reached = |name: &str| match (rank(achieved), rank(name)) {
        (Some(a), Some(b)) => a >= b,
        _ => false,
    };

    vec![
        LevelRow::new(
            "integrated",
            reached("integrated"),
            LevelAvailability::Available,
            "constrains the tool's startup posture; claims nothing about traffic \
             and nothing about host-level bypass",
        ),
        LevelRow::new(
            "gateway_protected",
            reached("gateway_protected"),
            LevelAvailability::Available,
            "protects the paths it sees; an unmanaged launch, a hardcoded endpoint \
             or a pinned client is outside its scope",
        ),
        LevelRow::new(
            HOST_ENFORCED_LEVEL,
            reached(HOST_ENFORCED_LEVEL),
            host_enforcement,
            host_limitation,
        ),
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
    /// Whether this run modified anything (AAASM-5499).
    ///
    /// `None` on a preview: `--dry-run` reports what a run *would* restore and
    /// establishes nothing about whether the end state already holds. The one
    /// preview that does carry an outcome is the tool with no integration at
    /// all, because that state is settled before any plan is previewed — see
    /// [`RepairReport::nothing_to_repair`].
    pub outcome: Option<ChangeOutcome>,
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
    /// Why this run repaired nothing, when it repaired nothing.
    ///
    /// `Some` is a *stated* no-op: either no receipt accounts for the tool, or
    /// the AASM-owned state already matches the one it has. Both render as an
    /// empty `repaired` list, and an empty list is exactly what a successful
    /// repair of nothing looks like — so the reason is carried explicitly
    /// rather than left to be inferred from which optional blocks are absent
    /// (AAASM-5455). `None` means the run went through the repair verb.
    ///
    /// Since AAASM-5499 this is the *reason* half of an `unchanged` outcome,
    /// not a second way of saying it: it is only ever set by
    /// [`RepairReport::nothing_to_do`], which sets [`RepairReport::outcome`] in
    /// the same call, so the two cannot disagree. The implication runs one way
    /// — a stated reason means `unchanged`, while an `unchanged` run that *did*
    /// send the repair verb and restored nothing has no reason to give beyond
    /// its empty `repaired` list.
    pub nothing_to_repair: Option<String>,
    /// The status after the repair, when one ran.
    pub status: Option<Box<StatusReport>>,
}

impl RepairReport {
    /// A run that never sent the repair verb, because the state it would have
    /// acted on is already the state that was asked for.
    ///
    /// The `unchanged` outcome and the reason are set together here, which is
    /// what makes them one statement rather than two that could drift apart.
    /// `dry_run` does not soften it: this state is settled from the lifecycle
    /// phase or from an empty drift list, both of which are established facts
    /// about the host and not a preview of work.
    pub fn nothing_to_do(
        runtime: RuntimeInfo,
        tool_id: &str,
        dry_run: bool,
        reason: String,
        status: Option<Box<StatusReport>>,
    ) -> Self {
        Self {
            outcome: Some(ChangeOutcome::Unchanged),
            runtime,
            tool_id: tool_id.to_string(),
            dry_run,
            drifted: Vec::new(),
            repaired: Vec::new(),
            unresolved: Vec::new(),
            nothing_to_repair: Some(reason),
            status,
        }
    }

    /// A preview of a repair that has drift to restore.
    ///
    /// Carries no outcome: it changed nothing, but it also did not establish
    /// that the end state already holds — the drift it is previewing is proof
    /// of the opposite — and calling it `failed` because it exits `drifted`
    /// would describe a working preview as a failure.
    pub fn preview(
        runtime: RuntimeInfo,
        tool_id: &str,
        drifted: Vec<String>,
        status: Option<Box<StatusReport>>,
    ) -> Self {
        Self {
            outcome: None,
            runtime,
            tool_id: tool_id.to_string(),
            dry_run: true,
            drifted,
            repaired: Vec::new(),
            unresolved: Vec::new(),
            nothing_to_repair: None,
            status,
        }
    }

    /// A run that sent the repair verb, classified from what it exits with and
    /// what it restored.
    ///
    /// `repaired` is the mutation evidence, and it is the service's own answer
    /// rather than something inferred from the drift that went in: a verb that
    /// ran and restored nothing is `unchanged`, not `changed`.
    pub fn ran(
        runtime: RuntimeInfo,
        tool_id: &str,
        outcome: super::exit::Outcome,
        drifted: Vec<String>,
        repaired: Vec<String>,
        unresolved: Vec<UnsupportedRow>,
        status: Option<Box<StatusReport>>,
    ) -> Self {
        Self {
            outcome: Some(ChangeOutcome::of(outcome, !repaired.is_empty())),
            runtime,
            tool_id: tool_id.to_string(),
            dry_run: false,
            drifted,
            repaired,
            unresolved,
            // The repair verb ran. Whether it restored anything is what
            // `repaired` says; this field is for runs that never got here.
            nothing_to_repair: None,
            status,
        }
    }
}

/// The `remove` report.
#[derive(Debug, Clone, Serialize)]
pub struct RemoveReport {
    /// Whether this run modified anything (AAASM-5499).
    ///
    /// `None` on a preview of a removal that has something to reverse: it
    /// changed nothing, and it established nothing about whether the end state
    /// already holds. A tool with no integration at all is not that preview —
    /// its end state is settled from the lifecycle phase before any plan is
    /// authored — so it reports `unchanged` with or without `--dry-run`.
    pub outcome: Option<ChangeOutcome>,
    /// Which runtime answered.
    pub runtime: RuntimeInfo,
    /// The tool.
    pub tool_id: String,
    /// Whether this was a preview that changed nothing.
    pub dry_run: bool,
    /// The id the executing call refers to, when a plan was authored.
    ///
    /// `None` is a *stated* absence, not a missing value. The service authors a
    /// reversal from an integration receipt and refuses when it holds none, so
    /// a tool with nothing installed has **no** removal plan rather than an
    /// unnamed one — and this command decides that case from the lifecycle
    /// phase without ever sending the Remove verb. Carrying `String::new()` for
    /// it printed `(plan )` to a person and `"plan_id": ""` to a script, which
    /// is indistinguishable from a plan the runtime failed to name
    /// (AAASM-5629).
    ///
    /// Since AAASM-5499 the *outcome* of that state is stated by
    /// [`RemoveReport::outcome`] instead, and this field is back to answering
    /// only the question it names — which plan, if any, was authored. The two
    /// are set in one call ([`RemoveReport::nothing_to_remove`]), so a report
    /// cannot name no plan while claiming to have changed something.
    pub plan_id: Option<String>,
    /// The restoration actions, in order.
    pub steps: Vec<StepRow>,
    /// What removal knowingly leaves behind.
    pub residual: Vec<String>,
    /// Anything else to read first.
    pub warnings: Vec<String>,
}

impl RemoveReport {
    /// A tool with no Agent Assembly integration to remove.
    ///
    /// The end state the caller asked for already holds, which is a success and
    /// a no-op — so `unchanged` is stated here rather than left to be inferred
    /// from a `null` plan id and an empty step list, both of which a reader had
    /// to know the shape of the report to interpret.
    pub fn nothing_to_remove(runtime: RuntimeInfo, tool_id: &str, dry_run: bool, reason: String) -> Self {
        Self {
            outcome: Some(ChangeOutcome::Unchanged),
            runtime,
            tool_id: tool_id.to_string(),
            dry_run,
            // No plan exists to name: the Remove verb is never sent here, and
            // it would refuse anyway — the service authors a reversal from a
            // receipt, and there is none (AAASM-5629).
            plan_id: None,
            steps: Vec::new(),
            residual: Vec::new(),
            warnings: vec![reason],
        }
    }

    /// Build the report from the service's removal plan.
    ///
    /// `dry_run` decides the outcome, and it is the honest reading of what the
    /// two calls mean: the Remove verb without a plan id *authors* the reversal
    /// and mutates nothing, and with one it *executes* it. So a preview reports
    /// no outcome and an execution reports `changed`.
    pub fn from_view(runtime: RuntimeInfo, view: &wire::RemovalView, dry_run: bool) -> Self {
        Self {
            outcome: (!dry_run).then_some(ChangeOutcome::Changed),
            runtime,
            tool_id: view.tool_id.clone(),
            dry_run,
            // proto3 cannot tell an absent string from an empty one, so a
            // runtime that answered without naming the plan is reported as
            // having named none rather than as having named `""`.
            plan_id: non_empty(&view.plan_id),
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

    /// An absent view means the peer could not answer. It must never render as
    /// `unconfigured`: that token is itself a refusal, so reading a version
    /// mismatch as one would manufacture a governance finding out of an old
    /// runtime (AAASM-5349).
    #[test]
    fn an_absent_policy_view_is_unknown_not_unconfigured() {
        let row = PolicyRow::from_view(None, 2);
        assert_eq!(row.state, "unknown");
        assert_ne!(row.state, "unconfigured");
        assert_eq!(row.refuses_launch, None, "an unanswerable question is not a refusal");
    }

    /// The negotiated version is what turns "missing" into a nameable cause.
    #[test]
    fn an_old_peer_is_named_as_the_reason() {
        let row = PolicyRow::from_view(None, 2);
        assert!(
            row.detail.contains("DI-API 2"),
            "must name the peer's version: {}",
            row.detail
        );
        assert!(
            row.detail.contains(&DI_API_POLICY_POSTURE_SINCE.to_string()),
            "must name the version that introduced it: {}",
            row.detail
        );
    }

    /// A current peer that sends nothing is a defect, not a policy state, and
    /// must not be described in the same words as an old one.
    #[test]
    fn a_current_peer_sending_nothing_is_called_a_defect() {
        let row = PolicyRow::from_view(None, DI_API_POLICY_POSTURE_SINCE);
        assert_eq!(row.state, "unknown");
        assert!(row.detail.contains("defect"), "got: {}", row.detail);
    }

    /// Only the two refusing states refuse, and only the two permitting states
    /// permit. Everything else — including a token a newer runtime might add —
    /// is left unanswered rather than guessed.
    #[test]
    fn refusal_is_derived_only_for_tokens_this_build_knows() {
        for (token, expected) in [
            ("enforced", Some(false)),
            ("permissive", Some(false)),
            ("unconfigured", Some(true)),
            ("load_failed", Some(true)),
            ("unknown", None),
            ("some_future_state", None),
        ] {
            let view = wire::PolicyView {
                state: token.to_string(),
                source: String::new(),
                detail: String::new(),
            };
            assert_eq!(
                PolicyRow::from_view(Some(&view), DI_API_POLICY_POSTURE_SINCE).refuses_launch,
                expected,
                "token {token}"
            );
        }
    }

    /// An empty `source` on the wire means "there is no artifact to name", not
    /// "the artifact is called empty string".
    #[test]
    fn an_empty_source_becomes_none_rather_than_an_empty_name() {
        let view = wire::PolicyView {
            state: "unconfigured".to_string(),
            source: String::new(),
            detail: "nothing found".to_string(),
        };
        assert_eq!(PolicyRow::from_view(Some(&view), 3).source, None);
    }

    use super::*;

    fn runtime() -> RuntimeInfo {
        RuntimeInfo {
            di_api_version: 2,
            core_version: "0.0.1".to_string(),
            degraded: false,
            unavailable_verbs: Vec::new(),
            started_by_this_command: false,
            provenance: RuntimeProvenanceInfo {
                standing: "verified".to_string(),
                verdict: "verified".to_string(),
                build_id_source: Some("checkout".to_string()),
                fields: Vec::new(),
                detail: "the Agent Assembly runtime answering is 0.0.1 (abcdef012345) (pid 4242)".to_string(),
                build_sha: Some("abcdef0123456789".to_string()),
                pid: Some(4242),
                executable_path: Some("/build/target/debug/aa-runtime".to_string()),
                executable_present: Some(true),
                source_path: Some("/build".to_string()),
                started_at_unix_secs: Some(1_700_000_000),
                reachable_runtimes: 1,
            },
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
            // These fixtures are about the ladder and its evidence; a `None`
            // policy also exercises the older-peer path, which is the one that
            // must never be read as `unconfigured`.
            policy: None,
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
            policy: None,
        }
    }

    /// A `ToolSummary` declaring exactly one thing about host enforcement.
    fn summary_declaring(support: &str, reason: &str) -> wire::ToolSummary {
        wire::ToolSummary {
            tool_id: "claude-code".to_string(),
            display_name: "Claude Code".to_string(),
            detected: true,
            detected_version: "2.1.220".to_string(),
            compatibility: "compatible".to_string(),
            capabilities: vec![wire::CapabilityView {
                capability: "host_enforcement".to_string(),
                support: support.to_string(),
                reason: reason.to_string(),
            }],
            adapter_ceiling: "l2_enforce".to_string(),
        }
    }

    fn host_rung(report: &StatusReport) -> &LevelRow {
        report
            .levels
            .iter()
            .find(|l| l.level == "host_enforced")
            .expect("host_enforced must be listed whatever the adapter said about it")
    }

    /// Product brief §7.3: the rung is *named*, never omitted — silence reads as
    /// "there is nothing above what I have".
    ///
    /// AAASM-5454: naming it is not licence to invent its answer. Whether this
    /// host can reach it is the adapter's declaration, read straight through.
    /// Hardcoding `false` here told every macOS user that the one platform the
    /// mechanism works on cannot do it.
    #[test]
    fn host_enforced_is_always_present_and_reports_the_adapters_own_availability() {
        for (support, expected) in [
            ("supported", LevelAvailability::Available),
            ("unsupported", LevelAvailability::Unsupported),
            // Nothing was declared. That is not a platform verdict.
            ("absent", LevelAvailability::Unmeasured),
            // A token this build does not know is not one it may interpret.
            ("some_future_token", LevelAvailability::Unmeasured),
        ] {
            let summary = summary_declaring(support, "the adapter's own sentence");
            let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), Some(&summary));
            let host = host_rung(&report);
            assert_eq!(host.availability, expected, "support {support:?}");
            assert_eq!(host.available, expected.is_available(), "support {support:?}");
            assert!(!host.achieved, "support {support:?}");
            assert!(!host.limitation.is_empty(), "support {support:?}");
        }
    }

    /// No summary at all is the same as no declaration: unmeasured, and never a
    /// statement about the platform.
    #[test]
    fn a_status_read_with_no_capability_declaration_leaves_host_enforcement_unmeasured() {
        let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), None);
        assert_eq!(host_rung(&report).availability, LevelAvailability::Unmeasured);
        assert!(!host_rung(&report).available);
    }

    /// Reachable is not reached. A rung the adapter supports and the evidence
    /// has not justified stays `achieved: false` — availability is a statement
    /// about a path, never about a measurement.
    #[test]
    fn an_available_rung_is_not_thereby_an_achieved_one() {
        let summary = summary_declaring("supported", "");
        let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), Some(&summary));
        let host = host_rung(&report);
        assert!(host.available, "the adapter said this host can reach it");
        assert!(!host.achieved, "nothing has established host enforcement here");
        assert!(
            report
                .exercised_evidence
                .iter()
                .all(|e| e.mechanism != "host_enforcement"),
            "the fixture must not smuggle in host-enforcement evidence"
        );
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
        let summary = summary_declaring("unsupported", "macOS Endpoint Security is an explicit non-goal");
        let report = StatusReport::from_view(runtime(), &status_view("integrated"), Some(&summary));
        assert_eq!(
            host_rung(&report).limitation,
            "macOS Endpoint Security is an explicit non-goal"
        );
    }

    /// The adapter says why the rung is not active through its *evidence* as
    /// well as its capability declaration — an `absent` row's outcome is that
    /// sentence. A supported mechanism carries no capability reason, so this is
    /// the branch that supplies the adapter's own words on macOS.
    #[test]
    fn a_supported_rung_takes_its_sentence_from_the_adapters_absent_evidence() {
        let mut view = status_view("gateway_protected");
        view.evidence.push(wire::EvidenceView {
            mechanism: "host_enforcement".to_string(),
            kind: "absent".to_string(),
            outcome: "host enforcement is not active: no endpoint-managed settings file was verified. \
                      Install it with `aasm integrations install claude-code --install-managed-settings`"
                .to_string(),
            observed_at_unix_secs: 1_700_000_000,
            detail: "known bypasses this integration cannot observe".to_string(),
        });
        let summary = summary_declaring("supported", "");
        let report = StatusReport::from_view(runtime(), &view, Some(&summary));
        let host = host_rung(&report);
        assert!(host.available);
        assert!(
            host.limitation.starts_with("host enforcement is not active"),
            "the adapter's own sentence was replaced: {}",
            host.limitation
        );
        assert!(
            host.limitation.contains("--install-managed-settings"),
            "the reachable path was not named: {}",
            host.limitation
        );
    }

    /// AAASM-5454's second bug: the fallback fired exactly when the mechanism
    /// *was* supported, and asserted a platform limitation nobody established.
    /// No fallback may say anything about a platform, in any state.
    #[test]
    fn no_fallback_asserts_a_platform_limitation() {
        for support in ["supported", "unsupported", "absent"] {
            // No capability reason and no host-enforcement evidence: every
            // branch below is this client's own wording.
            let summary = summary_declaring(support, "");
            let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), Some(&summary));
            let limitation = host_rung(&report).limitation.to_ascii_lowercase();
            assert!(!limitation.is_empty(), "support {support:?}");
            for forbidden in [
                "unavailable on this platform",
                "on this platform",
                "not supported by macos",
            ] {
                assert!(
                    !limitation.contains(forbidden),
                    "support {support:?} claimed {forbidden:?}: {limitation}"
                );
            }
        }
    }

    /// A plan from an adapter that either did or did not rule host enforcement
    /// out.
    fn plan_view(declares_unsupported: bool) -> wire::PlanView {
        wire::PlanView {
            schema_version: 1,
            plan_id: "plan-1".to_string(),
            tool_id: "claude-code".to_string(),
            profile: "recommended".to_string(),
            settings_scope: "managed".to_string(),
            policy_profile: None,
            planned_level: if declares_unsupported {
                "gateway_protected"
            } else {
                "host_enforced"
            }
            .to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            steps: Vec::new(),
            unsupported: if declares_unsupported {
                vec![wire::UnsupportedMechanismView {
                    capability: "host_enforcement".to_string(),
                    reason: "the adapter's own sentence".to_string(),
                }]
            } else {
                Vec::new()
            },
            warnings: Vec::new(),
        }
    }

    /// The two surfaces a user compares must not contradict each other.
    ///
    /// AAASM-5454 was reported as exactly this contradiction, on one host in
    /// one minute: `plan` answered `planned level: host_enforced` while
    /// `status` answered `unavailable on this platform`. Both derive from the
    /// same adapter declaration, so both must reach the same answer.
    #[test]
    fn plan_and_status_agree_on_whether_host_enforcement_is_reachable() {
        for (support, reachable) in [("supported", true), ("unsupported", false)] {
            let plan = PlanReport::from_view(runtime(), &plan_view(!reachable));
            let status = StatusReport::from_view(
                runtime(),
                &status_view("integrated"),
                Some(&summary_declaring(support, "the adapter's own sentence")),
            );

            let plan_says_reachable = !plan.unsupported.iter().any(|u| u.capability == "host_enforcement");
            let status_says_reachable = host_rung(&status).available;

            assert_eq!(
                plan_says_reachable, reachable,
                "the plan fixture is wrong for {support:?}"
            );
            assert_eq!(
                status_says_reachable, plan_says_reachable,
                "plan and status disagree about host enforcement for a {support:?} adapter: \
                 plan reachable={plan_says_reachable}, status reachable={status_says_reachable}"
            );
        }
    }

    /// A supported-but-not-yet-reached rung must tell the user how to reach it,
    /// even when the adapter volunteered nothing.
    #[test]
    fn the_available_fallback_names_the_command_that_reaches_the_rung() {
        let summary = summary_declaring("supported", "");
        let report = StatusReport::from_view(runtime(), &status_view("gateway_protected"), Some(&summary));
        let limitation = &host_rung(&report).limitation;
        assert!(
            limitation.contains("aasm integrations install claude-code --install-managed-settings"),
            "the reachable path was not named: {limitation}"
        );
    }

    #[test]
    fn an_empty_proto_string_becomes_null_rather_than_an_empty_string() {
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty("x"), Some("x".to_string()));
    }

    // ---- AAASM-5628: the standing folds in the runtime population ------------

    /// A verdict that positively identified the peer as this build.
    fn verified_verdict() -> ProvenanceVerdict {
        use aa_runtime::devint::provenance::{BuildIdentity, IdentitySource};

        ProvenanceVerdict::Verified {
            pid: 4242,
            identity: BuildIdentity {
                core_version: "0.0.1".to_string(),
                build_sha: "a".repeat(40),
                sha_source: IdentitySource::Checkout,
            },
            proved_by: "build_sha",
        }
    }

    /// The population `count` reachable sockets in one directory produce.
    fn reachable(count: usize) -> RuntimeMultiplicity {
        use std::path::PathBuf;

        let all: Vec<PathBuf> = (0..count)
            .map(|i| PathBuf::from(format!("/run/devint-{i}.sock")))
            .collect();
        aa_runtime::devint::provenance::multiplicity(&all[0], &all)
    }

    /// `standing` is the field the published wrapper guidance branches on, so
    /// it must not read `verified` for a result that came from one of several
    /// runtimes.
    ///
    /// Reachable only through `--allow-unverified-runtime`, which bypasses
    /// `session::guard_provenance`'s multiplicity refusal — and that flag is
    /// documented as changing whether a command proceeds, never what it
    /// reports. Two runtimes compiled from one commit have identical
    /// identities, so no identity comparison can notice there are two: the
    /// verdict below is `verified` and must stay so.
    #[test]
    fn a_result_from_one_of_several_runtimes_is_never_standing_verified() {
        let single = RuntimeProvenanceInfo::new(&verified_verdict(), &reachable(1), None);
        assert_eq!(single.standing, "verified");
        assert_eq!(single.reachable_runtimes, 1);

        let ambiguous = RuntimeProvenanceInfo::new(&verified_verdict(), &reachable(2), None);
        assert_eq!(ambiguous.reachable_runtimes, 2);
        assert_ne!(
            ambiguous.standing, "verified",
            "a result that cannot be attributed to a process was published as verified"
        );
        assert_eq!(
            ambiguous.standing, "refuted",
            "ADR 0030 §5.4a ratifies more-than-one-reachable as a positive finding"
        );
        assert_eq!(
            ambiguous.verdict, "verified",
            "the identity comparison itself is unchanged — it cannot see a duplicate"
        );
        assert!(
            ambiguous.detail.contains("2 Agent Assembly runtimes"),
            "the standing must carry its reason: {}",
            ambiguous.detail
        );
    }

    /// The JSON a harness records, asserted as a pair: the exact shape the CLI
    /// reference's `jq -e '.runtime.provenance.standing == "verified"'` snippet
    /// would otherwise accept from an ambiguous host.
    #[test]
    fn the_json_never_pairs_a_verified_standing_with_a_second_runtime() {
        let info = RuntimeProvenanceInfo::new(&verified_verdict(), &reachable(2), None);
        let json = serde_json::to_value(&info).expect("serialize");
        assert_eq!(json["reachable_runtimes"], serde_json::json!(2));
        assert_ne!(json["standing"], serde_json::json!("verified"));
    }

    // ── install's change outcome (AAASM-5674) ───────────────────────────────

    use aa_runtime::devint::{ApplyMutation, MutationUnknown};

    use super::{InstallReport, InstallVerdict};

    /// A stated mutation decides between the two success outcomes, and only
    /// between those two.
    #[test]
    fn a_stated_mutation_decides_changed_from_unchanged() {
        let changed = InstallVerdict::of(0, &ApplyMutation::Changed);
        assert_eq!(changed.exit, Outcome::Success);
        assert_eq!(changed.change, Some(ChangeOutcome::Changed));

        let unchanged = InstallVerdict::of(0, &ApplyMutation::Unchanged);
        assert_eq!(unchanged.exit, Outcome::Success);
        assert_eq!(unchanged.change, Some(ChangeOutcome::Unchanged));
    }

    /// A stated failure is a failure on both axes.
    #[test]
    fn a_stated_failure_exits_non_zero_and_reports_failed() {
        let verdict = InstallVerdict::of(
            0,
            &ApplyMutation::Failed {
                detail: "the settings write did not land".to_string(),
            },
        );
        assert_ne!(verdict.exit.code(), 0);
        assert_eq!(verdict.change, Some(ChangeOutcome::Failed));
    }

    /// **The load-bearing case.** Every way of not having an answer produces
    /// *no* outcome — never `unchanged`, and never any other success.
    ///
    /// Swept across all five non-answers rather than asserted on one, because a
    /// classifier that special-cased the version gap and fell through to a
    /// permissive default for the rest would pass a single-case test.
    #[test]
    fn no_absence_of_an_answer_is_ever_reported_as_a_success() {
        let unanswered = [
            ApplyMutation::Unsupported {
                detail: "this executor cannot compare canonical forms".to_string(),
            },
            ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                negotiated_version: 4,
                since: 5,
            }),
            ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 5 }),
            ApplyMutation::Unknown(MutationUnknown::Unspecified { detail: String::new() }),
            ApplyMutation::Unknown(MutationUnknown::Unrecognised { value: 77 }),
        ];
        for mutation in unanswered {
            let verdict = InstallVerdict::of(0, &mutation);
            assert_eq!(verdict.change, None, "{mutation:?} produced a change outcome");
            assert_ne!(verdict.change, Some(ChangeOutcome::Unchanged));
            // The apply itself succeeded; what could not be established is a
            // claim about the host, not about the command.
            assert_eq!(verdict.exit, Outcome::Success, "{mutation:?}");
        }
    }

    /// A failed step outranks whatever the mutation said, including a stated
    /// `changed`. A partial install is not a mutation to celebrate.
    #[test]
    fn a_failed_step_outranks_every_mutation_outcome() {
        for mutation in [
            ApplyMutation::Changed,
            ApplyMutation::Unchanged,
            ApplyMutation::Unsupported { detail: String::new() },
            ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 5 }),
        ] {
            let verdict = InstallVerdict::of(1, &mutation);
            assert_eq!(verdict.exit, Outcome::InternalError, "{mutation:?}");
            assert_eq!(verdict.change, Some(ChangeOutcome::Failed), "{mutation:?}");
        }
    }

    /// The invariant AAASM-5499 pinned, re-asserted for this command: a stated
    /// success outcome accompanies exit `0` and nothing else does.
    #[test]
    fn the_sign_of_the_exit_code_agrees_with_the_stated_outcome() {
        for failed in [0usize, 1] {
            for mutation in [
                ApplyMutation::Changed,
                ApplyMutation::Unchanged,
                ApplyMutation::Failed { detail: String::new() },
                ApplyMutation::Unsupported { detail: String::new() },
                ApplyMutation::Unknown(MutationUnknown::Omitted { negotiated_version: 5 }),
            ] {
                let verdict = InstallVerdict::of(failed, &mutation);
                if let Some(change) = verdict.change {
                    assert_eq!(
                        change.is_success(),
                        verdict.exit.code() == 0,
                        "{mutation:?} with {failed} failed step(s) exits {} but reports {}",
                        verdict.exit.code(),
                        change.as_str()
                    );
                }
            }
        }
    }

    fn apply_view(outcome: Option<wire::ApplyOutcomeView>) -> wire::ApplyView {
        wire::ApplyView {
            plan_id: "plan-1".to_string(),
            receipt_id: "receipt-1".to_string(),
            applied_at_unix_secs: 1_700_000_000,
            steps: Vec::new(),
            planned_level: "gateway_protected".to_string(),
            achieved_level: "integrated".to_string(),
            outcome,
        }
    }

    fn plan_stub() -> PlanReport {
        PlanReport {
            runtime: runtime(),
            schema_version: 1,
            plan_id: "plan-1".to_string(),
            tool_id: "claude-code".to_string(),
            profile: "recommended".to_string(),
            settings_scope: "user".to_string(),
            policy_profile: None,
            planned_level: "gateway_protected".to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            steps: Vec::new(),
            unsupported: Vec::new(),
            warnings: Vec::new(),
            required_permissions: Vec::new(),
            applied: true,
        }
    }

    /// The report's two outcome fields are set together, so a document can
    /// neither claim an outcome while explaining its absence nor the reverse.
    #[test]
    fn the_report_never_states_an_outcome_and_a_reason_for_having_none() {
        for mutation in [
            ApplyMutation::Changed,
            ApplyMutation::Unchanged,
            ApplyMutation::Failed { detail: String::new() },
            ApplyMutation::Unsupported {
                detail: "cannot compare".to_string(),
            },
            ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
                negotiated_version: 4,
                since: 5,
            }),
        ] {
            let (report, _) = InstallReport::from_applied(plan_stub(), &apply_view(None), &mutation);
            assert_eq!(
                report.outcome.is_none(),
                report.outcome_unknown.is_some(),
                "{mutation:?} produced a report whose two outcome fields disagree"
            );
        }
    }

    /// **The falsification, at the surface a user sees.**
    ///
    /// `aa-runtime`'s suite proves the rejected `bool` reading fabricates
    /// `Unchanged` from an older peer's frame. This carries that fabricated
    /// value the rest of the way and shows what it becomes: a published
    /// `"outcome": "unchanged"` next to exit `0` — a claim that the user's
    /// machine was already in the state they asked for, sourced from a field no
    /// runtime sent.
    ///
    /// Both readings are run against **one** frame, so the difference is the
    /// reading and nothing else.
    #[test]
    fn the_rejected_bool_reading_publishes_a_success_this_client_refuses() {
        // What a v4 runtime sends: no outcome block.
        let frame = apply_view(None);

        // The rejected design's reading of it, transcribed: one bit, and
        // absence lands on `false`.
        let bool_shaped = if frame
            .outcome
            .as_ref()
            .is_some_and(|o| o.mutation == wire::ApplyMutation::Changed as i32)
        {
            ApplyMutation::Changed
        } else {
            ApplyMutation::Unchanged
        };
        let fabricated = InstallVerdict::of(0, &bool_shaped);
        assert_eq!(
            fabricated.change,
            Some(ChangeOutcome::Unchanged),
            "the falsification is vacuous if the rejected reading does not publish a success"
        );
        assert_eq!(fabricated.exit, Outcome::Success);

        // The shipped reading of the same frame, through the version gate.
        let stated = ApplyMutation::from_view(frame.outcome.as_ref(), 4);
        let (report, exit) = InstallReport::from_applied(plan_stub(), &frame, &stated);
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(
            json["outcome"],
            serde_json::Value::Null,
            "this client published the fabricated success"
        );
        assert_ne!(json["outcome"], serde_json::json!("unchanged"));
        assert!(json["outcome_unknown"].as_str().expect("a reason").contains("v4"));
        // The apply itself worked, so the exit code is unchanged — which is
        // exactly why the exit code cannot be the thing that answers this.
        assert_eq!(exit, Outcome::Success);
    }

    /// The JSON a script reads never says `unchanged` for a run whose outcome
    /// was not stated — the exact document the ratified contract is about.
    #[test]
    fn the_json_says_null_rather_than_unchanged_when_nothing_was_stated() {
        let mutation = ApplyMutation::Unknown(MutationUnknown::NotReportedAtVersion {
            negotiated_version: 4,
            since: 5,
        });
        let (report, exit) = InstallReport::from_applied(plan_stub(), &apply_view(None), &mutation);
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["outcome"], serde_json::Value::Null);
        assert!(
            json["outcome_unknown"].as_str().expect("a reason").contains("v4"),
            "the reason must name the peer that could not say: {json}"
        );
        assert_eq!(exit, Outcome::Success, "the apply itself worked");
    }
}
