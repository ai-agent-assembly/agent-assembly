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
}
