//! `aasm run` — launch an AI dev tool with governance wiring.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use uuid::Uuid;

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

use aa_core::{DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel};

use crate::commands::proxy::guard::{ProxyGuard, ProxyGuardOptions};
use crate::commands::proxy::launch_state;
// AAASM-5349: resolution is shared with the devint service, so it lives in
// `aa-policy` rather than here. Aliased so the call sites read unchanged.
use crate::commands::run_registration::{self, GovernedRegistration};
use crate::commands::status::models::redact_database_url;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;
use aa_policy::resolve as run_policy;

/// Arguments for the `aasm run <tool> [args...]` subcommand.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The AI development tool to launch (claude, codex, copilot, windsurf), or
    /// `exec` to launch a program you own yourself.
    ///
    /// The longer ids `aasm integrations list` prints — claude-code,
    /// github-copilot, windsurf-cascade — name the same tools and are accepted
    /// here too (AAASM-5503).
    ///
    /// `exec` takes the program and its arguments after `--`:
    /// `aasm run exec [run-options] -- <program> [args...]` (AAASM-5706). It is
    /// resolved only after every tool id fails, so it cannot shadow one.
    pub tool: String,

    /// Arguments forwarded verbatim to the launched tool, or — after `exec` —
    /// the program to launch and its own arguments.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub tool_args: Vec<String>,

    /// Override the agent identity for this session.
    #[arg(long)]
    pub agent_id: Option<String>,

    /// Team identifier for this session.
    #[arg(long)]
    pub team_id: Option<String>,

    /// Root agent identifier for lineage tracking.
    #[arg(long)]
    pub root_agent: Option<String>,

    /// Override the governance level for this session.
    #[arg(long)]
    pub governance_level: Option<GovernanceLevel>,

    /// Launch WITHOUT routing the tool through the governed proxy.
    ///
    /// This is an explicit opt-out of the sidecar proxy mechanism: the tool's traffic
    /// is not inspected and no egress policy applies to it. Without this flag
    /// `aasm run` refuses to launch unless it can establish a trusted local
    /// proxy endpoint (AAASM-5323) — it never launches unproxied by accident.
    #[arg(long)]
    pub no_proxy: bool,

    /// Policy YAML file this session runs under.
    ///
    /// When absent the policy is resolved from `$AA_POLICY` and the default
    /// locations, in the same order `aasm gateway start` uses. A governed
    /// launch refuses when no effective policy resolves — an unconfigured
    /// policy is not an implicit allow-all (AAASM-5349).
    #[arg(long)]
    pub policy: Option<std::path::PathBuf>,

    /// Directory the launched process starts in.
    ///
    /// Absent, the child inherits this shell's working directory, which is the
    /// pre-existing behaviour. When present it is applied to the command **last**,
    /// so the operator's explicit choice wins over any directory an adapter
    /// selected, and the directory is checked before anything is registered or
    /// started — a launch that cannot start where it was told to is refused, not
    /// silently started somewhere else (AAASM-5706).
    #[arg(long, value_name = "DIR")]
    pub workdir: Option<std::path::PathBuf>,

    /// Show the launch command and settings without executing.
    #[arg(long)]
    pub dry_run: bool,

    /// Enforcement posture for this session — overrides the policy default for
    /// this agent. Defaults to `enforce` (live enforcement). When set to
    /// `observe`, policy decisions are recorded but never applied; the launched
    /// tool sees Allow for every action and shadow events land in the audit log.
    #[arg(long, value_enum)]
    pub enforcement_mode: Option<EnforcementModeFlag>,

    /// Shorthand for `--enforcement-mode observe`. Mutually exclusive with
    /// `--enforcement-mode` so the source of truth stays unambiguous.
    #[arg(long, conflicts_with = "enforcement_mode")]
    pub observe: bool,

    /// How much execution isolation this launch requires (AAASM-5711).
    ///
    /// Defaults to `none`, which is the behaviour every `aasm run` had before
    /// this flag existed. That default is deliberate and is not a statement that
    /// isolation does not matter: turning it on by default would sandbox every
    /// existing user's tool in a release they did not read the notes for, and a
    /// governed launch that suddenly cannot write to the operator's own
    /// repository is worse than one that says what it is not doing. Changing the
    /// default is a product decision with its own ticket, not a side effect of
    /// making the mode work.
    ///
    /// `auto` and `process` both **refuse** when no backend can provide the
    /// class on this host. Neither ever falls back to `none`: a launch that
    /// asked for a boundary and silently did not get one is the exact failure
    /// Epic AAASM-5702 exists to prevent.
    #[arg(long, value_enum, default_value_t = IsolationIntent::None)]
    pub isolation: IsolationIntent,

    /// Pin the concrete isolation backend by id. Advanced and diagnostic only.
    ///
    /// Not the product vocabulary and not a policy dimension — ADR 0035 §3 is
    /// explicit that policy describes required isolation *properties*, not a
    /// vendor, so this exists for reproducing a result on a specific mechanism
    /// and for telling two backends apart in a bug report. `--isolation` is what
    /// an operator normally sets.
    ///
    /// Refused alongside `--isolation none`: naming a backend for a launch that
    /// asked for no boundary is a contradiction, and silently ignoring one half
    /// of it would leave the operator believing the other half took effect.
    #[arg(long, value_name = "ID")]
    pub isolation_backend: Option<String>,
}

/// The stable, backend-neutral statement of how much execution isolation a
/// launch requires (ADR 0035 §3, "isolation class is not backend identity").
///
/// Deliberately spelled in isolation *classes* rather than in any mechanism's
/// vocabulary. A class is a property an operator can ask for and a backend can
/// answer; a mechanism name is neither portable nor a promise, and the moment it
/// appears in this enum an ordinary policy stops surviving a backend change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum IsolationIntent {
    /// No execution-isolation boundary is established for this launch.
    ///
    /// Represented explicitly rather than as the absence of a flag, because the
    /// report has to be able to say *why* a run has no boundary, and "nobody
    /// asked for one" is a different fact from "one was asked for and could not
    /// be built".
    #[default]
    None,
    /// Agent Assembly selects a backend by capability (AAASM-5808).
    ///
    /// Walks the compiled-in backends in a fixed order and selects the first
    /// one whose `plan()` can meet this launch's lowered policy requirements
    /// — the same negotiation a real launch uses, not a hand-written
    /// comparison of what each backend is known to cover. It is not a synonym
    /// for "isolate if convenient": when no compiled-in backend can meet the
    /// requirements, this refuses — naming every backend it considered and
    /// why — rather than running unconfined or falling back to a default.
    Auto,
    /// Confine the launch and its descendants within one host's process model.
    Process,
}

/// CLI surface for [`aa_core::EnforcementMode`]. Lives here (not in `aa-core`)
/// to avoid pulling `clap` into the `no_std`-friendly core crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum EnforcementModeFlag {
    /// Default — policy decisions are applied; deny blocks, redact strips.
    Enforce,
    /// Dry-run — decisions computed and audited; no enforcement applied.
    Observe,
    /// Policy evaluation disabled. Only valid in hermetic test environments.
    Disabled,
}

impl From<EnforcementModeFlag> for aa_core::EnforcementMode {
    fn from(flag: EnforcementModeFlag) -> Self {
        match flag {
            EnforcementModeFlag::Enforce => aa_core::EnforcementMode::Enforce,
            EnforcementModeFlag::Observe => aa_core::EnforcementMode::Observe,
            EnforcementModeFlag::Disabled => aa_core::EnforcementMode::Disabled,
        }
    }
}

impl RunArgs {
    /// Resolve the user's intent across `--observe` (boolean shorthand) and
    /// `--enforcement-mode` into a single `EnforcementMode`. Returns the
    /// pre-feature default (`Enforce`) when neither flag is set.
    pub fn resolved_enforcement_mode(&self) -> aa_core::EnforcementMode {
        if self.observe {
            aa_core::EnforcementMode::Observe
        } else {
            self.enforcement_mode
                .map(Into::into)
                .unwrap_or(aa_core::EnforcementMode::Enforce)
        }
    }
}

/// Planning for `aasm run`: what a launch resolves to, before anything runs.
///
/// # The seam
///
/// Everything a launch depends on is resolved **once**, here, into a
/// [`ResolvedRunPlan`]. Execution consumes that plan rather than re-deriving any
/// part of it. `--dry-run` and a live launch then differ in exactly the two
/// places they legitimately must, both named by [`PlanPosture`]: whether an
/// unmet precondition refuses or is merely reported, and whether the identity is
/// registered or synthesized. Every other input — the proxy endpoint, the
/// effective policy, the adapter's launch command, the child environment — is
/// computed by the same code for both.
///
/// That convergence is the whole point. Before it the preview built its own
/// command and its own environment, and the two drifted twice: AAASM-5327
/// dropped the adapter's environment from the *live* launch, AAASM-5329 dropped
/// the adapter entirely from the *preview*. Each time, one side reported a
/// session as protected that the other would not have protected.
///
/// # Why this is a module inside `run.rs` rather than a `run_plan.rs`
///
/// `.ci/strip-for-publish.sh` removes the `aasm run` surface from the published
/// crate by deleting an explicit list of files (`DELETED_FILES`). A sibling
/// `run_plan.rs` would consume `aa-devtool` and `aa-isolation` — both
/// `publish = false` — so it would have to be added to that list or the
/// published build would fail on dependencies its manifest no longer declares.
/// Living inside `run.rs` means this seam ships, and strips, with the command it
/// belongs to and needs no packaging edit at all. Extraction later is
/// mechanical: move this module body to `run_plan.rs` and add one line to
/// `DELETED_FILES`.
mod plan {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::ffi::OsString;

    use uuid::Uuid;

    use aa_core::{DevToolAdapter, DevToolInfo};
    use aa_isolation::{
        CredentialPosture, ExecutionSpec, IdentityRef, IsolationBackend, IsolationReport, SessionRef, TargetRef,
    };
    use aa_policy::resolve as run_policy;

    use super::{run_registration, RegistrationHandle, RunArgs};

    /// What a launch is pointed at.
    ///
    /// Two kinds, and the difference is carried in the type rather than in a
    /// pseudo-adapter (AAASM-5706). A dev-tool launch has an adapter behind it and
    /// is *entitled* to generate and apply that tool's managed settings; a generic
    /// command has no adapter, no settings schema and no configuration file of its
    /// own, and must not have one written on its behalf. A fake adapter would have
    /// made that a runtime convention; an enum makes it a case every `match` has
    /// to account for before it compiles.
    ///
    /// Everything else — identity, lineage, proxy, policy, enforcement posture,
    /// registration and deregistration — is deliberately *not* varied by this
    /// enum. Both kinds resolve through the same [`RunPlanner`] and bind through
    /// the same [`ResolvedRunPlan::bind`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum RunTarget {
        /// A supported developer tool, named by its canonical registry token.
        ///
        /// Canonical, not as-typed: [`super::canonical_tool_id`] has already
        /// resolved whichever accepted alias the operator used, so nothing
        /// downstream has to know which spelling arrived (AAASM-5503).
        DevTool {
            /// The canonical `aa_devtool::registry` token.
            tool: String,
        },

        /// A program the operator owns, launched exactly as typed after `--`.
        ///
        /// Held as [`OsString`] so that between the CLI boundary and `spawn` there
        /// is no string a shell, a quoter or a splitter could reinterpret: the
        /// child receives these values element for element, and no argument is
        /// ever joined into a command line and re-split. An argument that is not
        /// valid UTF-8 is refused by clap at parse time rather than lossily
        /// converted here — losing the launch is better than running an argv that
        /// differs from the one that was typed.
        Command {
            /// The program to execute. Resolved by the OS through `PATH` exactly
            /// as any other `exec` would resolve it; `aasm run` does not probe it,
            /// rewrite it, or wrap it in a shell.
            program: OsString,
            /// The remaining argv, in order, with nothing added or removed.
            args: Vec<OsString>,
        },
    }

    impl RunTarget {
        /// A launch of the supported developer tool named by `tool`.
        pub(super) fn dev_tool(tool: impl Into<String>) -> Self {
            Self::DevTool { tool: tool.into() }
        }

        /// A generic launch of `argv`, whose first element names the program.
        ///
        /// Refuses an empty `argv`. `aasm run exec` with nothing after `--` names
        /// no program, and the two ways to paper over that — defaulting to a shell
        /// or to `$SHELL` — would both reintroduce the shell reconstruction this
        /// target exists to avoid.
        pub(super) fn command(argv: &[String]) -> anyhow::Result<Self> {
            let (program, args) = argv.split_first().ok_or_else(|| {
                anyhow::anyhow!(
                    "`aasm run {target}` needs a program to launch: \
                     `aasm run {target} [run-options] -- <program> [args...]`",
                    target = super::EXEC_TARGET
                )
            })?;
            Ok(Self::Command {
                program: OsString::from(program),
                args: args.iter().map(OsString::from).collect(),
            })
        }

        /// The name this target is announced and refused under.
        ///
        /// Also the executable a degraded dev-tool preview falls back to, which is
        /// why it has to be the canonical token rather than a display string. For
        /// a generic command it is the program as typed, rendered lossily — this
        /// is a label for humans, never the value handed to `spawn`.
        pub(super) fn label(&self) -> Cow<'_, str> {
            match self {
                Self::DevTool { tool } => Cow::Borrowed(tool),
                Self::Command { program, .. } => program.to_string_lossy(),
            }
        }
    }

    /// Whether a plan is being resolved in order to *launch*, or in order to
    /// *describe a launch*.
    ///
    /// The only two things it changes are the two that legitimately differ:
    ///
    /// * an unmet precondition **refuses** under [`Launch`](Self::Launch) and is
    ///   **reported** under [`Preview`](Self::Preview) — a preview exists to tell
    ///   the operator what a live run would do, and "it would refuse" is the most
    ///   useful thing it can say;
    /// * a *minted* agent id is prefixed `dry-run-` under `Preview`, so nothing
    ///   downstream can mistake a previewed identity for a registered one.
    ///
    /// Nothing else branches on it. Every protection-critical value is derived
    /// the same way under both, which is what stops a preview from describing a
    /// launch that is not the launch.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum PlanPosture {
        /// Resolving in order to start a child process.
        Launch,
        /// Resolving in order to print `--dry-run` output.
        Preview,
    }

    /// Who the launch will be attributed to — the operator's intent, before any
    /// gateway has accepted it.
    ///
    /// Holds intent rather than an identity because at planning time no identity
    /// exists yet: a live launch obtains one by registering, a preview
    /// synthesizes one. Both derive it from *this*, so the identity a preview
    /// prints is the identity a live run would have submitted.
    #[derive(Debug, Clone)]
    pub(super) struct IdentityPlan {
        agent_id: Option<String>,
        team_id: Option<String>,
        root_agent: Option<String>,
    }

    impl IdentityPlan {
        /// The identity intent carried by `args`.
        pub(super) fn of(args: &RunArgs) -> Self {
            Self {
                agent_id: args.agent_id.clone(),
                team_id: args.team_id.clone(),
                root_agent: args.root_agent.clone(),
            }
        }

        /// The agent id this launch presents.
        ///
        /// An operator-supplied `--agent-id` is honored verbatim under both
        /// postures, so a preview shows the id a live run would submit rather
        /// than a stand-in. Only a *minted* id differs, and deliberately: the
        /// `dry-run-` prefix makes it obvious in the printed plan that no
        /// registration occurred.
        pub(super) fn agent_id(&self, posture: PlanPosture) -> String {
            self.agent_id.clone().unwrap_or_else(|| match posture {
                PlanPosture::Launch => Uuid::new_v4().to_string(),
                PlanPosture::Preview => format!("dry-run-{}", Uuid::new_v4()),
            })
        }

        /// The owning team, when the operator named one.
        pub(super) fn team_id(&self) -> Option<&str> {
            self.team_id.as_deref()
        }

        /// The lineage root, when the operator named one.
        pub(super) fn root_agent(&self) -> Option<&str> {
            self.root_agent.as_deref()
        }

        /// The identity a `--dry-run` preview presents, without contacting the
        /// gateway.
        ///
        /// Used by the preview so planning works in CI runners where no AI dev
        /// tool is installed and no gateway is reachable.
        ///
        /// The locally-minted correlation ids are prefixed `dry-run-` for the
        /// same reason a minted agent id is. `registration_did` and
        /// `registration_id`, by contrast, are **not** faked: both are pure
        /// derivations of the identity a live run would present, so the preview
        /// can show the DID that would be registered and the registry key it
        /// would occupy. A `dry-run-` placeholder there would hide the one thing
        /// about the identity worth previewing.
        pub(super) fn preview_handle(&self) -> RegistrationHandle {
            let agent_id = self.agent_id(PlanPosture::Preview);
            let registration_did = run_registration::registration_did(&agent_id);
            RegistrationHandle {
                registration_id: run_registration::registry_id(self.team_id(), &registration_did),
                agent_id,
                registration_did,
                trace_id: format!("dry-run-{}", Uuid::new_v4()),
                session_id: format!("dry-run-{}", Uuid::new_v4()),
                team_id: self.team_id.clone(),
            }
        }

        /// The backend-neutral identity reference an [`ExecutionSpec`] is built
        /// against.
        ///
        /// `--root-agent` becomes an *ancestor* rather than a flat parent field:
        /// ADR 0035 §6 needs lineage in order to check that sub-agent identity
        /// narrows while OS authority does not widen, and a single parent string
        /// cannot express depth.
        ///
        /// `agent_id` is a parameter rather than re-derived so the reference
        /// names the identity this launch actually presented — under `Launch`
        /// that is the one the gateway accepted, which [`Self::agent_id`] cannot
        /// know. The reference is **asserted, not verified**; nothing in
        /// `aa-isolation` authenticates it and no claim derived from it may
        /// present it as verified.
        pub(super) fn identity_ref(&self, agent_id: &str) -> IdentityRef {
            let mut identity = IdentityRef::root(agent_id);
            if let Some(team) = self.team_id() {
                identity = identity.with_team(team);
            }
            if let Some(root) = self.root_agent() {
                identity = identity.with_ancestor(root);
            }
            identity
        }
    }

    /// Where this launch's traffic goes.
    #[derive(Debug, Clone)]
    pub(super) struct NetworkPlan {
        endpoint: Option<String>,
        no_proxy: bool,
    }

    impl NetworkPlan {
        /// This launch's dedicated proxy's bound address (AAASM-5863), or
        /// `None`.
        ///
        /// `None` before `execute_with_adapters` calls [`Self::set_endpoint`]
        /// — every `resolve()`d plan starts this way, since the dedicated
        /// proxy cannot exist before registration has produced the identity
        /// it is configured with — and permanently for [`Self::no_proxy`] or a
        /// preview, neither of which ever starts one. It never means "use
        /// whatever the shell had" — an environment-supplied proxy address is
        /// the class of input this feature exists to stop treating as
        /// authoritative (AAASM-5323).
        pub(super) fn endpoint(&self) -> Option<&str> {
            self.endpoint.as_deref()
        }

        /// Record this launch's dedicated proxy's bound address, once
        /// [`super::ProxyGuard::spawn`] has confirmed it is ready. Called
        /// exactly once per live launch, after registration and before
        /// [`ResolvedRunPlan::bind`] — see `execute_with_adapters`.
        pub(super) fn set_endpoint(&mut self, endpoint: String) {
            self.endpoint = Some(endpoint);
        }

        /// Whether the operator explicitly opted out of interception.
        pub(super) fn no_proxy(&self) -> bool {
            self.no_proxy
        }
    }

    /// The effective policy this session runs under.
    ///
    /// Carries the whole four-state [`run_policy::PolicyResolution`] rather than
    /// a boolean: the two states that launch (`enforced`, `permissive`) and the
    /// two that refuse (`unconfigured`, `load_failed`) all have to survive as far
    /// as the receipt an operator reads.
    pub(super) struct PolicyPlan {
        resolution: run_policy::PolicyResolution,
        document: Option<aa_core::PolicyDocument>,
    }

    impl PolicyPlan {
        /// The resolution, including the states that would refuse a launch.
        pub(super) fn resolution(&self) -> &run_policy::PolicyResolution {
            &self.resolution
        }
    }

    /// The managed dev-tool integration this launch depends on.
    pub(super) struct IntegrationPlan<'a> {
        adapter: &'a dyn DevToolAdapter,
        detected: Option<DevToolInfo>,
    }

    impl<'a> IntegrationPlan<'a> {
        /// An integration plan for `adapter`, probing this host for whether the
        /// tool is installed.
        ///
        /// `detect()` inspects the host and starts nothing, which is why both a
        /// live launch and a preview can call it.
        pub(super) fn probe(adapter: &'a dyn DevToolAdapter) -> Self {
            Self {
                detected: adapter.detect(),
                adapter,
            }
        }

        /// What `detect()` found on this host, or `None` when the tool is not
        /// installed.
        ///
        /// Always `Some` for a plan resolved under [`PlanPosture::Launch`], which
        /// refuses without it. A preview keeps the `None` and degrades visibly.
        pub(super) fn detected(&self) -> Option<&DevToolInfo> {
            self.detected.as_ref()
        }

        /// Ask the adapter for the command this launch runs.
        ///
        /// The **single** implementation, used by the live launch and by
        /// `--dry-run` alike. Splitting it was the AAASM-5329 defect: the preview
        /// built its own `Command` and so omitted `NODE_EXTRA_CA_CERTS` and the
        /// normalised proxy URL — the two variables whose absence is what makes a
        /// session ungoverned — while reporting the launch as governed.
        ///
        /// Returns three things because the two callers dispose of failure
        /// differently and both dispositions are correct:
        ///
        /// * the command — the adapter's, or a bare fallback naming `label`;
        /// * the [`PreviewFidelity`], which is what a preview prints;
        /// * the adapter's own error, which is what a live launch fails on.
        ///
        /// `--dry-run` deliberately still works when the tool is not installed
        /// (AAASM-5329 AC 3). Requiring installation would be the tidier
        /// contract, but it would break previewing a launch from CI or from a
        /// machine being set up — the case the flag is most useful for. What is
        /// not acceptable is the old behaviour of silently printing a preview
        /// missing the adapter's contribution, so an un-derivable command is
        /// reported as degraded rather than passed off as faithful.
        ///
        /// Nothing here starts, writes or applies anything: `detect()` inspects
        /// the host and `build_launch_command` constructs a `Command` without
        /// running it.
        pub(super) fn launch_command(
            &self,
            args: &RunArgs,
            label: &str,
            handle: &RegistrationHandle,
            proxy: Option<&str>,
        ) -> (std::process::Command, super::PreviewFidelity, Option<String>) {
            let fallback = || {
                let mut cmd = std::process::Command::new(label);
                cmd.args(&args.tool_args);
                cmd
            };

            if self.detected.is_none() {
                return (
                    fallback(),
                    super::PreviewFidelity::Degraded(format!(
                        "{label} is not installed on this host, so the adapter could not be asked \
                         what it would run. The command and environment below omit everything the \
                         adapter contributes — including NODE_EXTRA_CA_CERTS and the normalised \
                         proxy URL, whose absence is what makes a session ungoverned. Install the \
                         tool and re-run to preview the real launch."
                    )),
                    None,
                );
            }

            match self
                .adapter
                .build_launch_command(&args.tool_args, &handle.agent_id, handle.team_id.as_deref(), proxy)
            {
                Ok(cmd) => (cmd, super::PreviewFidelity::FromAdapter, None),
                Err(e) => (
                    fallback(),
                    super::PreviewFidelity::Degraded(format!(
                        "the {label} adapter could not build a launch command ({e}), so the command \
                         and environment below omit everything it contributes. A live `aasm run` \
                         with these flags would fail here."
                    )),
                    Some(e.to_string()),
                ),
            }
        }
    }

    /// Which of the three things happened to this launch's execution boundary.
    ///
    /// Three variants because the alternative — an `Option<EnforcementPlan>` —
    /// makes "nobody asked for a boundary" and "one was asked for and refused"
    /// the same value, and those are opposite security statements. The second
    /// must stop the launch; the first must not change it at all.
    pub(super) enum Boundary {
        /// No boundary. The launch runs exactly as every `aasm run` did before
        /// this flag existed.
        Absent,
        /// A negotiated plan the launch must execute inside, or not at all.
        ///
        /// Boxed only to keep the enum small: an [`EnforcementPlan`] carries the
        /// whole spec plus every planned requirement, and the other two variants
        /// are a unit and a string, so an unboxed variant would make every
        /// `Boundary` the size of the largest one.
        Negotiated(Box<aa_isolation::EnforcementPlan>),
        /// Negotiation refused before anything started, with the operator-facing
        /// reason.
        Refused(String),
    }

    /// One of the concrete backends this build was compiled with, before it
    /// becomes `Arc<dyn IsolationBackend>`.
    ///
    /// # Why an enum and not `Box<dyn IsolationBackend>` here
    ///
    /// Selection is the one place that must name a backend — Rust has no plugin
    /// loader — and two of the three things selection does are *not* on the
    /// trait. `set_child_environment` takes the exact environment the confined
    /// program is to receive, and it cannot be on `IsolationBackend` without
    /// putting a process-environment model into a contract ADR 0035 keeps
    /// platform-free. Adding it there to save this enum would be a contract
    /// change made for a caller's convenience, which the AAASM-5801 amendment
    /// explicitly verified was not needed.
    ///
    /// So the enum lives here, in the module that already names every backend,
    /// and it ends at [`Self::into_arc`]: everything downstream of selection
    /// holds the trait object and cannot tell the concrete backends apart.
    pub(super) enum SelectedBackend {
        /// The backend built on the external `sandlock` supervisor (AAASM-5708).
        Sandlock(aa_isolation_sandlock::SandlockBackend),
        /// The AASM-native backend, whose boundary is installed by a launcher
        /// binary this workspace builds (AAASM-5802).
        Native(aa_isolation_native::NativeBackend),
        /// The macOS backend delegating to `aa-isolation-native` inside a
        /// Virtualization.framework guest (AAASM-5813). `Unavailable` on
        /// every host today — see the crate's own docs for why.
        MacosVm(aa_isolation_macos_vm::MacosVmBackend),
    }

    impl SelectedBackend {
        /// What this backend is, and where it came from.
        fn identity(&self) -> aa_isolation::BackendIdentity {
            match self {
                Self::Sandlock(backend) => backend.identity(),
                Self::Native(backend) => backend.identity(),
                Self::MacosVm(backend) => backend.identity(),
            }
        }

        /// What the selected backend can do on this host, right now.
        fn capabilities(&self) -> aa_isolation::BackendCapabilities {
            match self {
                Self::Sandlock(backend) => backend.capabilities(),
                Self::Native(backend) => backend.capabilities(),
                Self::MacosVm(backend) => backend.capabilities(),
            }
        }

        /// Install the exact environment the confined program is to receive.
        fn set_child_environment(&mut self, env: std::collections::BTreeMap<String, String>) {
            match self {
                Self::Sandlock(backend) => backend.set_child_environment(env),
                Self::Native(backend) => backend.set_child_environment(env),
                Self::MacosVm(backend) => backend.set_child_environment(env),
            }
        }

        /// Resolve a spec against this backend's capabilities, before anything
        /// starts.
        #[allow(clippy::result_large_err)]
        fn plan(&self, spec: &ExecutionSpec) -> Result<aa_isolation::EnforcementPlan, aa_isolation::PlanRefusal> {
            match self {
                Self::Sandlock(backend) => backend.plan(spec),
                Self::Native(backend) => backend.plan(spec),
                Self::MacosVm(backend) => backend.plan(spec),
            }
        }

        /// Hand the launch path the trait object it holds for the whole run.
        ///
        /// The last point at which the concrete backend is visible. After this
        /// the supervisor holds `Arc<dyn IsolationBackend>` and has no way to
        /// ask which of the two it got, which is ADR 0035 §3 held structurally.
        pub(super) fn into_arc(self) -> std::sync::Arc<dyn aa_isolation::IsolationBackend> {
            match self {
                Self::Sandlock(backend) => std::sync::Arc::new(backend),
                Self::Native(backend) => std::sync::Arc::new(backend),
                Self::MacosVm(backend) => std::sync::Arc::new(backend),
            }
        }
    }

    /// What the execution boundary is required to provide, and who is going to
    /// provide it.
    ///
    /// Backend-neutral where it has to be and concrete where it cannot avoid
    /// being: the requirements are lowered from policy and name no backend
    /// (`aa-isolation` keeps [`BackendIdentity`](aa_isolation::BackendIdentity)
    /// out of [`ControlRequirement`] and [`ExecutionSpec`] for exactly that
    /// reason, ADR 0035 §3), while *selection* has to name one because Rust has
    /// no plugin loader. Everything downstream of selection holds the trait.
    ///
    /// The requirement list is no longer empty (AAASM-5711). It is
    /// [`aa_isolation::lower_policy`] applied to the canonical projection
    /// `aa-policy` now retains — see `PolicyResolution`'s type documentation for
    /// why that projection had to be added before any of this could source a
    /// single requirement.
    #[derive(Default)]
    pub(super) struct IsolationPlan {
        /// What the effective policy asks of the boundary, per domain. `None`
        /// when no policy resolved, which only a preview can reach — a live
        /// launch refuses on that first.
        lowering: Option<aa_isolation::PolicyLowering>,
        /// The selected backend. `None` whenever no boundary is in play, and
        /// [`Self::absent`] then says which of the reasons applies.
        backend: Option<SelectedBackend>,
        /// Why this launch has no boundary, in words an operator can act on.
        absent: Option<String>,
        /// How the backend was selected, and what automatic selection
        /// considered along the way. `None` when selection was not automatic —
        /// there is nothing here for `--dry-run`/live parity to disagree about
        /// on an explicit or default selection.
        selection: Option<aa_isolation::BackendSelection>,
    }

    impl IsolationPlan {
        /// Take the selected backend, leaving none behind.
        ///
        /// Consuming rather than borrowing because the launch path needs it as
        /// `Arc<dyn IsolationBackend>` and holds it for the whole run, which
        /// outlives the plan.
        pub(super) fn take_backend(&mut self) -> Option<SelectedBackend> {
            self.backend.take()
        }

        /// The reason this launch has no boundary.
        ///
        /// Never a bare "none": every path that produces no boundary sets a
        /// sentence, because [`IsolationReport::no_boundary`] renders it and an
        /// operator reading "no boundary" without a reason cannot tell a default
        /// from a failure.
        fn absent_reason(&self) -> String {
            self.absent.clone().unwrap_or_else(|| {
                "no execution-isolation backend was selected for this launch, and nothing recorded why".to_string()
            })
        }

        /// Attach the recorded selection walk to `report`, when anything was
        /// recorded.
        ///
        /// Mirrors how `with_policy` is threaded onto every report
        /// [`resolve_boundary`](Self::resolve_boundary) produces: `--dry-run`
        /// and a live launch must describe an automatic selection identically,
        /// which only holds if every return point attaches it the same way.
        fn with_selection(&self, report: IsolationReport) -> IsolationReport {
            match &self.selection {
                Some(selection) => report.with_selection(selection.clone()),
                None => report,
            }
        }

        /// The launch as an [`ExecutionSpec`], before any requirement is
        /// attached.
        ///
        /// `None` when the program or any argument is not valid UTF-8.
        /// [`ExecutionSpec`] is explicit that a launch it cannot describe
        /// faithfully must be rejected at the CLI boundary rather than lossily
        /// converted — "losing the launch is better than logging an argv that
        /// differs from the one that ran".
        fn base_spec(
            &self,
            identity: &IdentityPlan,
            handle: &RegistrationHandle,
            command: &std::process::Command,
            credentials: CredentialPosture,
        ) -> Option<ExecutionSpec> {
            let program = command.get_program().to_str()?.to_string();
            let args: Vec<String> = command
                .get_args()
                .map(|arg| arg.to_str().map(str::to_string))
                .collect::<Option<_>>()?;

            let mut spec = ExecutionSpec::new(program, identity.identity_ref(&handle.agent_id))
                .with_args(args)
                .with_credentials(credentials);
            if let Some(dir) = command.get_current_dir() {
                spec = spec.with_working_dir(dir);
            }
            Some(spec)
        }

        /// Resolve this launch's execution boundary: the spec, the canonical
        /// projection of what was asked and achieved, and what execution must do
        /// about it.
        ///
        /// Called from [`ResolvedRunPlan::bind`] and therefore by `--dry-run` and
        /// the live launch alike, which is what makes AC 10 hold: nothing here
        /// prepares, starts or writes anything, so a preview negotiates the same
        /// plan against the same backend and prints it.
        ///
        /// `child_env` is handed to the backend rather than left to be
        /// inherited. The confined program is a different process from this one,
        /// and the governance identity, the proxy address and the adapter's CA
        /// path all live in a map this process holds rather than in its own
        /// environment — see `SandlockBackend::set_child_environment`.
        fn resolve_boundary(
            &mut self,
            identity: &IdentityPlan,
            handle: &RegistrationHandle,
            command: &std::process::Command,
            child_env: &std::collections::BTreeMap<String, String>,
            credentials: CredentialPosture,
        ) -> (Option<ExecutionSpec>, IsolationReport, Boundary) {
            let session = SessionRef::new(&handle.session_id, &handle.trace_id);
            let identity_ref = identity.identity_ref(&handle.agent_id);

            let Some(base) = self.base_spec(identity, handle, command, credentials.clone()) else {
                // The lossy rendering is a label for humans, which is all
                // `TargetRef` is — it deliberately carries no argv.
                let target = TargetRef::new(
                    command.get_program().to_string_lossy().into_owned(),
                    command.get_args().len(),
                );
                let report = self.with_selection(IsolationReport::no_boundary(
                    session,
                    identity_ref,
                    target,
                    credentials,
                    "this launch cannot be described faithfully — its program or an argument is not valid \
                     UTF-8 — so no execution specification exists, no backend was consulted, and nothing \
                     about its isolation is known",
                ));
                // A launch that asked for a boundary cannot get one without a
                // spec, and running it anyway would be an unconfined launch of
                // an untrusted program — the fallback this whole mode exists to
                // rule out. A launch that asked for none is unaffected, which is
                // why the two are not the same answer.
                let boundary = match self.backend {
                    Some(_) => Boundary::Refused(
                        "an execution-isolation boundary was requested and this launch cannot be described \
                         faithfully — its program or an argument is not valid UTF-8 — so no specification \
                         exists to negotiate one against"
                            .to_string(),
                    ),
                    None => Boundary::Absent,
                };
                return (None, report, boundary);
            };

            // No backend: either nobody asked for one, or a preview met a
            // refusal a live launch would have raised. Either way the boundary
            // is absent, and the report says which — with the policy lowering
            // attached, so every domain states whether the operator left a node
            // unset or whether the schema has no node to set. Without that, all
            // nine read `not_derived`, which is what they read before this
            // ticket and is far more benign than the truth.
            let Some(backend) = self.backend.as_mut() else {
                let mut report = IsolationReport::no_boundary(
                    session,
                    identity_ref,
                    TargetRef::of(&base),
                    credentials,
                    self.absent_reason(),
                );
                if let Some(lowering) = &self.lowering {
                    report = report.with_policy(lowering);
                }
                report = self.with_selection(report);
                return (Some(base), report, Boundary::Absent);
            };

            // A boundary was asked for, so a policy has to have lowered to
            // something for it to enforce. `apply_to` is fallible on purpose:
            // `negotiate` resolves an empty requirement set to `Ready` against
            // any backend at all, including one that enforces nothing, and
            // "we asked for nothing and got it" must not reach a reader as
            // readiness.
            let Some(lowering) = self.lowering.as_ref() else {
                let report = self.with_selection(IsolationReport::no_boundary(
                    session,
                    identity_ref,
                    TargetRef::of(&base),
                    credentials,
                    "an execution-isolation boundary was requested but no effective policy resolved, so \
                     there is nothing to lower into requirements for it to enforce",
                ));
                return (
                    Some(base),
                    report,
                    Boundary::Refused(
                        "an execution-isolation boundary was requested and no effective policy resolved to \
                         lower into it"
                            .to_string(),
                    ),
                );
            };

            let spec = match lowering.apply_to(base.clone()) {
                Ok(spec) => spec,
                Err(nothing) => {
                    let detail = nothing.to_string();
                    let mut report = IsolationReport::no_boundary(
                        session,
                        identity_ref,
                        TargetRef::of(&base),
                        credentials,
                        format!("the launch is refused: {detail}"),
                    );
                    report = report.with_policy(lowering);
                    report = self.with_selection(report);
                    return (Some(base), report, Boundary::Refused(detail));
                }
            };

            backend.set_child_environment(child_env.clone());
            match backend.plan(&spec) {
                Ok(plan) => {
                    let report = self.with_selection(IsolationReport::from_plan(session, &plan).with_policy(lowering));
                    (Some(spec), report, Boundary::Negotiated(Box::new(plan)))
                }
                Err(refusal) => {
                    let detail = super::describe_refusal(&refusal);
                    let report = self
                        .with_selection(IsolationReport::from_refusal(session, &spec, &refusal).with_policy(lowering));
                    (Some(spec), report, Boundary::Refused(detail))
                }
            }
        }
    }

    /// How this launch treats the authority the child would otherwise inherit.
    ///
    /// Three fields, three separate factual claims. ADR 0035 §9 requires the
    /// distinction because "the child has this credential because we handed it
    /// one" and "the child has this credential because we could not take it
    /// away" are different security postures with the same observable outcome.
    ///
    /// * `removed` — names the adapter asked to have unset. A fact: the spawn
    ///   path calls `env_remove` for exactly these, and `--dry-run` prints them
    ///   as removals.
    /// * `delegated` — **empty, and that is correct rather than unfinished**.
    ///   `aasm run` deliberately hands the launched tool no credential of its
    ///   own: the gateway's token authenticates *as the registered agent*, and
    ///   the launched tool is the software registration exists to govern (see
    ///   [`RegistrationHandle`]).
    /// * `ambient_unremoved` — inherited names that look like they carry
    ///   credential material and reach the child anyway. `build_child_env` seeds
    ///   the child from the operator's whole environment, so on a real host this
    ///   is normally non-empty — and it must be. An empty list would make
    ///   [`CredentialPosture::has_unremoved_ambient_authority`] answer `false`,
    ///   which reads as a least-authority run, which this is not.
    ///
    /// That last list is a name-shaped **lower bound** — see
    /// [`super::looks_like_credential_name`]. Its emptiness is never evidence
    /// that no ambient authority reached the child.
    fn credential_posture(
        effective: &std::collections::BTreeMap<String, String>,
        removed: &[String],
    ) -> CredentialPosture {
        let ambient_unremoved: Vec<String> = std::env::vars()
            .map(|(name, _)| name)
            .filter(|name| super::looks_like_credential_name(name))
            // Still present after the adapter's own removals were applied.
            .filter(|name| effective.contains_key(name))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        CredentialPosture {
            removed: removed.to_vec(),
            delegated: Vec::new(),
            ambient_unremoved,
        }
    }

    /// The exact command and environment a child will receive under one identity.
    ///
    /// Produced only by [`ResolvedRunPlan::bind`], so there is no way to obtain
    /// one without having gone through the plan.
    pub(super) struct BoundLaunch {
        command: std::process::Command,
        child_env: HashMap<String, String>,
        fidelity: super::PreviewFidelity,
        adapter_error: Option<String>,
        spec: Option<ExecutionSpec>,
        isolation: IsolationReport,
        boundary: Boundary,
    }

    impl BoundLaunch {
        /// The command as the adapter built it, environment included.
        pub(super) fn command(&self) -> &std::process::Command {
            &self.command
        }

        /// This session's governance identity and proxy variables, before the
        /// adapter's own environment is merged over the top of it.
        pub(super) fn child_env(&self) -> &HashMap<String, String> {
            &self.child_env
        }

        /// How faithfully this reflects the launch it describes.
        pub(super) fn fidelity(&self) -> &super::PreviewFidelity {
            &self.fidelity
        }

        /// The adapter's own error, when it could not build a launch command.
        ///
        /// Carried rather than raised so each caller keeps its own disposition: a
        /// preview degrades visibly and still prints, a live launch fails.
        pub(super) fn adapter_error(&self) -> Option<&str> {
            self.adapter_error.as_deref()
        }

        /// The backend-neutral [`ExecutionSpec`] this launch corresponds to,
        /// requirements included.
        #[allow(dead_code)]
        pub(super) fn spec(&self) -> Option<&ExecutionSpec> {
            self.spec.as_ref()
        }

        /// What execution must do about this launch's boundary.
        pub(super) fn boundary(&self) -> &Boundary {
            &self.boundary
        }

        /// What this launch's execution boundary was asked for, and what it got.
        ///
        /// The one projection both `--dry-run` and the live launch render, so
        /// neither can describe a boundary the other would not have (AAASM-5710).
        pub(super) fn isolation(&self) -> &IsolationReport {
            &self.isolation
        }

        /// Consume this into the values execution needs.
        ///
        /// The command and environment travel even for a confined launch: the
        /// unconfined path consumes them directly, and the confined one has
        /// already handed the environment to the backend, so returning them
        /// together keeps one exit from this type rather than two that could
        /// disagree about what was bound.
        pub(super) fn into_execution_parts(
            self,
        ) -> (
            std::process::Command,
            HashMap<String, String>,
            Boundary,
            IsolationReport,
        ) {
            (self.command, self.child_env, self.boundary, self.isolation)
        }
    }

    /// The values a live launch is entitled to assume resolved.
    ///
    /// Exists so `execute_with_adapters` does not have to re-check preconditions
    /// [`PlanPosture::Launch`] already refused without. Absent for a preview,
    /// which by design carries unmet preconditions rather than refusing on them.
    pub(super) struct Launchable<'a> {
        /// The detected tool this launch registers as, or `None` for a generic
        /// command — which has no adapter, so there is nothing to detect and no
        /// managed settings to generate.
        pub(super) info: Option<&'a DevToolInfo>,
        /// The policy document managed settings are generated from.
        pub(super) policy: &'a aa_core::PolicyDocument,
    }

    /// Everything one `aasm run` invocation resolved to, before any child exists.
    pub(super) struct ResolvedRunPlan<'a> {
        args: &'a RunArgs,
        posture: PlanPosture,
        target: RunTarget,
        identity: IdentityPlan,
        /// `None` for a generic command, which by construction has no adapter.
        integration: Option<IntegrationPlan<'a>>,
        network: NetworkPlan,
        policy: PolicyPlan,
        isolation: IsolationPlan,
        enforcement_mode: aa_core::EnforcementMode,
    }

    impl<'a> ResolvedRunPlan<'a> {
        /// Who the launch is attributed to.
        pub(super) fn identity(&self) -> &IdentityPlan {
            &self.identity
        }

        /// What this launch is pointed at.
        pub(super) fn target(&self) -> &RunTarget {
            &self.target
        }

        /// Where this launch's traffic goes.
        pub(super) fn network(&self) -> &NetworkPlan {
            &self.network
        }

        /// Record this live launch's dedicated proxy address — see
        /// [`NetworkPlan::set_endpoint`]. Must be called, if at all, before
        /// [`Self::bind`]: `bind` is what reads `network.endpoint()` into the
        /// child's `HTTP_PROXY`/`HTTPS_PROXY` and the adapter's launch command.
        pub(super) fn set_endpoint(&mut self, endpoint: String) {
            self.network.set_endpoint(endpoint);
        }

        /// The effective policy.
        pub(super) fn policy(&self) -> &PolicyPlan {
            &self.policy
        }

        /// The exact command and environment a child will receive under
        /// `handle`.
        ///
        /// This is the convergence AAASM-5705 exists for: the **only** place
        /// protection-critical launch state is constructed. `--dry-run` binds a
        /// synthesized identity and renders the result; a live launch binds the
        /// registered one and spawns it. Neither builds a command or an
        /// environment of its own, so the two cannot drift — which they did
        /// twice before, AAASM-5327 dropping the adapter's environment from the
        /// live launch and AAASM-5329 dropping the adapter entirely from the
        /// preview. Each time one side reported a protection the other did not
        /// have.
        ///
        /// Identity is a parameter rather than a field because it is the one
        /// thing the plan legitimately cannot know: a live launch obtains it by
        /// registering, which must happen *after* every refusal here has passed.
        ///
        /// The environment layers lowest to highest — inherited environment,
        /// governance identity, proxy variables, `AA_ENFORCEMENT_MODE`, policy
        /// annotations — and the adapter's own environment is applied last, at
        /// spawn time, so it wins on a collision. It is the layer that knows what
        /// the launched tool actually needs.
        pub(super) fn bind(&mut self, handle: &RegistrationHandle) -> BoundLaunch {
            let mut child_env = super::build_child_env(
                handle,
                self.network.endpoint(),
                self.network.no_proxy(),
                self.enforcement_mode,
            );
            self.policy.resolution.annotate_env(&mut child_env);

            let (mut command, fidelity, adapter_error) = self.launch_command(handle);

            // Applied after the command is built, so an explicit `--workdir` wins
            // over any directory the adapter chose — and applied *here*, in the
            // one place both postures bind through, so the directory the preview
            // prints is the directory the live launch starts in. It also reaches
            // the `ExecutionSpec` below, because `spec` reads it back off the
            // command rather than being told separately.
            if let Some(dir) = &self.args.workdir {
                command.current_dir(dir);
            }

            // Derived through the same merge `spawn_and_wait` applies, so the
            // spec describes the environment the child actually receives —
            // including the names the adapter removes, which a naive union of the
            // two sources would still show as present.
            let (effective, removed) = super::effective_child_env(&command, &child_env);
            let credentials = credential_posture(&effective, &removed);

            // The spec, the canonical projection and the execution decision are
            // resolved together, in the one place both postures bind through, so
            // the isolation section a preview prints is the one a live launch
            // would emit and the plan it names is the plan the live launch runs
            // (AAASM-5710 AC 1, AAASM-5711 AC 10).
            //
            // `effective` rather than `child_env`: it is the merge the child
            // actually receives, adapter values on top and the adapter's
            // removals already applied. Handing over the pre-merge map would put
            // a different environment inside the boundary than the one every
            // other surface reports.
            let (spec, isolation, boundary) =
                self.isolation
                    .resolve_boundary(&self.identity, handle, &command, &effective, credentials);

            BoundLaunch {
                command,
                child_env,
                fidelity,
                adapter_error,
                spec,
                isolation,
                boundary,
            }
        }

        /// Take the selected isolation backend, leaving none behind.
        pub(super) fn take_backend(&mut self) -> Option<SelectedBackend> {
            self.isolation.take_backend()
        }

        /// The command this launch runs, how faithfully it can be described, and
        /// the adapter's own error when it had one.
        ///
        /// The dev-tool arm delegates to the adapter — the single implementation
        /// a preview and a live launch share. The generic arm builds the command
        /// straight from the argv the operator typed: there is no adapter to ask,
        /// nothing is derived and nothing is reinterpreted, so the result is
        /// verbatim rather than "from the adapter" and there is no error a live
        /// launch could fail on.
        fn launch_command(
            &self,
            handle: &RegistrationHandle,
        ) -> (std::process::Command, super::PreviewFidelity, Option<String>) {
            match (&self.target, &self.integration) {
                (RunTarget::Command { program, args }, _) => {
                    let mut command = std::process::Command::new(program);
                    command.args(args);
                    (command, super::PreviewFidelity::Verbatim, None)
                }
                (target, Some(integration)) => {
                    integration.launch_command(self.args, &target.label(), handle, self.network.endpoint())
                }
                // A dev-tool target is only ever constructed alongside its
                // adapter, so nothing in this binary reaches here. It degrades
                // visibly rather than panicking: a launcher that aborts the
                // process tells the operator less than one that names what it
                // could not derive.
                (target, None) => {
                    let mut command = std::process::Command::new(&*target.label());
                    command.args(&self.args.tool_args);
                    (
                        command,
                        super::PreviewFidelity::Degraded(format!(
                            "no adapter was resolved for {}, so the command and environment below \
                             omit everything one contributes — including NODE_EXTRA_CA_CERTS and \
                             the normalised proxy URL, whose absence is what makes a session \
                             ungoverned.",
                            target.label()
                        )),
                        None,
                    )
                }
            }
        }

        /// The launch-only view of this plan, or `None` for a preview.
        pub(super) fn launchable(&self) -> Option<Launchable<'_>> {
            match self.posture {
                PlanPosture::Preview => None,
                PlanPosture::Launch => Some(Launchable {
                    info: self.integration.as_ref().map(|integration| {
                        integration
                            .detected
                            .as_ref()
                            .expect("a Launch-posture plan refuses when the tool is not installed")
                    }),
                    policy: self
                        .policy
                        .document
                        .as_ref()
                        .expect("a Launch-posture plan refuses when no policy is enforceable"),
                }),
            }
        }
    }

    /// Resolves one `aasm run` invocation into a [`ResolvedRunPlan`].
    pub(super) struct RunPlanner<'a> {
        args: &'a RunArgs,
        target: RunTarget,
        /// `None` for a generic command. Not an unfinished case: a program the
        /// operator owns has no dev-tool adapter, and supplying an inert one would
        /// make "this launch has no managed integration" indistinguishable from
        /// "this launch has one that does nothing".
        adapter: Option<&'a dyn DevToolAdapter>,
    }

    impl<'a> RunPlanner<'a> {
        /// A planner for `args`, launching `target` through `adapter`.
        pub(super) fn new(args: &'a RunArgs, target: RunTarget, adapter: Option<&'a dyn DevToolAdapter>) -> Self {
            Self { args, target, adapter }
        }

        /// Resolve every input this launch depends on, in the order the launch
        /// commits to them.
        ///
        /// The order is load-bearing and unchanged: **detect → proxy →
        /// `--no-proxy` guard → policy**, all of it before the caller registers
        /// anything. A launch that is going to be refused must not first create a
        /// gateway registration it then abandons, and a refusal issued after a
        /// child has started is not a refusal at all.
        ///
        /// Each stage announces itself on stderr where it resolves, so the
        /// operator sees the same trace, in the same order, as before this was
        /// one function. That is also why the planner is not pure: the trace is
        /// interleaved with the refusals, and hoisting it would either reorder
        /// the output or print a `policy=` line for a launch the proxy stage had
        /// already refused.
        ///
        /// Returns `Err` only under [`PlanPosture::Launch`]. A preview resolves
        /// infallibly by construction — every refusal it meets is reported and
        /// recorded rather than raised.
        pub(super) fn resolve(self, posture: PlanPosture) -> anyhow::Result<ResolvedRunPlan<'a>> {
            let enforcement_mode = self.args.resolved_enforcement_mode();

            // 0. Working directory. A pure check of the operator's own argument:
            //    it starts nothing, writes nothing and reaches no network, so it
            //    is free to run before everything else — and running it first is
            //    what keeps a launch that cannot start where it was told to from
            //    creating a gateway registration it then abandons. The relative
            //    order of every stage below is unchanged by it.
            if let Some(dir) = &self.args.workdir {
                if !dir.is_dir() {
                    posture.refuse(anyhow::anyhow!(
                        "--workdir {} is not a directory on this host",
                        dir.display()
                    ))?;
                }
            }

            // 1. Integration. A live launch of a tool that is not installed stops
            //    here. A preview does not: previewing a launch from CI, or from a
            //    machine still being set up, is the case `--dry-run` is most
            //    useful for, so it continues and degrades visibly instead
            //    (AAASM-5329 AC 3).
            //
            //    A generic command is not probed at all. `aasm run` has no adapter
            //    for it and no way to detect it, and refusing on a `PATH` lookup
            //    would be a claim about a program it does not manage — the `exec`
            //    itself is the test, and its failure is the operator's own
            //    `No such file or directory`.
            let integration = self.adapter.map(IntegrationPlan::probe);
            if posture == PlanPosture::Launch {
                match &integration {
                    Some(integration) => {
                        let info = integration
                            .detected()
                            .ok_or_else(|| anyhow::anyhow!("{} is not installed", self.target.label()))?;
                        eprintln!(
                            "tool={} version={} path={} governance_level={}",
                            self.target.label(),
                            info.version.as_deref().unwrap_or("unknown"),
                            info.install_path.display(),
                            info.governance_level,
                        );
                    }
                    None => eprintln!("command={}", self.target.label()),
                }
            }

            // 2. Network. Only the `--no-proxy` opt-out is decided here — the
            //    endpoint itself is deliberately left unresolved.
            //
            //    AAASM-5863 (Option 2, AAASM-5857): a governed launch's proxy is
            //    configured with the *registered* agent_id, so it cannot be
            //    started before registration exists — starting one earlier
            //    would mean either configuring it with an unauthenticated
            //    claim, or leaving it unattributed, both of which this
            //    architecture exists to rule out. `execute_with_adapters` fills
            //    `network.endpoint` in once registration has produced a real
            //    identity and the dedicated proxy for this launch is ready, or
            //    refuses the launch before anything is spawned if the proxy
            //    never comes up (see `ProxyGuard::spawn`). Stage 3 below still
            //    needs the `no_proxy` flag itself before registration, so it is
            //    decided here; only the address is deferred.
            if self.args.no_proxy {
                eprintln!(
                    "warning: --no-proxy — launching WITHOUT interception. This session's traffic is \
                     not inspected and no egress policy applies to it."
                );
            } else if super::ambient_proxy_is_set() {
                // AAASM-5892: `build_child_env` always replaces an ambient
                // `HTTPS_PROXY`/`HTTP_PROXY` with the trusted governed endpoint
                // (correctly — an ambient value is not authoritative, see that
                // function's doc comment). That override was previously silent,
                // so an operator whose pre-existing proxy also performed
                // authentication saw only a downstream auth failure with no clue
                // AASM had touched their routing. Name-only: the value itself is
                // never printed.
                eprintln!(
                    "warning: an ambient HTTPS_PROXY/HTTP_PROXY is set and will be replaced by this \
                     launch's governed proxy endpoint. If that proxy also performs authentication for \
                     your environment, this session may fail to authenticate; re-run with --no-proxy \
                     to keep your own proxy instead."
                );
            }

            // 3. AAASM-5350 AC 1: `--no-proxy` is refused where a party other
            //    than the invoking user has already decided this host runs
            //    managed. Checked before the policy resolves and before anything
            //    is registered or started, for the same reason the policy refusal
            //    is: refusing after a launch has begun is not refusing.
            //
            //    Launch-only, and that asymmetry is inherited rather than
            //    introduced here — the preview has never run this guard. It is
            //    now at least visible in one place instead of being an absence,
            //    and extending it to the preview is a behaviour change this
            //    refactor deliberately does not make.
            //
            //    Applied to a generic command too, keyed by the program name as
            //    typed. That catches `aasm run exec --no-proxy -- claude` on a
            //    host where someone else required managed operation of Claude
            //    Code, which is worth catching. It is a **name-shaped lower
            //    bound**, not a barrier: an absolute path, a symlink or a renamed
            //    copy resolves to no dev-tool kind and so meets no refusal here.
            if self.args.no_proxy && posture == PlanPosture::Launch {
                if let Some(refusal) = super::no_proxy_refusal(&self.target.label()) {
                    anyhow::bail!("{refusal}");
                }
            }

            // 4. Policy. A session with no effective policy is refused here,
            //    before any registration exists: a registered session that never
            //    launched is a governed identity with no process behind it, and
            //    an absent policy is not permission (AAASM-5349).
            let resolution = super::resolve_policy(self.args);
            let document = match resolution.clone().into_enforceable() {
                Ok(document) => Some(document),
                Err(e) => {
                    posture.refuse(e)?;
                    None
                }
            };

            // 5. Execution isolation. Last, because it is lowered from the
            //    policy stage 4 resolved and because selecting a backend probes
            //    the host — work a launch already refused should not do. Still
            //    before any registration exists: a boundary that cannot be
            //    provided refuses here, not after a governed identity has been
            //    created for a session that will not run.
            let isolation = Self::resolve_isolation(self.args, posture, &resolution)?;

            Ok(ResolvedRunPlan {
                args: self.args,
                posture,
                target: self.target,
                identity: IdentityPlan::of(self.args),
                integration,
                network: NetworkPlan {
                    endpoint: None,
                    no_proxy: self.args.no_proxy,
                },
                policy: PolicyPlan { resolution, document },
                isolation,
                enforcement_mode,
            })
        }

        /// Lower the effective policy onto capability requirements and select a
        /// backend to meet them, or record why there is none.
        ///
        /// The lowering happens for **every** launch, including `--isolation
        /// none`. That is not wasted work: it is what lets the report say, per
        /// domain, whether the operator left a policy node unset or whether the
        /// schema has no node to set. A run with no boundary that also said
        /// nothing about what policy asked for would report all nine domains as
        /// `not_derived`, which reads as "nothing to see" rather than as "no
        /// boundary was established".
        ///
        /// Selection refuses rather than degrading. Every path out of here that
        /// leaves `backend: None` while the operator asked for one has already
        /// gone through [`PlanPosture::refuse`], so under
        /// [`PlanPosture::Launch`] it is unreachable — a preview reports the
        /// refusal and carries on, which is what a preview is for.
        fn resolve_isolation(
            args: &RunArgs,
            posture: PlanPosture,
            resolution: &run_policy::PolicyResolution,
        ) -> anyhow::Result<IsolationPlan> {
            let lowering = resolution
                .canonical()
                .map(|document| aa_isolation::lower_policy(document, &aa_isolation::LoweringOptions::strict()));

            if args.isolation == super::IsolationIntent::None {
                // Naming a backend for a launch that asked for no boundary is a
                // contradiction, and honouring one half of it silently would
                // leave the operator believing the other half took effect.
                if let Some(id) = &args.isolation_backend {
                    posture.refuse(anyhow::anyhow!(
                        "--isolation-backend {id} names a backend, but --isolation is `none`, so this launch \
                         establishes no execution-isolation boundary for a backend to provide. Add \
                         `--isolation auto` (or `process`), or drop --isolation-backend."
                    ))?;
                }
                return Ok(IsolationPlan {
                    lowering,
                    backend: None,
                    absent: Some(
                        "no execution-isolation boundary was requested (`--isolation none`, the default), so \
                         no backend was consulted and nothing was negotiated, prepared or applied. This is \
                         the pre-existing behaviour of `aasm run`, stated rather than left to be inferred \
                         from an absence"
                            .to_string(),
                    ),
                    selection: None,
                });
            }

            // A named backend always wins, whichever isolation class asked for
            // it: it is the operator overriding selection outright, and
            // `--isolation auto --isolation-backend X` must behave exactly as
            // `--isolation process --isolation-backend X` does, not run
            // automatic selection and then check whether it agreed.
            if let Some(id) = &args.isolation_backend {
                return explicit_backend(id, args.isolation, lowering, posture);
            }

            if args.isolation == super::IsolationIntent::Auto {
                return auto_select(&lowering, posture);
            }

            // `--isolation process` with no backend named. The default is
            // unchanged by AAASM-5802 or by this ticket. ADR 0035's AAASM-5801
            // amendment is explicit that which backend a deployment uses by
            // default "is an evidence-based decision to be made later, under
            // AAASM-5805, once both backends have comparable measured evidence —
            // it is not pre-decided by naming the native backend here". So the
            // second backend is reachable only by naming it, and `process`
            // without a name stays hardcoded to `sandlock`.
            explicit_backend(aa_isolation_sandlock::BACKEND_ID, args.isolation, lowering, posture)
        }
    }

    /// Select the backend named by `requested`, or record why there is none.
    ///
    /// The single path for a backend the operator named directly — by
    /// `--isolation-backend`, or implicitly via `--isolation process`'s
    /// hardcoded default. Both must refuse for an unknown id and for an
    /// unavailable backend in exactly the same words, which is what pulling
    /// this out of [`RunPlanner::resolve_isolation`] guarantees rather than
    /// leaves to two call sites staying in sync by hand.
    fn explicit_backend(
        requested: &str,
        intent: super::IsolationIntent,
        lowering: Option<aa_isolation::PolicyLowering>,
        posture: PlanPosture,
    ) -> anyhow::Result<IsolationPlan> {
        let backend = match requested {
            id if id == aa_isolation_sandlock::BACKEND_ID => {
                // Discovery measures the host; it starts nothing and confines
                // nothing, so a preview may call it too — and must, or the
                // preview would describe a boundary the live launch could not
                // build.
                SelectedBackend::Sandlock(aa_isolation_sandlock::SandlockBackend::discover())
            }
            id if id == aa_isolation_native::BACKEND_ID => {
                SelectedBackend::Native(aa_isolation_native::NativeBackend::discover())
            }
            id if id == aa_isolation_macos_vm::BACKEND_ID => {
                SelectedBackend::MacosVm(aa_isolation_macos_vm::MacosVmBackend::discover())
            }
            other => {
                posture.refuse(anyhow::anyhow!(
                    "--isolation-backend {other} names no backend this build has. The backends \
                     compiled in are `{}`, `{}` and `{}`. Backend ids are a diagnostic control and are not \
                     portable — `--isolation {}` asks for the isolation class instead, and survives a \
                     backend change.",
                    aa_isolation_sandlock::BACKEND_ID,
                    aa_isolation_native::BACKEND_ID,
                    aa_isolation_macos_vm::BACKEND_ID,
                    match intent {
                        super::IsolationIntent::Auto => "auto",
                        _ => "process",
                    },
                ))?;
                return Ok(IsolationPlan {
                    lowering,
                    backend: None,
                    absent: Some(format!("no backend answers to the id `{other}` in this build")),
                    selection: None,
                });
            }
        };

        if let aa_isolation::BackendAvailability::Unavailable { reason } = backend.capabilities().availability().clone()
        {
            posture.refuse(anyhow::anyhow!(
                "refusing to launch: an execution-isolation boundary was requested and the `{requested}` \
                 backend cannot be selected on this host — {reason}.\n\
                 \n\
                 There is no fallback. A launch that asked for a boundary and quietly ran without one \
                 would report as governed while being unconfined, which is the failure this mode \
                 exists to prevent. Install the backend, or re-run with `--isolation none` to launch \
                 unconfined deliberately.",
            ))?;
            return Ok(IsolationPlan {
                lowering,
                backend: None,
                absent: Some(format!(
                    "an execution-isolation boundary was requested and no backend could be selected on \
                     this host: {reason}"
                )),
                selection: None,
            });
        }

        Ok(IsolationPlan {
            lowering,
            backend: Some(backend),
            absent: None,
            selection: None,
        })
    }

    /// A throwaway [`ExecutionSpec`] carrying `lowering`'s requirements, for
    /// probing whether a candidate backend can plan a launch — before any real
    /// launch exists to build one from.
    ///
    /// This is the eligibility oracle the whole design turns on: `narrow_for`
    /// and `negotiate` read only [`ExecutionSpec::requirements`], never the
    /// program, args, identity, working directory or credentials (pinned by
    /// `probe_spec_and_real_spec_produce_the_same_verdict` in
    /// `aa-isolation/tests/negotiation.rs`), so a probe spec built from nothing
    /// but the lowered requirements gets the identical verdict a real launch's
    /// negotiation would reach. `None` when the lowering has nothing to lower —
    /// the existing `NoRequirementsLowered` refusal in
    /// [`IsolationPlan::resolve_boundary`] handles that case; this function
    /// does not duplicate it.
    fn probe_spec(lowering: &aa_isolation::PolicyLowering) -> Option<ExecutionSpec> {
        let throwaway = ExecutionSpec::new("probe", IdentityRef::root("probe"));
        lowering.apply_to(throwaway).ok()
    }

    /// Walk the fixed, ordered candidate list and select the first backend that
    /// can plan this launch's lowered requirements, or refuse naming every
    /// candidate and why it was rejected.
    ///
    /// "Eligible" means `backend.plan(probe_spec).is_ok()` — the same
    /// `plan()`/`negotiate()` machinery a real launch uses, not a hand-written
    /// comparison of what each backend's capability gaps are known to be. That
    /// is deliberate: sandlock and the native backend's gaps are complementary
    /// rather than nested, so a domain-subset comparison would have to be kept
    /// in step with both backends by hand, and the negotiation machinery
    /// already has to be right for every other code path.
    fn auto_select(
        lowering: &Option<aa_isolation::PolicyLowering>,
        posture: PlanPosture,
    ) -> anyhow::Result<IsolationPlan> {
        const CANDIDATES: [&str; 3] = [
            aa_isolation_sandlock::BACKEND_ID,
            aa_isolation_native::BACKEND_ID,
            aa_isolation_macos_vm::BACKEND_ID,
        ];

        let Some(probe) = lowering.as_ref().and_then(probe_spec) else {
            // Nothing to lower — the existing `NoRequirementsLowered` refusal
            // in `resolve_boundary` fires downstream against today's default
            // candidate. Refusing here as well would duplicate that message
            // under a different name.
            return Ok(IsolationPlan {
                lowering: lowering.clone(),
                backend: Some(SelectedBackend::Sandlock(
                    aa_isolation_sandlock::SandlockBackend::discover(),
                )),
                absent: None,
                selection: None,
            });
        };

        let mut considered = Vec::new();
        for id in CANDIDATES {
            let backend = if id == aa_isolation_sandlock::BACKEND_ID {
                SelectedBackend::Sandlock(aa_isolation_sandlock::SandlockBackend::discover())
            } else if id == aa_isolation_native::BACKEND_ID {
                SelectedBackend::Native(aa_isolation_native::NativeBackend::discover())
            } else {
                debug_assert_eq!(
                    id,
                    aa_isolation_macos_vm::BACKEND_ID,
                    "CANDIDATES names every arm below"
                );
                SelectedBackend::MacosVm(aa_isolation_macos_vm::MacosVmBackend::discover())
            };

            // The candidate's own advertised identity, not the loop's literal
            // — a considered-backend record must name the backend that was
            // actually probed, not merely the id the walk expected it under.
            let backend_id = backend.identity().id;

            if let aa_isolation::BackendAvailability::Unavailable { reason } =
                backend.capabilities().availability().clone()
            {
                considered.push(aa_isolation::ConsideredBackend {
                    id: backend_id,
                    verdict: aa_isolation::CandidateVerdict::RejectedUnavailable,
                    detail: format!("the backend cannot be selected on this host — {reason}"),
                    unmet_domains: Vec::new(),
                });
                continue;
            }

            match backend.plan(&probe) {
                Ok(_) => {
                    considered.push(aa_isolation::ConsideredBackend {
                        id: backend_id,
                        verdict: aa_isolation::CandidateVerdict::Selected,
                        detail: "this candidate could plan the launch's lowered requirements".to_string(),
                        unmet_domains: Vec::new(),
                    });
                    return Ok(IsolationPlan {
                        lowering: lowering.clone(),
                        backend: Some(backend),
                        absent: None,
                        selection: Some(aa_isolation::BackendSelection {
                            mode: aa_isolation::SelectionMode::Automatic,
                            considered,
                        }),
                    });
                }
                Err(refusal) => {
                    let unmet_domains = refusal
                        .unmet()
                        .iter()
                        .filter_map(|(_, reason)| reason.domain())
                        .collect();
                    considered.push(aa_isolation::ConsideredBackend {
                        id: backend_id,
                        verdict: aa_isolation::CandidateVerdict::RejectedRequirementsUnmet,
                        detail: super::describe_refusal(&refusal),
                        unmet_domains,
                    });
                }
            }
        }

        let names = considered
            .iter()
            .map(|c| format!("  - {}: {}", c.id, c.detail))
            .collect::<Vec<_>>()
            .join("\n");
        posture.refuse(anyhow::anyhow!(
            "refusing to launch: --isolation auto walked every backend this build has and none of them \
             can plan this launch's lowered requirements.\n{names}\n\
             \n\
             There is no fallback. Use --isolation-backend to see one backend's full refusal, or \
             --isolation none to launch unconfined deliberately.",
        ))?;

        Ok(IsolationPlan {
            lowering: lowering.clone(),
            backend: None,
            absent: Some(format!(
                "--isolation auto found no backend on this host that can plan this launch's lowered \
                 requirements; considered: {}",
                considered.iter().map(|c| c.id.clone()).collect::<Vec<_>>().join(", ")
            )),
            selection: Some(aa_isolation::BackendSelection {
                mode: aa_isolation::SelectionMode::Automatic,
                considered,
            }),
        })
    }

    impl PlanPosture {
        /// Apply this posture's disposition to an unmet precondition: a live
        /// launch stops, a preview reports it and carries on.
        ///
        /// The preview wording is deliberate and unchanged — an operator ran
        /// `--dry-run` to find out what a live run would do, and "it would
        /// refuse" is the most useful answer it can give.
        fn refuse(self, error: anyhow::Error) -> anyhow::Result<()> {
            match self {
                Self::Launch => Err(error),
                Self::Preview => {
                    eprintln!("warning: {error}");
                    eprintln!("warning: a live `aasm run` with these flags would refuse to launch.");
                    Ok(())
                }
            }
        }
    }
}

/// Stable string form of an [`aa_core::EnforcementMode`] used on the wire to
/// the gateway and inside the `AA_ENFORCEMENT_MODE` child env var. Matches the
/// `serde(rename_all = "snake_case")` encoding so a round-trip via YAML/JSON
/// produces the same token.
pub(crate) fn enforcement_mode_str(mode: aa_core::EnforcementMode) -> &'static str {
    match mode {
        aa_core::EnforcementMode::Enforce => "enforce",
        aa_core::EnforcementMode::Observe => "observe",
        aa_core::EnforcementMode::Disabled => "disabled",
    }
}

/// Convert a [`DevToolKind`] to the snake_case string sent in the registration request body.
fn dev_tool_kind_str(kind: &DevToolKind) -> String {
    match kind {
        DevToolKind::ClaudeCode => "claude_code".into(),
        DevToolKind::Codex => "codex".into(),
        DevToolKind::GitHubCopilot => "github_copilot".into(),
        DevToolKind::WindsurfCascade => "windsurf_cascade".into(),
        DevToolKind::Custom(s) => s.clone(),
    }
}

/// Identity for a single `aasm run` session, as the launched tool sees it.
///
/// Deliberately carries no proxy address. The gateway used to return one, and
/// `aasm run` used to route the launched tool at it; that made a remote,
/// unauthenticated field the authority on where this machine's traffic goes,
/// and — because nothing ever populated it — meant every launch went out
/// unproxied while reporting as governed. The endpoint is now a host fact
/// resolved by [`crate::commands::proxy::trust`] and is never carried on the
/// registration path (AAASM-5323).
///
/// It also carries no credential token. The token the gateway mints
/// authenticates *as the registered agent*; the launched tool is the software
/// that registration exists to govern, so it is the last process that should be
/// able to speak for its own governance record.
///
/// Which of these values the *server* issued, and which this process minted, is
/// no longer left to guesswork — the three fields that used to be
/// `response.field.unwrap_or_else(Uuid::new_v4)` looked server-issued and never
/// were:
///
/// * `agent_id` / `registration_did` / `registration_id` are identity. They are
///   derived from, and accepted by, the gateway (see
///   [`crate::commands::run_registration`]).
/// * `trace_id` / `session_id` are **locally minted correlation ids**, because
///   the registration contract has no server-side model for either. Naming that
///   plainly is the point: a value the gateway never saw must not be presented
///   as one it issued.
struct RegistrationHandle {
    /// The operator-facing identifier the session's keypair is derived from.
    agent_id: String,
    /// The `did:key` the gateway registered this session under — the identity
    /// audit attributes the session's actions to.
    registration_did: String,
    /// The gateway's registry key for this agent, hex-encoded (32 hex chars).
    registration_id: String,
    /// Locally minted; correlates this launch's records with each other. There
    /// is no server-issued trace id at registration time to prefer over it.
    trace_id: String,
    /// Locally minted; identifies this single `aasm run` invocation.
    session_id: String,
    /// Carried from [`RunArgs::team_id`] (or echoed by the gateway) for `AA_TEAM_ID` injection.
    team_id: Option<String>,
}

impl RegistrationHandle {
    /// The launched tool's view of an accepted registration, plus this
    /// invocation's freshly minted correlation ids.
    fn of(registration: &GovernedRegistration) -> Self {
        Self {
            agent_id: registration.agent_id.clone(),
            registration_did: registration.registration_did.clone(),
            registration_id: registration.registration_id.clone(),
            trace_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            team_id: registration.team_id.clone(),
        }
    }
}

/// RAII guard that releases the gateway registration on drop.
///
/// The primary deregistration path is the explicit `deregister_with_gateway`
/// async call in `execute_with_adapters`. Set `deregistered = true` after that
/// call to suppress the duplicate backup. The backup fires only when a panic
/// unwinds the stack before the explicit call can run.
///
/// It releases the registration over the same gRPC service that granted it,
/// authenticated by that registration's own credential token. The
/// `DELETE /api/v1/agents/{id}` this guard used to send could not have worked
/// even in principle: that route parses `{id}` as 32 hex characters
/// (`aa-api/src/routes/agents.rs`) and the id being sent was a dashed UUID, so
/// every teardown was a `400` — and it is authenticated as the *operator*, not
/// as the agent, which is a different principal than the one that registered.
pub struct RegistrationGuard {
    registration: GovernedRegistration,
    /// True after `deregister_with_gateway` ran; suppresses the backup Drop.
    pub deregistered: bool,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        if self.deregistered {
            return;
        }
        let registration = self.registration.clone();
        // Spawn a detached OS thread so we never block or create a runtime inside
        // an existing tokio async context. Fire-and-forget: not guaranteed to reach
        // the gateway before process termination (panic path only).
        let _ = std::thread::spawn(move || {
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                rt.block_on(run_registration::deregister(&registration, "aasm run panicked"));
            }
        });
    }
}

/// Register the detected tool with the Agent Assembly gateway.
///
/// Goes through [`crate::commands::run_registration`], which performs the same
/// `RequestChallenge` → sign → `Register` handshake, built by the same
/// `aa-sdk-client` code, that every SDK-instrumented agent performs. There is no
/// CLI-shaped shortcut around it: the gateway applies its `did:key`↔`public_key`
/// binding and its possession-proof check to this request exactly as it does to
/// an SDK's.
/// `identity` supplies the agent id, team and lineage. It is the same
/// [`plan::IdentityPlan`] a `--dry-run` preview derives its printed identity
/// from, so the preview cannot advertise an identity the live run would not have
/// submitted.
async fn register_with_gateway(
    subject: &SessionSubject,
    identity: &plan::IdentityPlan,
    mode: aa_core::EnforcementMode,
) -> Result<GovernedRegistration> {
    let agent_id = identity.agent_id(plan::PlanPosture::Launch);

    run_registration::register(run_registration::SessionDescriptor {
        agent_id: &agent_id,
        name: &subject.name,
        version: &subject.version,
        team_id: identity.team_id(),
        parent_agent_id: identity.root_agent(),
        enforcement_mode: mode,
        governance_level: &subject.governance_level,
    })
    .await
    .map_err(|e| anyhow::anyhow!("refusing to launch unregistered: {e}"))
}

/// What a launch registers *as* — the descriptive half of the request, none of
/// which the gateway's gate consults.
///
/// Derived per target rather than shared, because the two kinds can honestly say
/// different things and neither may borrow the other's words.
///
/// A generic command reports:
///
/// * `name` — the program the operator named, prefixed `command:`. The prefix is
///   deliberate: without it `aasm run exec -- claude_code` would land in the
///   registry under the same name a managed Claude Code session registers under,
///   and an audit reader would have no way to tell an adapter-governed launch
///   from an arbitrary program that happens to be called that.
/// * `version` — `unknown`, and honestly so. `aasm run` does not probe an
///   arbitrary program for a version, and inventing one would put a value in the
///   registry that nothing measured.
/// * `governance_level` — [`GovernanceLevel::L0Discover`], which is the level a
///   launch with no adapter actually reaches: no managed settings, no MCP
///   governance, and only what the proxy sees of its traffic. Claiming a higher
///   level for a program `aasm run` cannot configure would be a protection claim
///   nothing delivers.
struct SessionSubject {
    name: String,
    version: String,
    governance_level: String,
}

impl SessionSubject {
    /// The subject `target` registers under. `info` is the adapter's detection
    /// result, and is `None` exactly when the target is a generic command.
    fn of(target: &plan::RunTarget, info: Option<&DevToolInfo>) -> Self {
        match info {
            Some(info) => Self {
                name: dev_tool_kind_str(&info.kind),
                version: info.version.clone().unwrap_or_else(|| "unknown".into()),
                governance_level: info.governance_level.to_string(),
            },
            None => Self {
                name: format!("command:{}", target.label()),
                version: "unknown".into(),
                governance_level: GovernanceLevel::L0Discover.to_string(),
            },
        }
    }
}

/// Sandbox banner printed to stderr when `--observe` is in effect. The text is
/// stable so audit / log scrapers can match on it; future copy changes should
/// extend rather than replace the existing lines.
fn emit_observe_banner() {
    eprintln!("⚠️  [AAASM] Running in sandbox/observe mode.");
    eprintln!("    Policy decisions are recorded but NOT enforced.");
    eprintln!("    Review captured events: aasm audit list --dry-run-only");
}

/// Whether a non-empty `HTTPS_PROXY`/`HTTP_PROXY` is already set in this
/// process's environment — i.e. what a governed launch is about to override.
/// Presence-only, by design: callers warn that an ambient proxy exists, never
/// what it points at (AAASM-5892/5897).
fn ambient_proxy_is_set() -> bool {
    ["HTTPS_PROXY", "HTTP_PROXY"]
        .iter()
        .any(|key| std::env::var(key).is_ok_and(|v| !v.is_empty()))
}

/// Build the environment map to be inherited by the child process.
///
/// Starts from the current process environment, then overlays governance
/// identity variables.
///
/// # Proxy variables
///
/// `proxy` is the endpoint [`crate::commands::proxy::trust`] vouched for, or
/// `None`. The three cases are distinct and none of them is "leave whatever was
/// there":
///
/// * `Some(url)` — both variables are set to it, overwriting anything the
///   operator's shell had. An ambient `HTTPS_PROXY` is an environment-supplied
///   proxy address, which is exactly the class of input this feature exists to
///   stop treating as authoritative.
/// * `None` with `no_proxy` — the operator asked for an unproxied launch, so
///   their own proxy configuration is left alone. This is the documented
///   opt-out, not a fallback.
/// * `None` without `no_proxy` — reachable only from `--dry-run`, since a live
///   launch refuses before it gets here. The variables are *removed* so the
///   preview cannot show an ambient proxy and read as a governed launch.
///
/// `AA_ENFORCEMENT_MODE` is set whenever `mode` differs from the pre-feature
/// default (`Enforce`) so tools that branch on the env var see the operator's
/// explicit choice; the variable is omitted in plain enforce-mode launches to
/// avoid surprising any tool that does best-effort env sniffing.
fn build_child_env(
    handle: &RegistrationHandle,
    proxy: Option<&str>,
    no_proxy: bool,
    mode: aa_core::EnforcementMode,
) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("AA_AGENT_ID".into(), handle.agent_id.clone());
    // The identity the gateway actually registered and audit attributes actions
    // to. Exported so anything downstream — an SDK inside the launched tool, a
    // log scraper joining child output to a registry record — can name it
    // without re-deriving it, and so a mismatch between the launched session and
    // the registered one is visible rather than assumed.
    env.insert("AA_AGENT_DID".into(), handle.registration_did.clone());
    env.insert("AA_TRACE_ID".into(), handle.trace_id.clone());
    env.insert("AA_SESSION_ID".into(), handle.session_id.clone());
    env.insert("AA_REGISTRATION_ID".into(), handle.registration_id.clone());
    if let Some(ref team_id) = handle.team_id {
        env.insert("AA_TEAM_ID".into(), team_id.clone());
    }
    match proxy {
        Some(url) => {
            env.insert("HTTPS_PROXY".into(), url.to_string());
            env.insert("HTTP_PROXY".into(), url.to_string());
        }
        None if !no_proxy => {
            env.remove("HTTPS_PROXY");
            env.remove("HTTP_PROXY");
        }
        None => {}
    }
    if mode != aa_core::EnforcementMode::Enforce {
        env.insert("AA_ENFORCEMENT_MODE".into(), enforcement_mode_str(mode).into());
    }
    env
}

/// Resolve the endpoint this launch will be routed through, or explain why the
/// launch must not happen.
///
/// The only `Ok(None)` is the operator's explicit `--no-proxy`. Every other
/// outcome is either a vouched-for endpoint or a refusal: there is no path from
/// "the proxy could not be verified" to "launch anyway", because that path is a
/// direct, uninspected connection made by a session presenting as governed.
/// The authoritative refusal, if any, for a `--no-proxy` launch of `tool`.
///
/// Reads both sources AC 1 names and lets
/// [`crate::commands::run_no_proxy_guard::refusal_for`] decide, so the decision lives in one
/// tested place rather than being spelled out at the call site.
///
/// A receipt that cannot be read is treated as **no receipt** rather than as a
/// refusal: an unreadable receipt is not evidence that someone required managed
/// operation, and refusing on it would turn a corrupt file into a policy. The
/// managed-settings source is unaffected and still refuses on its own.
///
/// # Scope (AAASM-5907)
///
/// Checks the Project-scope receipt for this launch's `cwd` *before* falling
/// back to User scope — Claude Code's own settings precedence layers Project
/// over User, so a project explicitly installed at `--scope project` must not
/// be silently invisible to this refusal just because it isn't the machine-wide
/// default.
///
/// [`ReceiptStore`](aa_core::integration::ReceiptStore) keys a receipt on
/// `(tool, scope)` alone, **not** on which project root it was installed
/// into — there is exactly one Project-scope receipt slot per tool on the
/// whole machine, shared across every project that ever installed at that
/// scope. Trusting it here for *any* cwd would misfire in an unrelated
/// directory that happens to have no relationship to the installed project.
/// So the Project-scope receipt is honoured only when its
/// `WriteManagedSettings` step's recorded `path` — the exact file the install
/// wrote, named at install time, never inferred from `cwd`
/// ([`StepAction::WriteManagedSettings`](aa_core::integration::step::StepAction::WriteManagedSettings))
/// — equals the Project-scope settings path for *this* `cwd`. A path match
/// means this cwd is (or was) the project that receipt was written for; a
/// mismatch or unresolvable `cwd` falls through to the User-scope check
/// unchanged.
fn no_proxy_refusal(tool: &str) -> Option<crate::commands::run_no_proxy_guard::RefusalSource> {
    use aa_core::integration::step::{SettingsScope, StepAction};

    let kind = aa_devtool::registry::kind_for(tool)?;
    let store = aa_core::integration::ReceiptStore::default_location().ok()?;

    let project_profile = std::env::current_dir().ok().and_then(|cwd| {
        let paths = aa_devtool_claude_code::scope::ClaudeCodePaths::from_env().with_project(cwd);
        let expected_path = paths.settings_path(SettingsScope::Project).ok()?;
        let receipt = store.load_receipt(&kind, SettingsScope::Project).ok().flatten()?;
        let installed_here = receipt.steps.iter().any(|step| {
            matches!(
                &step.action,
                StepAction::WriteManagedSettings { scope: SettingsScope::Project, path, .. }
                    if *path == expected_path
            )
        });
        installed_here.then_some(receipt.profile)
    });

    let user_profile = store
        .load_receipt(&kind, SettingsScope::User)
        .ok()
        .flatten()
        .map(|receipt| receipt.profile);

    // Project takes precedence when both exist, mirroring Claude Code's own
    // Project-over-User settings layering. `scope` travels with whichever
    // profile was actually used, so a reported refusal names the scope that
    // caused it rather than always claiming User.
    let (scope, receipt_profile) = match project_profile {
        Some(profile) => (SettingsScope::Project, Some(profile)),
        None => (SettingsScope::User, user_profile),
    };

    let managed = aa_devtool_claude_code::managed_settings::managed_installation_evidence().ok();

    crate::commands::run_no_proxy_guard::refusal_for(&kind, scope, receipt_profile, managed)
}

/// Resolve the effective policy for this launch, and announce which of the four
/// states it landed in.
///
/// This used to be a `load_policy()` that returned a hard-coded empty rule set,
/// which meant every `aasm run` delivered an intercepted, registered, monitored
/// launch enforcing nothing — and reported that as success. The banner is
/// unconditional for the same reason the observe-mode banner is: the posture a
/// session actually runs under has to be visible at the top of its output, not
/// inferred later from what the tool was or was not stopped from doing.
fn resolve_policy(args: &RunArgs) -> run_policy::PolicyResolution {
    let resolution = run_policy::resolve(args.policy.as_deref());
    // `summary()` already opens with the state token, so the `policy=<token>`
    // prefix an audit scraper matches on falls out of it without repeating it.
    eprintln!("policy={}", resolution.summary());
    resolution
}

/// Mask a credential-bearing env value before it is printed in the dry-run
/// preview. `build_child_env` seeds the child environment from the operator's
/// whole shell environment, so the preview would otherwise echo secrets
/// (`AA_JWT_SECRET`, `DB_PASSWORD`, connection URLs, …) in cleartext.
///
/// Two masking strategies, by key name (case-insensitive):
/// * keys naming a connection string (`*_URL` / `*_DSN` / `*_URI`) keep their
///   structure but have the password redacted via [`redact_database_url`],
///   matching how `aasm status` displays a `database_url`. `*_URI` covers the
///   common `MONGODB_URI` / `DATABASE_URI` / `REDIS_URI` / `AMQP_URI` shapes
///   that carry `user:pass@host` userinfo (AAASM-4936, sibling of AAASM-4894);
/// * keys whose name signals an opaque secret (token, key, password, secret,
///   credential, auth) have the entire value replaced — the value has no
///   structure worth preserving.
///
/// As a final fail-closed backstop, any value not caught by the rules above is
/// still routed through [`redact_database_url`]: a value in an unrecognised key
/// may itself be a `scheme://user:pass@host` connection string, and the
/// redactor returns the value unchanged unless it finds userinfo credentials to
/// strip — so ordinary values are untouched while an embedded credential is not
/// printed verbatim.
///
/// The denylist is intentionally broad and errs toward over-masking: a masked
/// non-secret in a diagnostic preview is harmless, a leaked secret is not.
fn mask_value(key: &str, value: &str) -> String {
    let upper = key.to_uppercase();
    if is_connection_string_name(&upper) {
        return redact_database_url(value);
    }
    if SECRET_SUBSTRINGS.iter().any(|needle| upper.contains(needle)) {
        return "***MASKED***".into();
    }
    redact_database_url(value)
}

/// Name fragments that signal an opaque secret, case-insensitive.
const SECRET_SUBSTRINGS: [&str; 7] = ["TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CREDENTIAL", "AUTH"];

/// Whether an already-uppercased name is a connection string — the shapes that
/// carry `user:pass@host` userinfo (AAASM-4936).
fn is_connection_string_name(upper: &str) -> bool {
    upper.ends_with("_URL") || upper.ends_with("_DSN") || upper.ends_with("_URI")
}

/// Whether an environment variable *name* suggests it carries credential
/// material.
///
/// A **name-shaped lower bound**, not a detector. It cannot see a secret in a
/// blandly-named variable, so a name that fails this test is not evidence that
/// its value is harmless, and an empty result is never evidence that no
/// credential is present.
///
/// Both callers want that bias and both err toward over-inclusion: one masks a
/// value before printing it in the `--dry-run` preview, the other records which
/// inherited authority reaches the launched child unvetted. Over-masking a
/// non-secret is harmless; under-recording ambient authority is not.
fn looks_like_credential_name(key: &str) -> bool {
    let upper = key.to_uppercase();
    is_connection_string_name(&upper) || SECRET_SUBSTRINGS.iter().any(|needle| upper.contains(needle))
}

/// How faithfully a preview reflects the launch it describes.
///
/// A preview that quietly drops adapter state is worse than no preview: the
/// operator ran it to check whether the session will be protected, and the
/// adapter contributes exactly the variables that decide that. So the shortfall
/// is a value carried into the output, not a log line — it prints whether or not
/// anyone is reading stderr.
enum PreviewFidelity {
    /// The command came from the adapter, as the live launch would build it.
    FromAdapter,
    /// The command is the operator's own program and argv, forwarded as typed.
    ///
    /// Distinct from [`FromAdapter`](Self::FromAdapter) rather than folded into
    /// it: a generic command has no adapter, so saying the preview was "derived
    /// from the adapter" would name a contribution that does not exist. It is
    /// equally not [`Degraded`](Self::Degraded) — nothing is missing, because
    /// there is nothing for an adapter to add.
    Verbatim,
    /// The adapter could not supply one; the preview is missing whatever it sets.
    Degraded(String),
}

/// The machine-readable isolation block, byte-identical on both surfaces.
///
/// `--dry-run` prints it to stdout beneath the operator render; a live launch
/// prints it to stderr, because stdout belongs to the launched tool. One
/// function emits it for both so a downstream dashboard or CI check does not
/// have to handle two shapes — and so the two cannot drift, which is the same
/// failure AAASM-5327 and AAASM-5329 were.
///
/// A consumer anchors on the header, then reads `key=value` records until the
/// first line that is not one. It never has to parse a sentence.
fn isolation_machine_block(report: &aa_isolation::IsolationReport) -> String {
    let mut out = String::from("--- execution isolation (machine-readable) ---\n");
    for line in report.machine_lines() {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Build the structured dry-run output string.
///
/// The `--- policy ---` section is the preview's receipt of which of the four
/// effective-policy states this launch resolved to. It is printed for all four,
/// including the two that would refuse: a preview that showed a policy section
/// only when one loaded would make "no policy at all" look like a formatting
/// quirk rather than the reason the live run stops.
///
/// The `--- execution isolation ---` section is the same receipt for the
/// execution boundary, rendered from the [`aa_isolation::IsolationReport`] the
/// live launch also emits (AAASM-5710). It is printed unconditionally for the
/// same reason: a section that appeared only once a backend was selected would
/// make "no boundary was established" look like a formatting quirk rather than
/// the state of the run.
// Eight parameters, one per section of the receipt. The obvious way to satisfy
// the lint is to take a `BoundLaunch` instead of the command, environment,
// fidelity and isolation report — but `BoundLaunch` is constructible only by
// `ResolvedRunPlan::bind`, deliberately, so that no caller can assemble a launch
// state that never went through the plan. Weakening that to quiet a parameter
// count would trade a real invariant for a cosmetic one.
#[allow(clippy::too_many_arguments)]
fn format_dry_run_output(
    handle: &RegistrationHandle,
    policy: &run_policy::PolicyResolution,
    no_proxy: bool,
    settings: &str,
    cmd: &std::process::Command,
    env: &HashMap<String, String>,
    fidelity: &PreviewFidelity,
    isolation: &aa_isolation::IsolationReport,
) -> String {
    const SETTINGS_LIMIT: usize = 1024;

    let truncated_settings = if settings.len() > SETTINGS_LIMIT {
        format!("{}... [truncated]", &settings[..SETTINGS_LIMIT])
    } else {
        settings.to_string()
    };

    let program = cmd.get_program().to_string_lossy().into_owned();
    let args_strs: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let cmd_line = if args_strs.is_empty() {
        program
    } else {
        format!("{} {}", program, args_strs.join(" "))
    };

    // Read back off the command rather than off the flag, so this reports the
    // directory the child is actually given — including one an adapter set that
    // the operator never asked for.
    let working_dir = cmd.get_current_dir().map_or_else(
        || "<inherited from this shell>".to_string(),
        |dir| dir.display().to_string(),
    );

    // Derived through the same merge `spawn_and_wait` applies, so the preview
    // cannot claim a variable the launch would not have — including one the
    // adapter removes, which a naive union of the two sources would still show.
    let (effective, removed) = effective_child_env(cmd, env);
    let mut env_lines: String = effective
        .iter()
        .map(|(k, v)| format!("{}={}\n", k, mask_value(k, v)))
        .collect();
    for name in &removed {
        env_lines.push_str(&format!("{name}=<removed by adapter>\n"));
    }

    let fidelity_line = match fidelity {
        PreviewFidelity::FromAdapter => "derived from the adapter, as the live launch builds it".to_string(),
        PreviewFidelity::Verbatim => "the program and argv you supplied, forwarded verbatim; a generic command has no \
             dev-tool adapter to contribute anything"
            .to_string(),
        PreviewFidelity::Degraded(why) => format!("DEGRADED — {why}"),
    };

    format!(
        "--- aasm run dry-run ---\nagent_id:    {}\nagent_did:   {}\ntrace_id:    {}\nsession_id:  {}\n\n--- preview fidelity ---\n{}\n\n--- protection ---\nstate:  {}\ndetail: {}\n\n--- policy ---\nstate:  {}\nsource: {}\ndetail: {}\n\n{}\n{}\n--- managed settings ---\n{}\n\n--- launch command ---\nworking_dir: {}\n{}\n\n--- environment ---\n{}",
        handle.agent_id,
        handle.registration_did,
        handle.trace_id,
        handle.session_id,
        fidelity_line,
        crate::commands::run_audit::protection_label(no_proxy),
        if no_proxy {
            "--no-proxy: nothing is intercepted, no egress policy applies, and nothing is inspected"
        } else {
            "a dedicated proxy is started for this launch only after it registers, so a preview \
             cannot show its address without starting one; whether interception works is \
             adjudicated at launch time, not asserted here"
        },
        policy.state_token(),
        policy.source().map_or("<none>".to_string(), |p| p.display().to_string()),
        policy.summary(),
        isolation.render(),
        isolation_machine_block(isolation),
        truncated_settings,
        working_dir,
        cmd_line,
        env_lines,
    )
}

/// The reserved `aasm run` target that launches a program the operator owns
/// rather than a managed developer tool (AAASM-5706).
///
/// It is resolved **only after** every tool id has failed to match, at both entry
/// points, so it can never shadow an existing `aasm run <tool>` form or one of
/// its aliases — if a tool were ever registered under this token the tool would
/// keep it. `exec_target_is_not_an_id_any_supported_tool_answers_to` pins the
/// other direction: today no tool answers to it, under either spelling.
const EXEC_TARGET: &str = "exec";

/// The canonical [`aa_devtool::registry`] token for any tool id `aasm run`
/// accepts, or `None` for an id no built-in tool answers to.
///
/// `run` and `aasm integrations` spell the same four tools differently: `run`
/// is keyed by the short registry tokens (`claude`, `copilot`, `windsurf`)
/// while the Developer Integration surface is keyed by each tool's wire id
/// (`claude-code`, `github-copilot`, `windsurf-cascade`) — which is also what
/// `aasm integrations list` prints in its `TOOL` column. Reading an id off the
/// discovery surface and typing it into `run` therefore failed for three of the
/// four tools (AAASM-5503). Both spellings now resolve here; the canonical
/// token is what the rest of `run` works with, so nothing downstream has to
/// know an alias was used.
///
/// The long ids are **derived**, not tabulated: each comes from projecting the
/// registry's own [`DevToolKind`] through the same
/// [`tool_id`](aa_runtime::devint::projection::tool_id) the DI wire uses. A
/// second copy of that mapping here is precisely the drift this fix closes — a
/// tool added to the registry picks up its alias with no edit to this function.
fn canonical_tool_id(id: &str) -> Option<&'static str> {
    aa_devtool::registry::SUPPORTED_TOOLS.iter().copied().find(|token| {
        *token == id
            || aa_devtool::registry::kind_for(token)
                .is_some_and(|kind| aa_runtime::devint::projection::tool_id(&kind) == id)
    })
}

/// Every tool id a launch would accept, canonical token first with its
/// Developer-Integration alias in parentheses when the two differ.
///
/// Built for the refusal below rather than stored, so a refusal can never list
/// a vocabulary the resolver does not actually implement.
fn accepted_tool_ids() -> String {
    aa_devtool::registry::SUPPORTED_TOOLS
        .iter()
        .map(|token| match aa_devtool::registry::kind_for(token) {
            Some(kind) => {
                let wire = aa_runtime::devint::projection::tool_id(&kind);
                if wire == *token {
                    (*token).to_string()
                } else {
                    format!("{token} ({wire})")
                }
            }
            None => (*token).to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Refuse an id no tool answers to, naming every id that would have worked.
///
/// Both spellings are listed because the user most likely arrived here having
/// copied one from `aasm integrations list`; a refusal that named only the
/// short tokens is what made that dead end hard to escape.
///
/// The generic target is named too, because "there is no adapter for my agent"
/// is the other reason to arrive here and the answer to it is no longer "you
/// cannot".
fn unknown_tool_error(tool: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "unknown tool: {tool}, supported: {}; to launch a program that is not a managed dev tool, \
         use `aasm run {EXEC_TARGET} [run-options] -- <program> [args...]`",
        accepted_tool_ids()
    )
}

/// Return the adapter for `tool`, or an error for unrecognised tool names.
///
/// Resolution goes through [`aa_devtool::registry`] — the same table
/// `aasm tools list` discovers with — so a tool cannot be launched with a
/// different adapter than the one discovery advertised (AAASM-5274). There is
/// no placeholder fallback: an unregistered tool is an error, never a silently
/// inert adapter.
///
/// `tool` may be either spelling; see [`canonical_tool_id`].
fn resolve_adapter(tool: &str) -> Result<Box<dyn DevToolAdapter>> {
    canonical_tool_id(tool)
        .and_then(aa_devtool::registry::adapter_for)
        .ok_or_else(|| unknown_tool_error(tool))
}

/// The command and argv this launch is recorded under in the audit trail.
///
/// A dev-tool launch is recorded under the canonical tool token and the arguments
/// forwarded to it, unchanged from before AAASM-5706. A generic command is
/// recorded under the program and argv the operator supplied, rendered with
/// `to_string_lossy`.
///
/// That lossiness is confined to the *record*: the child is spawned from the
/// [`OsString`](std::ffi::OsString)s in the target, so a byte an audit consumer
/// could not decode is replaced here and nowhere else. The launch is never
/// altered to suit what the trail can express.
fn audit_argv(target: &plan::RunTarget, args: &RunArgs) -> (String, Vec<String>) {
    match target {
        plan::RunTarget::DevTool { tool } => (tool.clone(), args.tool_args.clone()),
        plan::RunTarget::Command { program, args: argv } => (
            program.to_string_lossy().into_owned(),
            argv.iter().map(|arg| arg.to_string_lossy().into_owned()).collect(),
        ),
    }
}

/// Release the registration over the gRPC service that issued it.
///
/// Errors are silently discarded — the session is already over, and a gateway
/// that has gone away leaves the caller nothing to do about it.
async fn deregister_with_gateway(registration: &GovernedRegistration) {
    run_registration::deregister(registration, "aasm run session ended").await;
}

/// The environment a child launched with `cmd` will actually receive, and the
/// names the adapter wants *removed* from it.
///
/// Returned rather than applied so that `--dry-run` can show the same answer the
/// live launch acts on. A preview that recomputes this independently is a second
/// implementation of the merge, and the two would disagree the moment either
/// changed — which is the defect AAASM-5329 exists to fix.
///
/// `get_envs` yields `None` for a variable the adapter wants removed, which is
/// not the same request as setting it empty: an adapter that unsets a variable
/// to disable a tool behaviour must not have that turned into an
/// empty-but-present variable the tool then honours. Those names come back
/// separately because "absent" cannot be expressed as an entry in the map.
///
/// The adapter is applied **last and therefore wins** on a collision — it is the
/// layer that knows what the launched tool actually needs.
fn effective_child_env(
    cmd: &std::process::Command,
    child_env: &HashMap<String, String>,
) -> (BTreeMap<String, String>, Vec<String>) {
    let mut env: BTreeMap<String, String> = child_env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let mut removed = Vec::new();
    for (name, value) in cmd.get_envs() {
        let key = name.to_string_lossy().into_owned();
        match value {
            Some(value) => {
                env.insert(key, value.to_string_lossy().into_owned());
            }
            None => {
                env.remove(&key);
                removed.push(key);
            }
        }
    }
    (env, removed)
}

/// Spawn `cmd` as a tokio child process, forward SIGTERM/SIGINT on Unix,
/// and wait for the child to exit. Returns the child's exit code.
///
/// The child's environment is the union of `child_env` (the operator's shell
/// environment plus this session's governance identity) and the environment the
/// adapter set on `cmd`. The adapter is applied **last and therefore wins** on a
/// collision: it is the layer that knows what the launched tool actually needs —
/// `NODE_EXTRA_CA_CERTS` pointing at the proxy CA, without which the tool's
/// runtime refuses the intercepted TLS and the session is ungoverned while
/// looking governed — and it is the layer that normalises the gateway's bare
/// `host:port` proxy address into the `http://host:port` URL an HTTP client
/// accepts (AAASM-5324). Dropping the adapter's environment, as this function
/// did before AAASM-5327, silently defeated both.
///
/// # Why the working directory is copied across explicitly
///
/// `cmd` is a `std::process::Command` and this spawns a `tokio` one, so every
/// piece of state has to be carried over by name — nothing is inherited. The
/// working directory was the third thing to be lost that way: the plan set it,
/// `--dry-run` printed it, and the child started in the launcher's directory
/// regardless (AAASM-5706, caught by
/// `exec_starts_the_child_in_the_requested_working_directory`). Anything added to
/// the bound command in future has to be added here too.
async fn spawn_and_wait(cmd: std::process::Command, child_env: &HashMap<String, String>) -> Result<i32> {
    let (effective, removed) = effective_child_env(&cmd, child_env);

    let mut tokio_cmd = tokio::process::Command::new(cmd.get_program());
    tokio_cmd.args(cmd.get_args());
    tokio_cmd.envs(&effective);
    for name in &removed {
        tokio_cmd.env_remove(name);
    }
    if let Some(dir) = cmd.get_current_dir() {
        tokio_cmd.current_dir(dir);
    }

    let mut child = tokio_cmd.spawn()?;
    let child_pid = child.id().unwrap_or(0) as i32;

    #[cfg(unix)]
    let status = {
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
        let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = sigterm.recv() => {
                if child_pid > 0 {
                    // Safety: child_pid is a valid pid we just spawned.
                    unsafe { libc::kill(child_pid, libc::SIGTERM); }
                }
                child.wait().await?
            }
            _ = sigint.recv() => {
                if child_pid > 0 {
                    unsafe { libc::kill(child_pid, libc::SIGTERM); }
                }
                child.wait().await?
            }
            s = child.wait() => s?
        }
    };

    #[cfg(not(unix))]
    let status = child.wait().await?;

    Ok(status.code().unwrap_or(1))
}

/// One operator-facing sentence per reason a backend refused a launch.
///
/// Every reason, not just the first: an operator fixing one at a time and
/// re-running would otherwise discover them serially, which is the reason
/// `PlanRefusal` collects them all rather than short-circuiting.
fn describe_refusal(refusal: &aa_isolation::PlanRefusal) -> String {
    let mut out = format!(
        "the `{}` backend refused this launch before anything started",
        refusal.backend().id
    );
    if let Some(reason) = refusal.backend_unavailable() {
        out.push_str(&format!("\n  - the backend cannot be selected on this host: {reason}"));
    }
    for (requirement, reason) in refusal.unmet() {
        out.push_str(&format!(
            "\n  - {}: {}",
            requirement.domain(),
            describe_refusal_reason(reason)
        ));
    }
    out
}

/// What one unmet requirement means, in words that name the remedy.
///
/// Deliberately per-variant. "Could not enforce filesystem writes" is not
/// actionable; "the backend observes filesystem writes but the requirement needs
/// a decision before the effect" tells an operator whether to change the policy,
/// change the backend, or accept the risk.
fn describe_refusal_reason(reason: &aa_isolation::RefusalReason) -> String {
    use aa_isolation::RefusalReason as R;
    match reason {
        R::BackendUnavailable { reason } => format!("the backend cannot be selected on this host — {reason}"),
        R::NoCapabilityReported { .. } => {
            "the backend reported nothing about this domain. Silence is not a claim that the domain \
             needs no control, so the requirement cannot be treated as met"
                .to_string()
        }
        R::DomainUnsupported { reason, .. } => format!("the backend has no mechanism for this domain — {reason}"),
        R::ObserveOnlyForPreventionRequirement { mediation, .. } => format!(
            "policy asked for the action to be denied before it happens, and this backend's mediation for \
             the domain is `{mediation:?}`. An observed action is not a prevented one and must not be \
             promoted to one"
        ),
        R::DecisionTooLate { timing, .. } => format!(
            "the backend enforces this domain, but its decision timing is `{timing:?}` — after the effect. \
             That is detection, not prevention"
        ),
        R::DecisionNotSynchronous { synchrony, .. } => format!(
            "the backend decides before the effect, but its synchrony is `{synchrony:?}`, so the action does \
             not wait for the decision and can win the race"
        ),
        R::NoEvidenceProduced { .. } => {
            "the requirement asked for evidence and this capability produces none".to_string()
        }
        R::DescendantCoverageInsufficient { offered, .. } => format!(
            "the requirement must reach the whole process tree and this capability covers `{offered:?}`. An \
             agent that escapes by spawning a child has no boundary"
        ),
        R::PrerequisiteUnsatisfied { requirement, .. } => {
            format!("a host precondition this capability depends on is not known to hold: {requirement}")
        }
        // `RefusalReason` is `#[non_exhaustive]`. A reason this build has not
        // been taught is printed rather than swallowed: an unexplained refusal
        // is still a refusal, and hiding it would make the launch look like it
        // stopped for no reason.
        other => format!("{other:?}"),
    }
}

/// Run the launch inside a negotiated boundary, and nowhere else.
///
/// # The one thing this function must never do
///
/// There is no arm here that falls back to [`spawn_and_wait`]. `prepare` and
/// `spawn` failures propagate, and the launch produces no process at all — the
/// backend holds the same property structurally on its side (see
/// `aa_isolation_sandlock::backend`'s "single launch path"), and this is the
/// caller-side half of it. A fallback would turn every host problem into a
/// silently unconfined run of an untrusted program.
///
/// The supervisor stays outside the boundary (ADR 0035 §5). It holds an opaque
/// handle, waits on a thread it owns, and forwards a termination request through
/// the backend — it never acquires a descriptor into, or a process id inside,
/// the confined tree.
async fn run_confined(
    backend: std::sync::Arc<dyn aa_isolation::IsolationBackend>,
    plan: aa_isolation::EnforcementPlan,
    report: aa_isolation::IsolationReport,
) -> Result<i32> {
    let prepared = backend
        .prepare(plan)
        .map_err(|e| anyhow::anyhow!("refusing to launch: the execution boundary could not be established — {e}"))?;
    let handle = backend.spawn(prepared).map_err(|e| {
        anyhow::anyhow!(
            "refusing to launch: the confined launch failed — {e}. No process was started outside the boundary"
        )
    })?;

    // `wait_for_exit` blocks by contract — `aa-isolation` takes no async runtime
    // — so it runs on a thread this process owns rather than on the executor,
    // which has signal handlers to service.
    let waiter = {
        let backend = std::sync::Arc::clone(&backend);
        let handle = handle.clone();
        tokio::task::spawn_blocking(move || backend.wait_for_exit(&handle))
    };
    tokio::pin!(waiter);

    #[cfg(unix)]
    let disposition = {
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
        let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
        loop {
            tokio::select! {
                // Forwarded, then the wait continues. The pre-isolation path
                // sent SIGTERM to the child and then waited for it, and an
                // operator's Ctrl-C must still mean the same thing here.
                // A failure to deliver is reported and not fatal: the child may
                // already be exiting, and turning that into an error would make
                // a clean shutdown look like a launcher failure.
                _ = sigterm.recv() => forward_termination(backend.as_ref(), &handle),
                _ = sigint.recv() => forward_termination(backend.as_ref(), &handle),
                joined = &mut waiter => break joined,
            }
        }
    };

    #[cfg(not(unix))]
    let disposition = waiter.await;

    let disposition = disposition
        .map_err(|e| anyhow::anyhow!("the thread waiting on the confined launch failed: {e}"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // The evidenced transition (ADR 0035 §10): what the run actually produced,
    // joined to the plan. `with_evidence` may only *lower* a posture, and this
    // backend records no per-decision channel, so nothing here can turn "the
    // program ran" into "a control decided".
    let evidence = backend.evidence(&handle);
    eprint!("{}", isolation_machine_block(&report.with_evidence(&evidence)));

    // The launcher's exit code has always been the launched program's, with `1`
    // where no code was observable. That contract predates isolation and is not
    // changed by it: the confinement mechanism passes the program's code
    // through, and this passes the mechanism's through.
    Ok(disposition.code_or(1))
}

/// Deliver a termination request, reporting a failure rather than raising it.
#[cfg(unix)]
fn forward_termination(backend: &dyn aa_isolation::IsolationBackend, handle: &aa_isolation::ExecutionHandle) {
    if let Err(e) = backend.terminate(handle, aa_isolation::TerminationRequest::Graceful) {
        eprintln!("warning: could not forward the termination request to the confined launch: {e}");
    }
}

/// Render the `--dry-run` preview for `args`.
///
/// Returns the payload instead of printing it so a test can assert on the whole
/// thing — including that it came from the adapter. When this was inlined in
/// `execute_with_adapters`, reverting it to build its own command would have left
/// every test passing, because nothing could observe what the branch produced.
///
/// Nothing here launches, registers, or writes: under
/// [`plan::PlanPosture::Preview`] the planner reports refusals rather than
/// raising them, since the operator ran this to find out what a live run *would*
/// do — and "it would refuse" is only useful if they are shown it.
///
/// The enforcement mode is no longer a parameter. It is derived from `args` by
/// the planner, which is the only way to guarantee a preview and a live launch
/// cannot be handed different postures for the same flags.
fn dry_run_preview(target: plan::RunTarget, adapter: Option<&dyn DevToolAdapter>, args: &RunArgs) -> String {
    // Every refusal a preview meets is reported by the planner and recorded in
    // the plan, so `Preview` resolution cannot fail.
    let mut resolved = plan::RunPlanner::new(args, target, adapter)
        .resolve(plan::PlanPosture::Preview)
        .expect("a preview reports refusals rather than raising them");

    let handle = resolved.identity().preview_handle();

    // The same bind the live launch performs, against a synthesized identity
    // instead of a registered one. Nothing about the command or the environment
    // below is computed here.
    let bound = resolved.bind(&handle);

    // Managed settings are the one thing a preview does not derive: generating
    // them is harmless, but it needs an enforceable policy the preview may not
    // have, and the honest placeholder says so rather than implying the live run
    // would apply nothing.
    //
    // A generic command gets a different placeholder because it describes a
    // different fact. "Not generated in a preview" would imply a live run
    // generates some; a program with no adapter has no settings schema and no
    // file of its own, and none is written for it at any posture.
    let settings = match resolved.target() {
        plan::RunTarget::Command { .. } => {
            "<none: a generic command has no dev-tool managed settings, and none is written for it>".to_string()
        }
        plan::RunTarget::DevTool { .. } => "<dry-run: managed settings not generated>".to_string(),
    };

    format_dry_run_output(
        &handle,
        resolved.policy().resolution(),
        resolved.network().no_proxy(),
        &settings,
        bound.command(),
        bound.child_env(),
        bound.fidelity(),
        bound.isolation(),
    )
}

/// Testable core of `execute`: detect, register, apply settings, spawn child.
///
/// Returns the child process exit code, or 0 on `--dry-run`.
///
/// `--dry-run` short-circuits *before* `register_with_gateway()` so the planning
/// preview works when no gateway is reachable (e.g. CI runners). It does call
/// `adapter.detect()` and `build_launch_command()` — since AAASM-5329, because a
/// preview that does not ask the adapter cannot show the two variables whose
/// absence means the session is ungoverned. Neither call starts or writes
/// anything. When the tool is not installed the preview still prints, and says
/// so: it degrades visibly rather than silently.
/// `ctx` is deliberately absent. It named the `:8080` HTTP/OpenAPI surface, and
/// registration no longer travels over it — keeping the parameter would suggest
/// `--api-url` still steers where a session registers, which it does not
/// (AAASM-5323). The gateway gRPC endpoint is resolved by
/// [`crate::commands::run_registration::gateway_endpoint`].
pub async fn execute_with_adapters(args: &RunArgs, adapters: &HashMap<&str, Box<dyn DevToolAdapter>>) -> Result<i32> {
    // A registered tool id is resolved **first**. `exec` names the generic target
    // only where no adapter answers to it, so adding the reserved word cannot
    // take an id away from a tool that already had it (AAASM-5706).
    let (target, adapter): (plan::RunTarget, Option<&dyn DevToolAdapter>) = match adapters.get(args.tool.as_str()) {
        Some(adapter) => (plan::RunTarget::dev_tool(&args.tool), Some(adapter.as_ref())),
        None if args.tool == EXEC_TARGET => (plan::RunTarget::command(&args.tool_args)?, None),
        None => return Err(unknown_tool_error(&args.tool)),
    };

    let mode = args.resolved_enforcement_mode();

    // AAASM-1558: surface observe-mode posture before any tool output so an
    // operator immediately sees they're not under live enforcement. Emitted to
    // stderr (stdout is reserved for tool output / dry-run payload). The
    // banner fires whether or not --dry-run is also set — orthogonal flags.
    if mode == aa_core::EnforcementMode::Observe {
        emit_observe_banner();
    }

    for warning in aa_devtool::registry::launch_warnings(&args.tool, &args.tool_args) {
        eprintln!("warning: {warning}");
    }

    if args.dry_run {
        print!("{}", dry_run_preview(target, adapter, args));
        return Ok(0);
    }

    // Every precondition this launch depends on, resolved in one place and in
    // the order the launch commits to them: detect → proxy → `--no-proxy` guard
    // → policy. `Launch` posture makes each one fatal, so reaching the next line
    // means all four passed and nothing has been registered or started yet.
    let mut resolved = plan::RunPlanner::new(args, target, adapter).resolve(plan::PlanPosture::Launch)?;
    let launchable = resolved
        .launchable()
        .expect("a Launch-posture plan resolves every precondition or refuses");

    // Fatal on failure, and fatal *before* anything is launched: a session the
    // gateway did not accept has no governed identity, and a tool started under
    // no identity is an ungoverned process wearing a governed launch's name.
    // Identical for both target kinds — a generic command registers, and later
    // deregisters, through the same handshake, so it is a governed identity for
    // exactly as long as it runs.
    let subject = SessionSubject::of(resolved.target(), launchable.info);
    // Cloned out before `bind` takes the plan mutably. The managed-settings
    // policy is the adapter's projection and is used after the bind; keeping the
    // borrow alive across it would be the only thing standing between this
    // function and the boundary resolution `bind` now performs.
    let managed_policy = launchable.policy.clone();
    let registration = register_with_gateway(&subject, resolved.identity(), mode).await?;
    let handle = RegistrationHandle::of(&registration);

    // Created here, immediately after registration succeeds, rather than just
    // before the spawn: from this point on the function has refusal paths —
    // the dedicated-proxy spawn below is one, the boundary refusal further
    // down is another — and a registered session abandoned without
    // deregistration is a governed identity with no process behind it.
    // `deregistered` is still set on the normal path so the Drop does not
    // duplicate the request.
    let mut guard = RegistrationGuard {
        registration: registration.clone(),
        deregistered: false,
    };

    // AAASM-5863 (Option 2, AAASM-5857): start this launch's dedicated proxy
    // now that a real registered identity exists to configure it with. Fails
    // closed — a proxy that cannot start or does not become ready refuses the
    // launch here, before any managed settings are written or any child
    // exists, rather than falling back to an unproxied or shared-proxy
    // connection a session presenting as governed must never make silently.
    // `None` only for `--no-proxy`, which took the same warned, explicit
    // opt-out path before registration existed (`RunPlanner::resolve` stage
    // 2) and reaches here unchanged.
    let proxy_guard = if args.no_proxy {
        None
    } else {
        let state = launch_state::allocate(launch_state::run_state_label(Some(&handle.agent_id))).map_err(|e| {
            anyhow::anyhow!("refusing to launch ungoverned: could not allocate per-launch proxy state: {e}")
        })?;
        // `AA_CA_DIR` is read here, not delegated to `shared_ca_dir()`'s own
        // resolution, so an operator's override is honoured for the proxy
        // this launch actually starts — `shared_ca_dir()` stays a pure
        // function of nothing but the default, which is what its own tests
        // pin down (AAASM-5862 review).
        let ca_dir = std::env::var_os("AA_CA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(launch_state::shared_ca_dir);
        let opts = ProxyGuardOptions {
            ready_file: state.ready_file,
            ca_dir,
            agent_id: Some(handle.agent_id.clone()),
            gateway_endpoint: Some(run_registration::gateway_endpoint()),
            audit_jsonl_path: Some(state.audit_jsonl_path),
        };
        Some(
            ProxyGuard::spawn(opts)
                .map_err(|e| anyhow::anyhow!("refusing to launch ungoverned: dedicated proxy failed to start: {e}"))?,
        )
    };

    // Recorded now, not at exit: an audit trail that only learns about a session
    // when it ends loses every session still running and every one that does not
    // end cleanly. Reachable only for a policy that permitted the launch — the
    // two refusing states are refused above, before any registration exists, so
    // they cannot reach the trail at all (see `run_audit`'s module docs).
    let (audit_command, audit_args) = audit_argv(resolved.target(), args);
    run_registration::report_launch(
        &registration,
        &handle.trace_id,
        &handle.session_id,
        &audit_command,
        &audit_args,
        &resolved.policy().resolution().posture(),
        args.no_proxy,
    )
    .await;

    if let Some(pg) = &proxy_guard {
        resolved.set_endpoint(format!("http://{}", pg.bound_addr()));
    }

    // The same bind `--dry-run` renders, against the identity the gateway just
    // accepted. No `cmd.envs(&child_env)` anywhere: `spawn_and_wait` applies both
    // sources with the adapter's on top, and overlaying `child_env` onto the
    // command first would overwrite the adapter's values inside `cmd` — the merge
    // would then faithfully carry forward the very values it is meant to
    // override.
    let bound = resolved.bind(&handle);

    // The same projection `--dry-run` renders, on the path that actually starts a
    // child (AAASM-5710). Machine-readable and on stderr: stdout is reserved for
    // the launched tool's own output, and a dashboard or CI check watching a live
    // run should not have to parse a receipt written for a human. Emitted before
    // the child exists, so a run that never returns still leaves the record of
    // what its boundary was — and was not.
    eprint!("{}", isolation_machine_block(bound.isolation()));

    // Before the managed settings are written and long before any child exists:
    // a required control the backend cannot provide stops the launch, and it
    // stops it without having changed anything on the host first (AAASM-5711 AC
    // 4). The report above has already said which control and why.
    if let plan::Boundary::Refused(why) = bound.boundary() {
        anyhow::bail!("refusing to launch: {why}");
    }

    // Managed settings are a dev-tool artifact, so they are generated and applied
    // only where there is a dev tool. A generic command has no adapter, no
    // settings schema and no configuration file of its own; writing one would put
    // an operator-owned program under some other tool's configuration, changing
    // that tool's behaviour on the host in a way nobody asked for and nothing
    // would undo. `generic_run_writes_no_dev_tool_settings` is the control.
    if let Some(adapter) = adapter {
        let settings = adapter
            .generate_managed_settings(&managed_policy)
            .await
            .map_err(|e| anyhow::anyhow!("failed to generate managed settings: {e}"))?;

        adapter
            .apply_settings(&settings)
            .await
            .map_err(|e| anyhow::anyhow!("failed to apply settings: {e}"))?;
    }

    // Raised here rather than at bind time so the failure still lands where it
    // always has: after the managed settings have been applied, not before.
    if let Some(e) = bound.adapter_error() {
        anyhow::bail!("failed to build launch command: {e}");
    }

    let backend = resolved.take_backend();
    let (cmd, child_env, boundary, isolation) = bound.into_execution_parts();
    let code = match boundary {
        // The launch runs inside the negotiated boundary, or not at all. There
        // is no arm below that reaches `spawn_and_wait` after a boundary was
        // established and then failed.
        plan::Boundary::Negotiated(plan) => {
            let backend = backend.expect("a negotiated plan is only produced by a selected backend");
            run_confined(backend.into_arc(), *plan, isolation).await?
        }
        // Unchanged from every `aasm run` before `--isolation` existed.
        plan::Boundary::Absent => spawn_and_wait(cmd, &child_env).await?,
        // Refused above, before the managed settings were written.
        plan::Boundary::Refused(why) => anyhow::bail!("refusing to launch: {why}"),
    };

    // Stop this launch's dedicated proxy before deregistering, not after: its
    // `Drop` is what flushes/finalizes this launch's audit segment, and a
    // governed session should not be reported as ended to the gateway while
    // its own proxy is still writing that session's audit trail. `None` under
    // `--no-proxy`, where there is nothing to stop.
    drop(proxy_guard);

    // Primary deregistration path — async, reliable. Mark the guard first so its
    // Drop does not fire a duplicate request when the function returns normally.
    guard.deregistered = true;
    deregister_with_gateway(&registration).await;

    Ok(code)
}

/// Launch the specified AI dev tool with governance wiring.
///
/// The tool id is normalised to its canonical registry token **once**, here,
/// before anything reads it. `args.tool` is not just a map key: it is also the
/// fallback executable name in a degraded `--dry-run` preview, the subject of
/// the launch warnings and the `--no-proxy` refusal, and the name printed in
/// the session banner. Resolving the alias at the lookup alone would leave all
/// of those talking about an id the rest of the system does not use
/// (AAASM-5503).
pub async fn execute(mut args: RunArgs) -> Result<i32> {
    // Tool ids are resolved first and the generic target only after they all
    // fail, so `exec` cannot shadow a tool id or one of its aliases.
    match canonical_tool_id(&args.tool) {
        Some(canonical) => args.tool = canonical.to_string(),
        None if args.tool == EXEC_TARGET => {}
        None => return Err(unknown_tool_error(&args.tool)),
    }

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    for tool in aa_devtool::registry::SUPPORTED_TOOLS {
        adapters.insert(tool, resolve_adapter(tool)?);
    }
    execute_with_adapters(&args, &adapters).await
}

/// Entry point for `aasm run`.
///
/// `_ctx` is unused: `--api-url` names the HTTP surface, and this command's only
/// gateway conversation is the gRPC registration handshake. The parameter stays
/// so the `commands::dispatch` table keeps one shape.
pub fn dispatch(args: RunArgs, _ctx: &ResolvedContext, _output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    match rt.block_on(execute(args)) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    // Stub adapters below implement DevToolAdapter, so the test module carries
    // the trait-object plumbing the production path no longer needs.
    use aa_core::{AdapterError, DevToolInfo, DevToolKind, McpServerInfo, PolicyDocument};
    use async_trait::async_trait;
    use clap::Parser;

    use super::*;

    /// Minimal CLI wrapper for testing `run` subcommand parsing.
    #[derive(Parser)]
    #[command(name = "aasm")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Run(RunArgs),
    }

    // --- parse tests (carried forward from AAASM-927) ---

    #[test]
    fn parse_basic_run_command() {
        let cli = TestCli::try_parse_from(["aasm", "run", "claude", "foo", "bar"]).unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert_eq!(args.tool, "claude");
                assert_eq!(args.tool_args, vec!["foo", "bar"]);
                assert!(!args.dry_run);
                assert!(!args.no_proxy);
            }
        }
    }

    #[test]
    fn parse_with_flags() {
        let cli = TestCli::try_parse_from([
            "aasm",
            "run",
            "claude",
            "--agent-id",
            "a1",
            "--dry-run",
            "--",
            "--some-flag",
        ])
        .unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert_eq!(args.tool, "claude");
                assert_eq!(args.agent_id.as_deref(), Some("a1"));
                assert!(args.dry_run);
                assert_eq!(args.tool_args, vec!["--some-flag"]);
            }
        }
    }

    #[test]
    fn parse_governance_level_short_forms() {
        for (input, expected) in [
            ("L0", GovernanceLevel::L0Discover),
            ("L1", GovernanceLevel::L1Observe),
            ("L2", GovernanceLevel::L2Enforce),
            ("L3", GovernanceLevel::L3Native),
        ] {
            let cli = TestCli::try_parse_from(["aasm", "run", "codex", "--governance-level", input]).unwrap();
            match cli.command {
                TestCommands::Run(args) => {
                    assert_eq!(args.governance_level, Some(expected), "input={input}");
                }
            }
        }
    }

    // --- enforcement-mode CLI parsing (AAASM-1558) ---

    #[test]
    fn parse_observe_flag_resolves_to_observe_mode() {
        // --observe is the documented shorthand; resolves to Observe regardless
        // of whether --enforcement-mode is present (it isn't here).
        let cli = TestCli::try_parse_from(["aasm", "run", "claude", "--observe"]).unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert!(args.observe);
                assert_eq!(args.enforcement_mode, None);
                assert_eq!(args.resolved_enforcement_mode(), aa_core::EnforcementMode::Observe);
            }
        }
    }

    #[test]
    fn parse_enforcement_mode_flag_accepts_all_three_modes() {
        for (input, expected) in [
            ("enforce", aa_core::EnforcementMode::Enforce),
            ("observe", aa_core::EnforcementMode::Observe),
            ("disabled", aa_core::EnforcementMode::Disabled),
        ] {
            let cli = TestCli::try_parse_from(["aasm", "run", "claude", "--enforcement-mode", input]).unwrap();
            match cli.command {
                TestCommands::Run(args) => {
                    assert!(!args.observe, "input={input}");
                    assert_eq!(args.resolved_enforcement_mode(), expected, "input={input}");
                }
            }
        }
    }

    #[test]
    fn parse_observe_and_enforcement_mode_together_is_rejected() {
        // conflicts_with on --observe — both flags at once must error out so
        // the source of truth stays unambiguous.
        match TestCli::try_parse_from(["aasm", "run", "claude", "--observe", "--enforcement-mode", "enforce"]) {
            Ok(_) => panic!("clap must reject --observe + --enforcement-mode together"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("cannot be used with") || msg.contains("conflict"),
                    "expected conflicts_with error, got: {msg}"
                );
            }
        }
    }

    #[test]
    fn parse_dry_run_combined_with_observe_works() {
        // --dry-run (preview-only) and --observe (governance posture) are
        // orthogonal flags. Both must be allowed in one invocation.
        let cli = TestCli::try_parse_from(["aasm", "run", "claude", "--dry-run", "--observe"]).unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert!(args.dry_run);
                assert!(args.observe);
                assert_eq!(args.resolved_enforcement_mode(), aa_core::EnforcementMode::Observe);
            }
        }
    }

    #[test]
    fn resolved_enforcement_mode_defaults_to_enforce_when_neither_flag_set() {
        // The pre-feature default — and the path every existing `aa run`
        // invocation takes today.
        let cli = TestCli::try_parse_from(["aasm", "run", "claude"]).unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert!(!args.observe);
                assert_eq!(args.enforcement_mode, None);
                assert_eq!(args.resolved_enforcement_mode(), aa_core::EnforcementMode::Enforce);
            }
        }
    }

    // --- adapter resolution tests ---

    #[test]
    fn unknown_tool_errors() {
        let err = match resolve_adapter("notathing") {
            Ok(_) => panic!("expected Err for unknown tool"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("unknown tool"),
            "expected 'unknown tool' in error, got: {err}"
        );
        assert!(
            err.to_string().contains("notathing"),
            "expected tool name in error, got: {err}"
        );
    }

    #[test]
    fn known_tools_resolve_without_error() {
        for tool in aa_devtool::registry::SUPPORTED_TOOLS {
            assert!(resolve_adapter(tool).is_ok(), "resolve_adapter({tool}) should succeed");
        }
    }

    /// Every tool must resolve to a real per-tool adapter. `L0Discover` was the
    /// level the old in-file `PlaceholderAdapter` reported, so it is the exact
    /// signature of the regression this asserts against: a tool that `aasm run`
    /// accepts but cannot actually govern or launch (AAASM-5274; previously
    /// this test covered codex only).
    #[test]
    fn no_tool_resolves_to_a_placeholder_adapter() {
        for tool in aa_devtool::registry::SUPPORTED_TOOLS {
            let adapter = resolve_adapter(tool).expect("registered tool must resolve");
            assert_ne!(
                adapter.governance_level(),
                GovernanceLevel::L0Discover,
                "{tool} resolved to a non-governing placeholder adapter"
            );
        }
    }

    /// AAASM-5274 regression guard: `aasm tools list` (via [`DiscoveryService`])
    /// and `aasm run` (via [`resolve_adapter`]) must resolve the *same* adapter
    /// for every supported tool.
    ///
    /// Before AAASM-5274 they did not: discovery constructed detection-only
    /// stubs from `aa_devtool::adapters` (Claude Code declaring `L3Native`)
    /// while `aasm run claude` got an inert placeholder declaring `L0Discover`
    /// — so `aasm tools list` advertised governance the launcher could not
    /// deliver. This fails if either consumer is ever pointed somewhere other
    /// than `aa_devtool::registry`.
    #[test]
    fn discovery_and_run_resolve_the_same_adapter_metadata() {
        let discovery = aa_devtool::DiscoveryService::new();
        let discovered = discovery.adapters();

        assert_eq!(
            discovered.len(),
            aa_devtool::registry::SUPPORTED_TOOLS.len(),
            "DiscoveryService must load exactly one adapter per supported tool"
        );

        // `built_in_adapters()` yields adapters in SUPPORTED_TOOLS order, so the
        // index identifies the tool.
        for (idx, tool) in aa_devtool::registry::SUPPORTED_TOOLS.iter().enumerate() {
            let run_adapter = resolve_adapter(tool).expect("registered tool must resolve");
            let discovery_adapter = &discovered[idx];

            assert_eq!(
                run_adapter.governance_level(),
                discovery_adapter.governance_level(),
                "{tool}: `aasm run` reports {:?} but discovery reports {:?}",
                run_adapter.governance_level(),
                discovery_adapter.governance_level(),
            );

            // Detection identity. On a host without the tool both sides return
            // None, which still proves they agree; when the tool *is* installed
            // this pins the concrete DevToolKind each side reports.
            let run_kind = run_adapter.detect().map(|i| i.kind);
            let discovery_kind = discovery_adapter.detect().map(|i| i.kind);
            assert_eq!(
                run_kind, discovery_kind,
                "{tool}: `aasm run` detects {run_kind:?} but discovery detects {discovery_kind:?}"
            );
            if let Some(kind) = run_kind {
                assert_eq!(
                    Some(&kind),
                    aa_devtool::registry::kind_for(tool).as_ref(),
                    "{tool}: detected kind disagrees with the registry's declared kind"
                );
            }
        }
    }

    /// Pins each CLI tool token to the [`DevToolKind`] the registry declares for
    /// it, expressed as the wire token `aasm run` sends to the gateway. Unlike
    /// the parity test above this is load-bearing on any host, installed tools
    /// or not — it fails if a registry entry is ever repointed at another tool.
    #[test]
    fn registry_tool_tokens_map_to_expected_dev_tool_kinds() {
        let expected = [
            ("claude", "claude_code"),
            ("codex", "codex"),
            ("copilot", "github_copilot"),
            ("windsurf", "windsurf_cascade"),
        ];
        assert_eq!(
            expected.len(),
            aa_devtool::registry::SUPPORTED_TOOLS.len(),
            "a tool was added to the registry without extending this mapping"
        );
        for (tool, wire) in expected {
            let kind = aa_devtool::registry::kind_for(tool).expect("registered tool must have a kind");
            assert_eq!(dev_tool_kind_str(&kind), wire, "{tool} maps to the wrong DevToolKind");
        }
    }

    // --- tool-id agreement between `aasm integrations` and `aasm run` ---

    /// A policy document is required to build the registrations; its contents
    /// are irrelevant to the ids they are keyed by.
    fn empty_policy() -> aa_core::policy::PolicyDocument {
        aa_core::policy::PolicyDocument {
            version: 1,
            name: "tool-id-agreement".to_string(),
            rules: Vec::new(),
            enforcement_mode: aa_core::EnforcementMode::Enforce,
        }
    }

    /// The ids `aasm integrations list` prints in its `TOOL` column, taken from
    /// the registration list the runtime actually serves `list_tools` from
    /// rather than from a copy of it.
    fn integrations_tool_ids() -> Vec<String> {
        aa_runtime::devint::adapters::built_in_integrations(empty_policy())
            .iter()
            .map(|registration| aa_runtime::devint::projection::tool_id(&registration.tool))
            .collect()
    }

    /// AAASM-5503: the discovery surface and the execution surface name the
    /// same four tools, so an id printed by one must be accepted by the other.
    ///
    /// Both vocabularies are *derived* here — `integrations`' from
    /// [`built_in_integrations`](aa_runtime::devint::adapters::built_in_integrations)
    /// projected through the same `tool_id` the wire uses, `run`'s from
    /// [`SUPPORTED_TOOLS`](aa_devtool::registry::SUPPORTED_TOOLS) through the
    /// same [`resolve_adapter`] a launch calls. Nothing here is a hand-written
    /// pair list, so a tool added to one surface and not the other fails this
    /// test rather than slipping through it.
    ///
    /// Before the fix `run` accepted only the short tokens, so three of the four
    /// ids `integrations list` teaches (`claude-code`, `github-copilot`,
    /// `windsurf-cascade`) were refused by the command a user would copy them
    /// into.
    #[test]
    fn every_id_integrations_prints_is_accepted_by_run() {
        let integration_ids = integrations_tool_ids();
        assert_eq!(
            integration_ids.len(),
            aa_devtool::registry::SUPPORTED_TOOLS.len(),
            "the two surfaces know a different number of tools: integrations {integration_ids:?} \
             vs run {:?}",
            aa_devtool::registry::SUPPORTED_TOOLS,
        );

        for id in &integration_ids {
            assert!(
                resolve_adapter(id).is_ok(),
                "`aasm integrations list` prints {id:?} but `aasm run {id}` refuses it: {}",
                resolve_adapter(id).err().map_or_else(String::new, |e| e.to_string()),
            );
        }
    }

    /// Accepting an id is not enough — it must resolve to the tool it names.
    /// An alias table that merely resolved would be free to point
    /// `github-copilot` at Claude Code and still satisfy the test above.
    #[test]
    fn an_integrations_id_resolves_to_the_tool_it_names() {
        for token in aa_devtool::registry::SUPPORTED_TOOLS {
            let kind = aa_devtool::registry::kind_for(token).expect("registered tool must have a kind");
            let id = aa_runtime::devint::projection::tool_id(&kind);
            assert_eq!(
                canonical_tool_id(&id),
                Some(token),
                "`aasm run {id}` resolves to {:?}, not {token}",
                canonical_tool_id(&id),
            );
        }
    }

    /// The other direction: nothing `aasm run` accepts is a tool the
    /// integrations surface has never heard of.
    #[test]
    fn every_tool_run_accepts_is_known_to_integrations() {
        let integration_ids = integrations_tool_ids();
        for token in aa_devtool::registry::SUPPORTED_TOOLS {
            let kind = aa_devtool::registry::kind_for(token).expect("registered tool must have a kind");
            let id = aa_runtime::devint::projection::tool_id(&kind);
            assert!(
                integration_ids.contains(&id),
                "`aasm run {token}` is accepted but no integration answers for {id:?}; \
                 integrations knows {integration_ids:?}"
            );
        }
    }

    /// AC 2: adding the long ids must not cost the short ones. Driven from the
    /// registry so a renamed token is caught here too.
    #[test]
    fn the_short_tool_tokens_keep_working() {
        for token in aa_devtool::registry::SUPPORTED_TOOLS {
            assert_eq!(
                canonical_tool_id(token),
                Some(token),
                "`aasm run {token}` no longer resolves to itself"
            );
            assert!(resolve_adapter(token).is_ok(), "`aasm run {token}` stopped working");
        }
    }

    /// A genuine typo is still refused, and the refusal still names every value
    /// that would have worked — including the ids the user most likely copied
    /// from `aasm integrations list`.
    #[test]
    fn a_typo_is_still_refused_with_every_accepted_id() {
        assert_eq!(canonical_tool_id("not-a-tool"), None, "a typo must not resolve");
        let err = match resolve_adapter("not-a-tool") {
            Ok(_) => panic!("a typo must not resolve to an adapter"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("not-a-tool"), "{err}");
        for token in aa_devtool::registry::SUPPORTED_TOOLS {
            assert!(err.contains(token), "the refusal omits {token}: {err}");
        }
        for id in integrations_tool_ids() {
            assert!(err.contains(&id), "the refusal omits {id}: {err}");
        }
    }

    // --- build_child_env tests ---

    fn stub_handle(team_id: Option<&str>) -> RegistrationHandle {
        RegistrationHandle {
            agent_id: "test-agent".into(),
            registration_did: run_registration::registration_did("test-agent"),
            registration_id: "test-reg".into(),
            trace_id: "test-trace".into(),
            session_id: "test-session".into(),
            team_id: team_id.map(String::from),
        }
    }

    /// The isolation report a bound launch carries today: no backend selected,
    /// so no boundary established.
    ///
    /// Built with the same constructor `IsolationPlan::report` uses, so a test
    /// asserting on the rendered section is asserting on the shape the command
    /// actually emits.
    fn stub_isolation(credentials: aa_isolation::CredentialPosture) -> aa_isolation::IsolationReport {
        aa_isolation::IsolationReport::no_boundary(
            aa_isolation::SessionRef::new("test-session", "test-trace"),
            aa_isolation::IdentityRef::root("test-agent"),
            aa_isolation::TargetRef::new("mock-tool", 0),
            credentials,
            "no isolation backend is selected",
        )
    }

    /// A resolved-and-enforced policy, for tests whose subject is not the
    /// policy state itself.
    fn stub_resolution() -> run_policy::PolicyResolution {
        run_policy::PolicyResolution::Enforced {
            source: PathBuf::from("/tmp/test-policy.yaml"),
            document: PolicyDocument {
                version: 1,
                name: "test".into(),
                rules: vec![aa_core::PolicyRule {
                    action_pattern: "bash".into(),
                    decision: aa_core::PolicyDecision::Deny,
                }],
                enforcement_mode: aa_core::EnforcementMode::default(),
            },
            // Deliberately the empty canonical document: these tests are about
            // the policy *state*, and a stub that restricted something would
            // give every one of them an execution boundary they never asked for.
            canonical: aa_security::policy::PolicyDocument::default(),
        }
    }

    /// Set `HTTPS_PROXY` / `HTTP_PROXY` on this process for the duration of the
    /// guard, so `build_child_env`'s copy of the ambient environment carries an
    /// operator-supplied proxy the way a real shell would.
    struct AmbientProxy {
        _lock: std::sync::MutexGuard<'static, ()>,
        prior: Vec<(&'static str, Option<String>)>,
    }

    impl AmbientProxy {
        fn set(value: &str) -> Self {
            let lock = crate::test_support::env_guard();
            let mut prior = Vec::new();
            for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
                prior.push((key, std::env::var(key).ok()));
                std::env::set_var(key, value);
            }
            Self { _lock: lock, prior }
        }

        /// Removes both vars for the duration of the guard, so a test that
        /// asserts "no ambient proxy" is not just inheriting whatever happened
        /// to be unset in this process already.
        fn clear() -> Self {
            let lock = crate::test_support::env_guard();
            let mut prior = Vec::new();
            for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
                prior.push((key, std::env::var(key).ok()));
                std::env::remove_var(key);
            }
            Self { _lock: lock, prior }
        }
    }

    impl Drop for AmbientProxy {
        fn drop(&mut self) {
            for (key, prior) in self.prior.drain(..) {
                match prior {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// Constraint: the identity that registered must be the identity the launch
    /// runs under. `AA_AGENT_ID` is the seed the DID is derived from, so anything
    /// downstream that derives from it — an SDK inside the launched tool, a later
    /// `aasm run` for the same agent — must land on the DID the gateway
    /// registered. If these two ever disagree, the launched process is operating
    /// under an identity the gateway never accepted.
    #[test]
    fn the_launched_tool_carries_the_registered_identity_and_can_rederive_it() {
        let handle = stub_handle(Some("team-a"));
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);

        let seed = env.get("AA_AGENT_ID").expect("the launch must carry an agent id");
        let did = env
            .get("AA_AGENT_DID")
            .expect("the launch must carry the registered DID");
        assert_eq!(
            did,
            &run_registration::registration_did(seed),
            "`AA_AGENT_DID` must be what `AA_AGENT_ID` derives to; a child that re-derives the \
             identity would otherwise reach a different agent than the one that registered"
        );
        assert!(did.starts_with("did:key:z"), "got {did}");
    }

    /// The gateway's credential token authenticates *as the registered agent*.
    /// The launched tool is the software that registration exists to govern, so
    /// it must never receive one — and `--dry-run` prints this whole map, so a
    /// leak here reaches stdout and from there a CI log.
    #[test]
    fn no_gateway_credential_reaches_the_launched_tool() {
        // `build_child_env` inherits the process environment, so this assertion
        // is only meaningful when no unrelated test has a stray `AA_*` var set.
        // Hold the shared env lock so we observe the environment between other
        // env-mutating tests (e.g. integrations' `AA_DEVINT_TOKEN_FILE`), not
        // mid-mutation — otherwise this flakes under the shared-process harness.
        let _guard = crate::test_support::env_guard();
        let handle = stub_handle(Some("team-a"));
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);

        for key in env.keys().filter(|k| k.starts_with("AA_")) {
            assert!(
                !key.contains("CREDENTIAL") && !key.contains("TOKEN"),
                "`{key}` hands the governed process a credential for its own governance record"
            );
        }
    }

    #[test]
    fn build_child_env_sets_proxy() {
        let handle = stub_handle(None);
        let env = build_child_env(
            &handle,
            Some("http://proxy:8080"),
            false,
            aa_core::EnforcementMode::Enforce,
        );
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://proxy:8080"),
            "HTTPS_PROXY should be set"
        );
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://proxy:8080"),
            "HTTP_PROXY should be set"
        );
        assert_eq!(env.get("AA_AGENT_ID").map(String::as_str), Some("test-agent"));
        assert_eq!(env.get("AA_TRACE_ID").map(String::as_str), Some("test-trace"));
        assert_eq!(env.get("AA_SESSION_ID").map(String::as_str), Some("test-session"));
        assert_eq!(env.get("AA_REGISTRATION_ID").map(String::as_str), Some("test-reg"));
    }

    /// `--no-proxy` is an opt-out of *our* injection, not a scrub of the
    /// operator's own configuration: a developer behind a corporate proxy who
    /// asks for an unproxied launch still needs their own proxy to reach the
    /// network.
    #[test]
    fn build_child_env_leaves_the_ambient_proxy_alone_under_no_proxy() {
        let _ambient = AmbientProxy::set("http://corporate:3128");
        let handle = stub_handle(None);
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://corporate:3128"),
            "--no-proxy must not rewrite the operator's own proxy configuration"
        );
    }

    /// An environment-supplied proxy address is not authoritative: whatever the
    /// operator's shell (or anything that wrote to it) had must lose to the
    /// endpoint the host-side trust check vouched for.
    #[test]
    fn build_child_env_overwrites_an_ambient_proxy_with_the_trusted_endpoint() {
        let _ambient = AmbientProxy::set("http://attacker.example:8080");
        let handle = stub_handle(None);
        let env = build_child_env(
            &handle,
            Some("http://127.0.0.1:8899"),
            false,
            aa_core::EnforcementMode::Enforce,
        );
        for key in ["HTTPS_PROXY", "HTTP_PROXY"] {
            assert_eq!(
                env.get(key).map(String::as_str),
                Some("http://127.0.0.1:8899"),
                "`{key}` must carry the trusted endpoint, not the ambient one"
            );
        }
    }

    /// The dry-run path: no trusted endpoint and no opt-out. An inherited
    /// `HTTPS_PROXY` must be dropped rather than shown, or the preview reads as
    /// a governed launch that the live run would have refused.
    #[test]
    fn build_child_env_drops_an_ambient_proxy_when_none_was_vouched_for() {
        let _ambient = AmbientProxy::set("http://corporate:3128");
        let handle = stub_handle(None);
        let env = build_child_env(&handle, None, false, aa_core::EnforcementMode::Enforce);
        assert!(
            !env.contains_key("HTTPS_PROXY"),
            "an unvouched-for ambient HTTPS_PROXY must not reach the child"
        );
        assert!(
            !env.contains_key("HTTP_PROXY"),
            "an unvouched-for ambient HTTP_PROXY must not reach the child"
        );
    }

    // --- ambient_proxy_is_set tests (AAASM-5892/5897) ---

    /// Vanilla launch, no ambient proxy: the AAASM-5897 warning must not fire.
    #[test]
    fn ambient_proxy_is_set_is_false_with_no_ambient_proxy() {
        let _ambient = AmbientProxy::clear();
        assert!(
            !ambient_proxy_is_set(),
            "no ambient HTTPS_PROXY/HTTP_PROXY was set; the warning's precondition must not fire"
        );
    }

    /// The AAASM-5892 incident shape: an operator (or CC-Switch, or a corporate
    /// shell profile) already has a proxy configured. This is exactly the case
    /// the new warning exists to surface before `build_child_env` silently
    /// overrides it.
    #[test]
    fn ambient_proxy_is_set_is_true_with_a_real_ambient_proxy() {
        let _ambient = AmbientProxy::set("http://corporate:3128");
        assert!(
            ambient_proxy_is_set(),
            "a real ambient HTTPS_PROXY/HTTP_PROXY was set; the warning's precondition must fire"
        );
    }

    /// An empty-string env var is not a configured proxy. Some shells/CI carry
    /// `HTTPS_PROXY=` unset-but-present; treating that as "ambient" would warn
    /// on every such launch for nothing to report.
    #[test]
    fn ambient_proxy_is_set_is_false_for_an_empty_value() {
        let _ambient = AmbientProxy::set("");
        assert!(
            !ambient_proxy_is_set(),
            "an empty-string HTTPS_PROXY/HTTP_PROXY is not a configured ambient proxy"
        );
    }

    // --- no_proxy_refusal scope-awareness tests (AAASM-5907) ---

    /// Pins `AASM_STATE_DIR` and the process cwd for the duration of the guard,
    /// so `no_proxy_refusal`'s real `ReceiptStore::default_location()` and
    /// `std::env::current_dir()` calls land in an isolated fixture instead of
    /// this developer's real `~/.aasm` and worktree.
    struct ReceiptFixture {
        _lock: std::sync::MutexGuard<'static, ()>,
        _state_dir: tempfile::TempDir,
        prior_state_dir: Option<String>,
        prior_cwd: PathBuf,
    }

    impl ReceiptFixture {
        /// `project_root` becomes the process cwd; a Project-scope receipt is
        /// written only when `install_at` is given, with its
        /// `WriteManagedSettings` step's `path` set to `install_at`'s
        /// `.claude/settings.json` — deliberately *not* always `project_root`,
        /// so a test can construct "a receipt for a different project" to prove
        /// the path-match, not just presence, is what gates the refusal.
        fn new(project_root: &std::path::Path, install_at: Option<&std::path::Path>) -> Self {
            let lock = crate::test_support::env_guard();
            let state_dir = tempfile::tempdir().expect("tempdir");
            let prior_state_dir = std::env::var("AASM_STATE_DIR").ok();
            let prior_cwd = std::env::current_dir().expect("current cwd");
            std::env::set_var("AASM_STATE_DIR", state_dir.path());
            std::env::set_current_dir(project_root).expect("set cwd to fixture project root");

            // macOS's tempdir lives under a `/var/folders/...` path that is
            // itself a symlink to `/private/var/folders/...`. `set_current_dir`
            // above followed by the real `no_proxy_refusal`'s
            // `std::env::current_dir()` returns the *canonical* form, so any
            // path built from the raw tempdir path here would never string-match
            // it — a test-harness artifact, not the production path-match logic
            // this fixture exists to exercise. Canonicalize before building any
            // path so the fixture agrees with what the code under test actually
            // sees.
            if let Some(install_root) = install_at {
                let install_root = install_root.canonicalize().expect("canonicalize install root");
                let settings_path = install_root.join(".claude").join("settings.json");
                let step = aa_core::integration::step::IntegrationStep::new(
                    "settings",
                    aa_core::integration::step::StepAction::WriteManagedSettings {
                        scope: aa_core::integration::step::SettingsScope::Project,
                        path: settings_path,
                        managed_keys: vec!["permissions".to_string()],
                        content_sha256: "test-fixture-sha".to_string(),
                        merge: aa_core::integration::step::SettingsMerge::MergeManagedKeys,
                        format: aa_core::integration::step::DocumentFormat::Json,
                    },
                    "write the managed settings block",
                );
                let receipt = aa_core::integration::IntegrationReceipt {
                    schema_version: aa_core::integration::LIFECYCLE_SCHEMA_VERSION,
                    receipt_id: "test-receipt".to_string(),
                    plan_id: "test-plan".to_string(),
                    tool: aa_core::DevToolKind::ClaudeCode,
                    profile: aa_core::integration::ProtectionProfile::Strict,
                    settings_scope: aa_core::integration::step::SettingsScope::Project,
                    applied_at_unix_secs: 1_000_000,
                    versions: aa_core::integration::version::ComponentVersions {
                        core: aa_core::integration::version::core_version(),
                        adapter: aa_core::integration::version::ToolVersion::new(0, 1, 0),
                        lifecycle_schema: aa_core::integration::LIFECYCLE_SCHEMA_VERSION,
                    },
                    tool_version: None,
                    steps: vec![aa_core::integration::StepReceipt::applied(&step, None)],
                    planned_level: aa_core::integration::state::ProtectionLevel::GatewayProtected,
                    achieved_level: aa_core::integration::state::ProtectionLevel::GatewayProtected,
                    achieved_evidence: Vec::new(),
                    verified_at_unix_secs: Some(1_000_000),
                };
                // `ReceiptStore::default_location()` — what `no_proxy_refusal`
                // actually reads through — resolves to `$AASM_STATE_DIR/integrations`,
                // not `$AASM_STATE_DIR` itself. Constructing the store the same way
                // here (rather than `ReceiptStore::at(state_dir.path())`) is what
                // makes this fixture's save land where the code under test looks.
                aa_core::integration::store::ReceiptStore::default_location()
                    .expect("resolve default receipt store location")
                    .save_receipt(&receipt)
                    .expect("save fixture receipt");
            }

            Self {
                _lock: lock,
                _state_dir: state_dir,
                prior_state_dir,
                prior_cwd,
            }
        }
    }

    impl Drop for ReceiptFixture {
        fn drop(&mut self) {
            match &self.prior_state_dir {
                Some(v) => std::env::set_var("AASM_STATE_DIR", v),
                None => std::env::remove_var("AASM_STATE_DIR"),
            }
            let _ = std::env::set_current_dir(&self.prior_cwd);
        }
    }

    /// The AAASM-5906/5907 correctness requirement: a Project-scope receipt
    /// exists globally per `(tool, scope)`, not per project root, so it must
    /// only be honoured when its recorded settings path matches *this* cwd.
    #[test]
    fn no_proxy_refusal_honours_a_project_scope_receipt_installed_at_this_cwd() {
        let project = tempfile::tempdir().expect("project tempdir");
        let _fixture = ReceiptFixture::new(project.path(), Some(project.path()));

        let refusal = no_proxy_refusal("claude");
        assert!(
            matches!(
                refusal,
                Some(crate::commands::run_no_proxy_guard::RefusalSource::StrictProfile { .. })
            ),
            "a Project-scope Strict receipt installed at this exact cwd must refuse --no-proxy, got {refusal:?}"
        );
    }

    /// The receipt-store's lack of project-root binding (AAASM-5906 correction)
    /// must not let a Project-scope receipt for a *different* project leak into
    /// an unrelated directory's refusal decision.
    #[test]
    fn no_proxy_refusal_ignores_a_project_scope_receipt_installed_elsewhere() {
        let other_project = tempfile::tempdir().expect("other project tempdir");
        let this_project = tempfile::tempdir().expect("this project tempdir");
        let _fixture = ReceiptFixture::new(this_project.path(), Some(other_project.path()));

        let refusal = no_proxy_refusal("claude");
        assert!(
            refusal.is_none(),
            "a Project-scope receipt installed at a different path must not refuse --no-proxy here, got {refusal:?}"
        );
    }

    /// No receipt at all, either scope: the ordinary unconfigured case must stay
    /// silent, exactly as before this ticket.
    #[test]
    fn no_proxy_refusal_is_none_with_no_receipt_at_all() {
        let project = tempfile::tempdir().expect("project tempdir");
        let _fixture = ReceiptFixture::new(project.path(), None);

        assert!(
            no_proxy_refusal("claude").is_none(),
            "no receipt at either scope must mean no refusal"
        );
    }

    #[test]
    fn build_child_env_sets_team_id_when_present() {
        let handle = stub_handle(Some("my-team"));
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);
        assert_eq!(env.get("AA_TEAM_ID").map(String::as_str), Some("my-team"));
    }

    #[test]
    fn build_child_env_omits_team_id_when_absent() {
        let handle = stub_handle(None);
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);
        assert!(
            !env.contains_key("AA_TEAM_ID"),
            "AA_TEAM_ID must not be set when team_id is None"
        );
    }

    #[test]
    fn build_child_env_omits_aa_enforcement_mode_when_enforce() {
        // Pre-feature behaviour: an enforce-mode launch must not introduce
        // any new env var so tools that env-sniff don't pick up a phantom
        // posture marker.
        let handle = stub_handle(None);
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);
        assert!(
            !env.contains_key("AA_ENFORCEMENT_MODE"),
            "AA_ENFORCEMENT_MODE must be absent in plain enforce-mode launches"
        );
    }

    #[test]
    fn build_child_env_sets_aa_enforcement_mode_for_observe_and_disabled() {
        // The downstream tool / SDK reads this env var to decide whether to
        // surface a "running under observe mode" badge / banner in its own
        // UX. Locks in the snake_case wire form.
        let handle = stub_handle(None);
        let observe_env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Observe);
        assert_eq!(
            observe_env.get("AA_ENFORCEMENT_MODE").map(String::as_str),
            Some("observe")
        );

        let disabled_env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Disabled);
        assert_eq!(
            disabled_env.get("AA_ENFORCEMENT_MODE").map(String::as_str),
            Some("disabled")
        );
    }

    // --- register_with_gateway tests ---
    //
    // What the CLI *submits* is asserted in `run_registration`'s own unit tests
    // (identity derivation, the did:key ↔ public_key binding, the possession
    // proof over the server nonce, the enforcement-mode mapping). Whether a real
    // gateway *accepts* it is asserted in `tests/run_registration_gateway.rs`
    // against `AgentLifecycleServiceImpl` itself. Neither claim can be made
    // against a mock HTTP endpoint that answers a route no gateway serves, which
    // is all the two tests that used to sit here could do.

    // --- execute_with_adapters tests ---

    struct StubNotInstalled;

    #[async_trait]
    impl DevToolAdapter for StubNotInstalled {
        fn detect(&self) -> Option<DevToolInfo> {
            None
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            unimplemented!()
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            unimplemented!()
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            unimplemented!()
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L0Discover
        }
    }

    struct StubDetected {
        version: Option<String>,
    }

    #[async_trait]
    impl DevToolAdapter for StubDetected {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: self.version.clone(),
                install_path: PathBuf::from("/usr/local/bin/claude"),
                governance_level: GovernanceLevel::L2Enforce,
                supports_mcp: true,
                supports_managed_settings: true,
            })
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Ok("{}".into())
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Ok(std::process::Command::new("echo"))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L2Enforce
        }
    }

    /// Adapter that records whether `apply_settings` was called.
    struct MockAdapter {
        apply_called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DevToolAdapter for MockAdapter {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: Some("9.9.9".into()),
                install_path: PathBuf::from("/usr/local/bin/mock-tool"),
                governance_level: GovernanceLevel::L2Enforce,
                supports_mcp: false,
                supports_managed_settings: true,
            })
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Ok(r#"{"key":"val"}"#.into())
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            self.apply_called.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Ok(std::process::Command::new("mock-tool"))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L2Enforce
        }
    }

    fn run_args(tool: &str) -> RunArgs {
        RunArgs {
            tool: tool.to_string(),
            tool_args: vec![],
            agent_id: None,
            team_id: None,
            root_agent: None,
            governance_level: None,
            no_proxy: false,
            policy: None,
            workdir: None,
            dry_run: false,
            enforcement_mode: None,
            observe: false,
            // The default, and the point: every existing test describes a
            // launch with no execution-isolation boundary, exactly as before.
            isolation: IsolationIntent::None,
            isolation_backend: None,
        }
    }

    #[tokio::test]
    async fn tool_not_found_errors() {
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert("claude", Box::new(StubNotInstalled));

        let err = execute_with_adapters(&run_args("claude"), &adapters).await.unwrap_err();
        assert!(
            err.to_string().contains("is not installed"),
            "expected 'is not installed' in error, got: {err}"
        );
        assert!(
            err.to_string().contains("claude"),
            "expected tool name in error, got: {err}"
        );
    }

    // `detected_tool_succeeds` moved to `tests/run_registration_gateway.rs`: a
    // detected tool now has to register with a real `AgentLifecycleService`
    // before it can launch, and the mock HTTP endpoint that used to stand in for
    // that answered a route no gateway serves.

    /// The core claim of AAASM-5323: with no trusted proxy on this host, a
    /// launch is refused — and a `proxy_addr` in the gateway's response cannot
    /// rescue it, because the response is not a source of truth for where this
    /// machine's traffic goes.
    ///
    /// Not `#[tokio::test]`: the `AA_DATA_DIR` redirection needs the crate's
    /// environment lock, and holding a `std` guard across an `.await` is a
    /// deadlock hazard clippy rightly rejects. Driving the async body through a
    /// local runtime keeps the whole guarded region await-free.
    #[test]
    fn launch_refuses_when_no_trusted_proxy_can_be_established() {
        let _lock = crate::test_support::env_guard();
        let prior = std::env::var("AA_DATA_DIR").ok();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("AA_DATA_DIR", tmp.path());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build test runtime");
        let outcome = rt.block_on(async {
            let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
            adapters.insert("claude", Box::new(StubDetected { version: None }));
            execute_with_adapters(&run_args("claude"), &adapters).await
        });

        match prior {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }

        let err = outcome.expect_err(
            "with no proxy running, `aasm run` must refuse to launch rather than launch \
             unproxied — a gateway-supplied address is not evidence that a proxy exists",
        );
        assert!(
            err.to_string().contains("refusing to launch ungoverned"),
            "the refusal must say what it refused and why; got: {err}"
        );

        // And the refusal is the *proxy* one, which is how this test shows the
        // launch never reached registration: `AA_GATEWAY_ENDPOINT` is unset here,
        // so a run that got as far as registering would have failed against the
        // default `127.0.0.1:50051` with an unreachable-gateway message instead.
        // A refused launch must leave no abandoned session behind.
        assert!(
            !err.to_string().contains("refusing to launch unregistered"),
            "the launch reached registration before the proxy check; the refusal must come \
             first so no session is created for a launch that will not happen. Got: {err}"
        );
    }

    #[tokio::test]
    async fn unknown_tool_in_adapters_errors() {
        let adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();

        let err = execute_with_adapters(&run_args("notathing"), &adapters)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown tool"), "got: {err}");
    }

    // --- dry-run tests ---

    /// `--dry-run` still works on a host where the tool is not installed and no
    /// gateway is reachable — a CI runner, or a machine being set up.
    ///
    /// Since AAASM-5329 it *does* call `detect()`; what it must never do is
    /// register, generate or apply settings. `StubNotInstalled` panics on all
    /// three, so reaching any of them fails here rather than silently.
    #[tokio::test]
    async fn dry_run_needs_neither_an_installed_tool_nor_a_gateway() {
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert("claude", Box::new(StubNotInstalled));

        let mut args = run_args("claude");
        args.dry_run = true;

        let result = execute_with_adapters(&args, &adapters).await;
        assert!(
            result.is_ok(),
            "--dry-run should succeed without an installed tool or a gateway: {result:?}",
        );
        assert_eq!(result.unwrap(), 0, "--dry-run should exit 0");
    }

    /// Adapter shaped like the real Claude Code one: it contributes the two
    /// variables whose absence makes a session ungoverned, and it *removes* one.
    ///
    /// The removal is the case a naive union of the two environment sources gets
    /// wrong — it would show the variable as present in a preview of a launch
    /// that will not have it.
    struct StubEnvContributing;

    #[async_trait]
    impl DevToolAdapter for StubEnvContributing {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: Some("1.2.3".into()),
                install_path: PathBuf::from("/usr/local/bin/claude"),
                governance_level: GovernanceLevel::L2Enforce,
                supports_mcp: true,
                supports_managed_settings: true,
            })
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Ok("{}".into())
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        fn build_launch_command(
            &self,
            args: &[String],
            _agent: &str,
            _team: Option<&str>,
            proxy: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            let mut cmd = std::process::Command::new("claude-real-binary");
            cmd.args(args);
            cmd.env("NODE_EXTRA_CA_CERTS", "/tmp/aasm-ca.pem");
            if let Some(proxy) = proxy {
                cmd.env("HTTPS_PROXY", format!("http://{proxy}"));
            }
            cmd.env_remove("ANTHROPIC_API_KEY");
            Ok(cmd)
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L2Enforce
        }
    }

    /// AC 4, and the load-bearing one: the preview's environment is the launch's
    /// environment, because both come from `effective_child_env`.
    ///
    /// Asserted as an equality against the merge the spawn path uses rather than
    /// against a hand-written expected set — a hand-written set would keep
    /// passing if both sides drifted together, which is the failure this guards.
    #[test]
    fn the_preview_environment_is_the_launch_environment() {
        let adapter = StubEnvContributing;
        let mut child_env: HashMap<String, String> = HashMap::new();
        child_env.insert("AA_AGENT_ID".into(), "agent-1".into());
        child_env.insert("HTTPS_PROXY".into(), "127.0.0.1:8080".into());
        child_env.insert("ANTHROPIC_API_KEY".into(), "sk-should-be-removed".into());

        let cmd = adapter
            .build_launch_command(&[], "agent-1", None, Some("127.0.0.1:8080"))
            .expect("command");
        let (effective, removed) = effective_child_env(&cmd, &child_env);

        assert_eq!(
            effective.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some("/tmp/aasm-ca.pem"),
            "the adapter's CA path must reach the child"
        );
        assert_eq!(
            effective.get("HTTPS_PROXY").map(String::as_str),
            Some("http://127.0.0.1:8080"),
            "the adapter's normalised URL must win over the bare host:port"
        );
        assert!(
            !effective.contains_key("ANTHROPIC_API_KEY"),
            "a variable the adapter removes must not be present: {effective:?}"
        );
        assert_eq!(removed, vec!["ANTHROPIC_API_KEY".to_string()]);
    }

    /// AC 2: the two variables that decide whether a session is protected are
    /// visible in the printed preview, not merely present in a struct.
    #[test]
    fn the_preview_shows_the_ca_and_the_normalised_proxy_url() {
        let adapter = StubEnvContributing;
        let handle = stub_handle(None);
        let cmd = adapter
            .build_launch_command(&[], &handle.agent_id, None, Some("127.0.0.1:8080"))
            .expect("command");
        let mut env: HashMap<String, String> = HashMap::new();
        env.insert("HTTPS_PROXY".into(), "127.0.0.1:8080".into());
        env.insert("ANTHROPIC_API_KEY".into(), "sk-removed".into());

        let output = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            "{}",
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );

        assert!(
            output.contains("NODE_EXTRA_CA_CERTS=/tmp/aasm-ca.pem"),
            "preview omits the proxy CA: {output}"
        );
        assert!(
            output.contains("HTTPS_PROXY=http://127.0.0.1:8080"),
            "preview omits the normalised proxy URL: {output}"
        );
        assert!(
            output.contains("claude-real-binary"),
            "preview shows its own command, not the adapter's: {output}"
        );
        assert!(
            output.contains("ANTHROPIC_API_KEY=<removed by adapter>"),
            "a removal must be shown as a removal, not hidden or shown as set: {output}"
        );
    }

    /// AC 3: an un-derivable preview degrades **visibly**. Silently printing one
    /// that omits adapter state is the outcome the AC rules out, and it is also
    /// the pre-AAASM-5329 behaviour.
    #[test]
    fn a_preview_that_could_not_ask_the_adapter_says_so() {
        let args = {
            let mut a = run_args("claude");
            a.dry_run = true;
            a
        };
        let handle = stub_handle(None);
        let (cmd, fidelity, _) =
            plan::IntegrationPlan::probe(&StubNotInstalled).launch_command(&args, "claude", &handle, None);

        assert!(
            matches!(fidelity, PreviewFidelity::Degraded(_)),
            "an uninstalled tool must degrade the preview"
        );
        assert_eq!(cmd.get_program().to_string_lossy(), "claude");

        let output = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            "{}",
            &cmd,
            &HashMap::new(),
            &fidelity,
            &stub_isolation(Default::default()),
        );
        assert!(
            output.contains("DEGRADED"),
            "the shortfall must be in the output: {output}"
        );
        assert!(
            output.contains("NODE_EXTRA_CA_CERTS"),
            "it must name what is missing, not just that something is: {output}"
        );
    }

    /// The whole preview — not just the helper — is derived from the adapter.
    ///
    /// This is the test that fails if the dry-run branch is reverted to building
    /// its own `Command`. The unit tests above would all still pass in that
    /// case, because none of them can observe what the branch produced.
    #[test]
    fn the_whole_preview_is_derived_from_the_adapter() {
        let mut args = run_args("claude");
        args.dry_run = true;
        args.no_proxy = true; // keeps the preview off any real proxy resolution

        let output = dry_run_preview(
            plan::RunTarget::dev_tool("claude"),
            Some(&StubEnvContributing as &dyn DevToolAdapter),
            &args,
        );

        assert!(
            output.contains("claude-real-binary"),
            "the preview must show the adapter's command, not `aasm run`'s own: {output}"
        );
        assert!(
            output.contains("NODE_EXTRA_CA_CERTS=/tmp/aasm-ca.pem"),
            "the preview must carry what the adapter contributes: {output}"
        );
        assert!(
            output.contains("--- preview fidelity ---"),
            "every preview states how faithful it is: {output}"
        );
        assert!(
            !output.contains("DEGRADED"),
            "an installed tool yields a faithful preview: {output}"
        );
    }

    /// A faithful preview must not carry the degraded wording — otherwise the
    /// warning becomes noise an operator learns to ignore.
    #[test]
    fn a_faithful_preview_is_not_labelled_degraded() {
        let args = {
            let mut a = run_args("claude");
            a.dry_run = true;
            a
        };
        let handle = stub_handle(None);
        let (_, fidelity, error) = plan::IntegrationPlan::probe(&StubEnvContributing).launch_command(
            &args,
            "claude",
            &handle,
            Some("127.0.0.1:8080"),
        );
        assert!(matches!(fidelity, PreviewFidelity::FromAdapter));
        assert!(error.is_none(), "a faithful command carries no adapter error");
    }

    #[tokio::test]
    async fn dry_run_does_not_apply_settings() {
        // No gateway of any kind: `--dry-run` short-circuits before registration,
        // and a preview that needed one could not run where this test runs.
        let apply_called = Arc::new(AtomicBool::new(false));
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert(
            "claude",
            Box::new(MockAdapter {
                apply_called: Arc::clone(&apply_called),
            }),
        );

        let mut args = run_args("claude");
        args.dry_run = true;

        let result = execute_with_adapters(&args, &adapters).await;
        assert!(result.is_ok(), "dry-run should succeed: {result:?}");
        assert!(
            !apply_called.load(Ordering::SeqCst),
            "apply_settings must NOT be called when --dry-run is set"
        );
    }

    #[test]
    fn dry_run_prints_command_line() {
        let handle = RegistrationHandle {
            agent_id: "agent-xyz".into(),
            registration_did: run_registration::registration_did("agent-xyz"),
            registration_id: "reg-xyz".into(),
            trace_id: "trace-xyz".into(),
            session_id: "session-xyz".into(),
            team_id: None,
        };
        let settings = r#"{"mode":"strict"}"#;
        let mut cmd = std::process::Command::new("mock-tool");
        cmd.args(["--flag", "value"]);
        let mut env = HashMap::new();
        env.insert("AA_AGENT_ID".into(), "agent-xyz".into());
        env.insert("MY_API_KEY".into(), "secret123".into());
        env.insert("NORMAL_VAR".into(), "hello".into());

        let output = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            settings,
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );

        assert!(output.contains("agent_id:"), "missing identity section: {output}");
        assert!(output.contains("agent-xyz"), "missing agent_id value: {output}");
        assert!(output.contains("trace-xyz"), "missing trace_id value: {output}");
        assert!(output.contains("session-xyz"), "missing session_id value: {output}");
        assert!(
            output.contains("--- managed settings ---"),
            "missing settings header: {output}"
        );
        assert!(
            output.contains(r#"{"mode":"strict"}"#),
            "missing settings content: {output}"
        );
        assert!(
            output.contains("--- launch command ---"),
            "missing command header: {output}"
        );
        assert!(
            output.contains("mock-tool"),
            "missing tool name in command line: {output}"
        );
        assert!(
            output.contains("--- environment ---"),
            "missing environment header: {output}"
        );
        assert!(
            output.contains("***MASKED***"),
            "MY_API_KEY value should be masked: {output}"
        );
        assert!(
            output.contains("NORMAL_VAR=hello"),
            "NORMAL_VAR should be unmasked: {output}"
        );
    }

    /// The four effective-policy states must survive as far as the artefact an
    /// operator actually reads.
    ///
    /// This is the assertion that a four-variant enum on its own does not
    /// satisfy: a consumer that renders every state the same way — or that
    /// collapses them into "a policy loaded" / "it did not" — passes the type
    /// checker and fails the contract. So the check is on the rendered receipt,
    /// and it is pairwise: `enforced` and `permissive` both launch, and are the
    /// pair most likely to be flattened into each other.
    #[test]
    fn the_dry_run_receipt_distinguishes_all_four_policy_states() {
        let handle = stub_handle(None);
        let cmd = std::process::Command::new("mock-tool");
        let env = HashMap::new();

        let states = [
            run_policy::PolicyResolution::Enforced {
                source: PathBuf::from("/p.yaml"),
                document: PolicyDocument {
                    version: 1,
                    name: "p".into(),
                    rules: vec![aa_core::PolicyRule {
                        action_pattern: "bash".into(),
                        decision: aa_core::PolicyDecision::Deny,
                    }],
                    enforcement_mode: aa_core::EnforcementMode::default(),
                },
                canonical: aa_security::policy::PolicyDocument::default(),
            },
            run_policy::PolicyResolution::Permissive {
                source: PathBuf::from("/p.yaml"),
                document: PolicyDocument {
                    version: 1,
                    name: "p".into(),
                    rules: vec![aa_core::PolicyRule {
                        action_pattern: "*".into(),
                        decision: aa_core::PolicyDecision::Allow,
                    }],
                    enforcement_mode: aa_core::EnforcementMode::default(),
                },
                canonical: aa_security::policy::PolicyDocument::default(),
            },
            run_policy::PolicyResolution::Unconfigured(run_policy::Unconfigured::NoSource { searched: vec![] }),
            run_policy::PolicyResolution::LoadFailed {
                source: PathBuf::from("/p.yaml"),
                detail: "bad".into(),
            },
        ];

        let sections: Vec<String> = states
            .iter()
            .map(|state| {
                let output = format_dry_run_output(
                    &handle,
                    state,
                    false,
                    "{}",
                    &cmd,
                    &env,
                    &PreviewFidelity::FromAdapter,
                    &stub_isolation(Default::default()),
                );
                let start = output
                    .find("--- policy ---")
                    .expect("receipt must carry a policy section");
                let rest = &output[start..];
                let end = rest.find("--- managed settings ---").unwrap_or(rest.len());
                rest[..end].to_string()
            })
            .collect();

        for (state, section) in states.iter().zip(&sections) {
            assert!(
                section.contains(state.state_token()),
                "the receipt must name the state it is reporting; {} is missing from:\n{section}",
                state.state_token()
            );
        }

        for (i, a) in sections.iter().enumerate() {
            for (j, b) in sections.iter().enumerate().skip(i + 1) {
                assert_ne!(
                    a,
                    b,
                    "states {} and {} render an identical policy receipt, so an operator cannot \
                     tell them apart",
                    states[i].state_token(),
                    states[j].state_token()
                );
            }
        }
    }

    #[test]
    fn dry_run_masks_secret_and_connection_url_env_vars() {
        let handle = RegistrationHandle {
            agent_id: "agent-xyz".into(),
            registration_did: run_registration::registration_did("agent-xyz"),
            registration_id: "reg-xyz".into(),
            trace_id: "trace-xyz".into(),
            session_id: "session-xyz".into(),
            team_id: None,
        };
        let cmd = std::process::Command::new("mock-tool");
        let mut env = HashMap::new();
        env.insert("AA_JWT_SECRET".into(), "super-secret-signing-key".into());
        env.insert("DATABASE_URL".into(), "postgresql://aasm:hunter2@db:5432/aasm".into());

        let output = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            "{}",
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );

        assert!(
            !output.contains("super-secret-signing-key"),
            "AA_JWT_SECRET value must not appear in cleartext: {output}"
        );
        assert!(
            output.contains("AA_JWT_SECRET=***MASKED***"),
            "AA_JWT_SECRET should be fully masked: {output}"
        );
        assert!(
            !output.contains("hunter2"),
            "DATABASE_URL password must not appear in cleartext: {output}"
        );
        assert!(
            output.contains("DATABASE_URL=postgresql://aasm:***@db:5432/aasm"),
            "DATABASE_URL password should be redacted while preserving structure: {output}"
        );
    }

    /// AAASM-4936 (sibling of AAASM-4894): `*_URI` connection strings —
    /// `MONGODB_URI` / `REDIS_URI` / `AMQP_URI` / `DATABASE_URI` — carry
    /// `user:pass@host` userinfo just like `*_URL`, but the previous denylist
    /// only matched `_URL` / `_DSN`, so a `MONGODB_URI` password printed in the
    /// clear in the dry-run preview. It must be redacted like a `_URL`.
    #[test]
    fn dry_run_redacts_uri_connection_strings() {
        let handle = RegistrationHandle {
            agent_id: "agent-xyz".into(),
            registration_did: run_registration::registration_did("agent-xyz"),
            registration_id: "reg-xyz".into(),
            trace_id: "trace-xyz".into(),
            session_id: "session-xyz".into(),
            team_id: None,
        };
        let cmd = std::process::Command::new("mock-tool");
        let mut env = HashMap::new();
        env.insert("MONGODB_URI".into(), "mongodb://user:p4ss@host:27017/db".into());

        let output = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            "{}",
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );

        assert!(
            !output.contains("p4ss"),
            "MONGODB_URI password must not appear in cleartext: {output}"
        );
        assert!(
            output.contains("MONGODB_URI=mongodb://user:***@host:27017/db"),
            "MONGODB_URI password should be redacted while preserving structure: {output}"
        );
    }

    /// The fail-closed backstop: a value carrying `user:pass@` userinfo must be
    /// redacted even when its key name matches none of the connection-string
    /// suffixes or secret substrings, since the value is itself a credential.
    #[test]
    fn mask_value_redacts_connection_string_in_unrecognised_key() {
        let masked = mask_value("PRIMARY_BROKER", "amqp://svc:s3cr3t@rabbit:5672/vhost");
        assert!(
            !masked.contains("s3cr3t"),
            "userinfo password must be redacted: {masked}"
        );
        assert_eq!(masked, "amqp://svc:***@rabbit:5672/vhost");
    }

    /// The backstop must not mangle an ordinary non-credential value: a plain
    /// value with no `scheme://user:pass@` shape passes through untouched.
    #[test]
    fn mask_value_leaves_plain_value_unchanged() {
        assert_eq!(mask_value("LOG_LEVEL", "debug"), "debug");
        assert_eq!(
            mask_value("ENDPOINT", "https://api.example.com/v1"),
            "https://api.example.com/v1"
        );
    }

    /// AAASM-5350 AC 2, receipt surface: a preview of an unprotected launch has
    /// to *say* it is unprotected. Before this the reader had to notice that
    /// `HTTPS_PROXY` was absent from the environment listing and infer the rest
    /// — an inference, made by the person least placed to make it.
    #[test]
    fn the_dry_run_receipt_states_the_protection_it_previews() {
        let handle = stub_handle(None);
        let cmd = std::process::Command::new("claude");
        let env = HashMap::new();

        let unprotected = format_dry_run_output(
            &handle,
            &stub_resolution(),
            true,
            "{}",
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );
        assert!(unprotected.contains("--- protection ---"), "{unprotected}");
        assert!(unprotected.contains("unprotected"), "{unprotected}");
        assert!(
            unprotected.contains("nothing is intercepted"),
            "the consequence, not just the flag: {unprotected}"
        );

        let proxied = format_dry_run_output(
            &handle,
            &stub_resolution(),
            false,
            "{}",
            &cmd,
            &env,
            &PreviewFidelity::FromAdapter,
            &stub_isolation(Default::default()),
        );
        assert!(proxied.contains("proxy_configured"), "{proxied}");
        assert!(
            !proxied.contains("gateway_protected") && !proxied.contains("host_enforced"),
            "a preview must not claim an adjudicated rung: {proxied}"
        );
    }

    /// AAASM-5350 AC 4: an operator-supplied `HTTPS_PROXY` is not AASM
    /// interception, and no surface may report it as though it were.
    ///
    /// The property was documented on `build_child_env` and enforced there, but
    /// never asserted — so nothing would have caught a later change that read
    /// the ambient value back out as evidence of protection. The protection
    /// label derives from what `aasm` resolved, so an ambient proxy cannot
    /// produce `proxy_configured`.
    #[test]
    fn an_ambient_proxy_is_never_reported_as_aasm_interception() {
        let _guard = crate::test_support::env_guard();
        let prior = std::env::var("HTTPS_PROXY").ok();
        std::env::set_var("HTTPS_PROXY", "http://corporate.example:3128");

        // A `--no-proxy` launch with an ambient proxy set is still unprotected:
        // the operator's own route is left alone, and it governs nothing.
        assert_eq!(
            crate::commands::run_audit::protection_label(true),
            "unprotected",
            "an ambient HTTPS_PROXY must not upgrade an unprotected launch"
        );

        // And the child keeps the operator's route rather than having it
        // removed or overwritten — the documented opt-out behaviour.
        let handle = stub_handle(None);
        let env = build_child_env(&handle, None, true, aa_core::EnforcementMode::Enforce);
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://corporate.example:3128"),
            "--no-proxy leaves the operator's own proxy configuration alone"
        );

        match prior {
            Some(v) => std::env::set_var("HTTPS_PROXY", v),
            None => std::env::remove_var("HTTPS_PROXY"),
        }
    }

    // --- execution-isolation receipt (AAASM-5710) ---

    /// The lines of `rendered` between the isolation header and the section
    /// after it.
    fn isolation_section(rendered: &str) -> String {
        rendered
            .split("--- execution isolation ---")
            .nth(1)
            .expect("the dry-run receipt carries an execution-isolation section")
            .split("--- managed settings ---")
            .next()
            .expect("the isolation section is followed by managed settings")
            .to_string()
    }

    /// A preview of `tool` under `--no-proxy`, so the resolution never depends on
    /// what is running on this host.
    fn isolation_preview(args: &RunArgs) -> String {
        let adapter = StubDetected { version: None };
        dry_run_preview(plan::RunTarget::dev_tool(&args.tool), Some(&adapter), args)
    }

    /// AC 1 / AC 9: `--dry-run` prints a deterministic execution-isolation
    /// section derived from the canonical plan, and a machine-readable form
    /// beside it.
    ///
    /// AC 7 is the load-bearing assertion here. `aasm run` selects no backend
    /// and lowers no requirement, and `aa_isolation::negotiate` resolves an
    /// empty spec to `Ready` against any backend at all — so the one thing this
    /// section must never say is that the run is ready.
    #[test]
    fn the_dry_run_receipt_states_the_execution_isolation_it_previews() {
        let _guard = crate::test_support::env_guard();
        let mut args = run_args("claude");
        args.no_proxy = true;
        args.agent_id = Some("preview-agent".into());

        let section = isolation_section(&isolation_preview(&args));

        assert!(
            section.contains("schema:           aasm.isolation.report/1"),
            "the section must name the schema it is written in: {section}"
        );
        assert!(
            section.contains("posture:          NO BOUNDARY ESTABLISHED"),
            "a run with no backend and no requirement is not ready: {section}"
        );
        assert!(
            !section.contains("posture:          READY"),
            "`negotiate` calls an empty spec ready; the receipt must not: {section}"
        );
        assert!(
            section.contains("An empty requirement set is not a clean boundary"),
            "the empty requirement set must be named as such: {section}"
        );
        assert!(section.contains("agent_id:         preview-agent"), "{section}");

        // Availability of a backend is never rendered as enforcement.
        assert!(
            section.contains("not about this run"),
            "the backend line must refuse the availability-is-coverage reading: {section}"
        );

        // The machine-readable block a dashboard or CI check consumes.
        assert!(
            section.contains("--- execution isolation (machine-readable) ---"),
            "{section}"
        );
        assert!(section.contains("\nschema=aasm.isolation.report/1\n"), "{section}");
        assert!(section.contains("\nposture=no_boundary\n"), "{section}");
        assert!(section.contains("\ndomain_count=9\n"), "{section}");
        assert!(section.contains("\nbackend_selected=false\n"), "{section}");
        for domain in aa_isolation::CapabilityDomain::ALL {
            assert!(
                section.contains(&format!("\ndomain.{}.claim=unmeasured\n", domain.as_str())),
                "every domain must answer the claim axis: {section}"
            );
        }
    }

    /// AC 1: the same plan renders the same section, byte for byte.
    ///
    /// Bound twice against one handle, so the only way the two could differ is a
    /// non-deterministic iteration inside the report — which is exactly what the
    /// credential lists would introduce if they were not sorted.
    #[test]
    fn the_isolation_section_renders_byte_identically_for_one_plan() {
        let _guard = crate::test_support::env_guard();
        let adapter = StubDetected { version: None };
        let mut args = run_args("claude");
        args.no_proxy = true;
        args.agent_id = Some("preview-agent".into());

        let mut resolved = preview_plan(&adapter, &args);
        let handle = stub_handle(Some("pioneer"));

        let first = resolved.bind(&handle);
        let second = resolved.bind(&handle);
        assert_eq!(first.isolation().render(), second.isolation().render());
        assert_eq!(first.isolation().machine_lines(), second.isolation().machine_lines());
    }

    /// AC 1 anti-drift: `--dry-run` and the live path emit **one** projection.
    ///
    /// The preview's embedded machine block must be byte-identical to what the
    /// live path writes to stderr for the same bound launch. AAASM-5327 and
    /// AAASM-5329 were both this failure in a different field — one side
    /// reporting a protection the other did not have — so it is asserted rather
    /// than assumed.
    #[test]
    fn both_run_paths_emit_one_isolation_projection() {
        let _guard = crate::test_support::env_guard();
        let adapter = StubDetected { version: None };
        let mut args = run_args("claude");
        args.no_proxy = true;
        args.agent_id = Some("preview-agent".into());

        let mut resolved = preview_plan(&adapter, &args);
        let handle = stub_handle(Some("pioneer"));
        let bound = resolved.bind(&handle);

        // What the live path writes to stderr.
        let live = isolation_machine_block(bound.isolation());

        // What the preview embeds in its stdout receipt, for the same bind.
        let preview = format_dry_run_output(
            &handle,
            &stub_resolution(),
            true,
            "{}",
            bound.command(),
            bound.child_env(),
            bound.fidelity(),
            bound.isolation(),
        );

        assert!(
            preview.contains(&live),
            "the preview must embed exactly the block the live path emits.\nlive:\n{live}\npreview:\n{preview}"
        );
    }

    /// AC 11 regression: existing `--dry-run` secret masking survives, and the
    /// new section never prints a credential **value**.
    ///
    /// The two halves are separate claims and both are asserted. The environment
    /// listing must still mask the value; the isolation section must carry the
    /// variable's *name* — which proves the ambient-authority list is live and
    /// not merely empty — while the value appears nowhere in the whole receipt.
    #[test]
    fn the_isolation_section_reports_credential_names_and_never_values() {
        let _guard = crate::test_support::env_guard();
        const NAME: &str = "AA_5710_PROBE_TOKEN";
        const VALUE: &str = "value-that-must-never-be-printed-5710";

        let prior = std::env::var(NAME).ok();
        std::env::set_var(NAME, VALUE);

        let mut args = run_args("claude");
        args.no_proxy = true;
        args.agent_id = Some("preview-agent".into());
        let output = isolation_preview(&args);

        match prior {
            Some(v) => std::env::set_var(NAME, v),
            None => std::env::remove_var(NAME),
        }

        assert!(
            !output.contains(VALUE),
            "no surface of the dry-run receipt may print a credential value: {output}"
        );
        assert!(
            output.contains(&format!("{NAME}=***MASKED***")),
            "the environment listing must still mask the value (AAASM-4894/4936 regression): {output}"
        );

        let section = isolation_section(&output);
        assert!(
            section.contains(NAME),
            "the ambient-authority list must name the variable, or its emptiness would read as \
             least-authority: {section}"
        );
        assert!(!section.contains(VALUE), "{section}");
        assert!(
            section.contains("least_authority:  NO —"),
            "a run holding a credential it could not remove is not least-authority: {section}"
        );
        assert!(
            section.contains("\nleast_authority=false\n"),
            "the machine form must agree with the render: {section}"
        );
    }

    // --- launch planning (AAASM-5705) ---

    /// A plan resolved the way `--dry-run` resolves one.
    ///
    /// `--no-proxy` keeps the resolution off any real proxy trust check, so this
    /// is the same construction the preview performs without depending on what
    /// is running on the host.
    fn preview_plan<'a>(adapter: &'a dyn DevToolAdapter, args: &'a RunArgs) -> plan::ResolvedRunPlan<'a> {
        plan::RunPlanner::new(args, plan::RunTarget::dev_tool(&args.tool), Some(adapter))
            .resolve(plan::PlanPosture::Preview)
            .expect("preview resolution reports refusals rather than raising them")
    }

    fn planning_args(tool: &str) -> RunArgs {
        let mut args = run_args(tool);
        args.no_proxy = true;
        args
    }

    /// AC 8: every supported tool plans a launch, and the plan's two failure
    /// signals agree.
    ///
    /// Driven from the registry rather than a hand-written list of four, so a
    /// tool added to `SUPPORTED_TOOLS` is covered here without an edit — the same
    /// discipline the tool-id agreement tests above use.
    ///
    /// The invariant is the one that matters now that a single `launch_command`
    /// serves both callers: `PreviewFidelity` is what a preview prints and the
    /// adapter error is what a live launch fails on, so a result that is
    /// `FromAdapter` must carry no error, and one that carries an error must not
    /// present itself as faithful. If those two ever disagree, one of the paths
    /// is reporting a launch the other would not perform.
    ///
    /// Copilot is the load-bearing case: its `build_launch_command` always
    /// errors by design, so on a host where it is detected this exercises the
    /// degraded-with-error arm rather than only the happy one.
    #[test]
    fn every_supported_tool_plans_a_launch_with_agreeing_failure_signals() {
        for tool in aa_devtool::registry::SUPPORTED_TOOLS {
            let adapter = resolve_adapter(tool).expect("registered tool must resolve");
            let args = planning_args(tool);
            let handle = stub_handle(None);

            let integration = plan::IntegrationPlan::probe(adapter.as_ref());
            let detected = integration.detected().is_some();
            let (cmd, fidelity, error) = integration.launch_command(&args, tool, &handle, None);

            match (&fidelity, &error) {
                (PreviewFidelity::FromAdapter, Some(e)) => {
                    panic!("{tool}: a faithful command must carry no adapter error, got {e}")
                }
                (PreviewFidelity::Degraded(_), None) if detected => {
                    // The tool is installed but the adapter declined to build a
                    // command and said nothing about why — a live launch would
                    // then fail with no message to fail on.
                    panic!("{tool}: a degraded command from an installed tool must name the error")
                }
                _ => {}
            }

            if !detected {
                assert!(
                    matches!(fidelity, PreviewFidelity::Degraded(_)),
                    "{tool}: an uninstalled tool must degrade rather than claim fidelity"
                );
                assert_eq!(
                    cmd.get_program().to_string_lossy(),
                    *tool,
                    "{tool}: the fallback command must name the tool the operator asked for"
                );
                assert!(
                    error.is_none(),
                    "{tool}: 'not installed' is a detection fact, not an adapter error"
                );
            }
        }
    }

    /// The bound launch composes both layers: what the *plan* contributes (this
    /// session's governance identity) and what the *adapter* contributes (the CA
    /// path and the normalised proxy URL).
    ///
    /// Before AAASM-5705 the preview built these separately from the live launch,
    /// and each drifted in turn — AAASM-5327 lost the adapter's half on the live
    /// path, AAASM-5329 lost it in the preview. Asserting both halves are present
    /// in one bound result is what makes losing either a test failure rather than
    /// a silently ungoverned session.
    #[test]
    fn the_bound_launch_carries_both_the_session_identity_and_the_adapter_environment() {
        let adapter = StubEnvContributing;
        let args = planning_args("claude");
        let mut resolved = preview_plan(&adapter, &args);
        let handle = stub_handle(Some("team-a"));

        let bound = resolved.bind(&handle);
        let (effective, removed) = effective_child_env(bound.command(), bound.child_env());

        assert_eq!(
            effective.get("AA_AGENT_DID").map(String::as_str),
            Some(run_registration::registration_did("test-agent").as_str()),
            "the plan's governance identity must reach the child"
        );
        assert_eq!(
            effective.get("AA_TEAM_ID").map(String::as_str),
            Some("team-a"),
            "the plan's team must reach the child"
        );
        assert_eq!(
            effective.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some("/tmp/aasm-ca.pem"),
            "the adapter's CA path must reach the child"
        );
        assert_eq!(
            removed,
            vec!["ANTHROPIC_API_KEY".to_string()],
            "the adapter's removal must survive the bind"
        );
    }

    /// The spec describes the command that will actually run, not a
    /// reconstruction of it.
    #[test]
    fn the_execution_spec_describes_the_command_that_will_run() {
        let adapter = StubEnvContributing;
        let mut args = planning_args("claude");
        args.tool_args = vec!["--resume".into(), "session-7".into()];
        let mut resolved = preview_plan(&adapter, &args);
        let handle = stub_handle(None);

        let bound = resolved.bind(&handle);
        let spec = bound.spec().expect("a UTF-8 argv must yield a spec");

        assert_eq!(spec.program(), "claude-real-binary");
        assert_eq!(spec.args(), ["--resume", "session-7"]);
        assert_eq!(
            spec.program(),
            bound.command().get_program().to_string_lossy(),
            "the spec must name the same program the launch will spawn"
        );
    }

    /// AC 9: this refactor adds no protection claim.
    ///
    /// The spec carries no requirement, because nothing lowers policy into an
    /// isolation requirement yet and no backend is selected. A requirement
    /// appearing here without a backend asked to meet it is exactly the
    /// "planned but never enforced" shape ADR 0035 exists to prevent, so this
    /// fails the moment one is added ahead of the ticket that negotiates it.
    #[test]
    fn the_execution_spec_states_no_isolation_requirement_yet() {
        let adapter = StubEnvContributing;
        let args = planning_args("claude");
        let mut resolved = preview_plan(&adapter, &args);
        let bound = resolved.bind(&stub_handle(None));
        let spec = bound.spec().expect("spec");

        assert!(
            spec.requirements().is_empty(),
            "no backend is active, so a requirement here would be one nothing was asked to meet: {:?}",
            spec.requirements()
        );
        assert_eq!(spec.required().count(), 0);
    }

    /// The identity a spec is built against is the one the launch presented,
    /// with `--root-agent` recorded as lineage rather than flattened away.
    ///
    /// ADR 0035 §6 needs the ancestry in order to check later that sub-agent
    /// identity narrows; a single parent string cannot express depth.
    #[test]
    fn the_execution_spec_identity_carries_the_team_and_the_lineage() {
        let adapter = StubEnvContributing;
        let mut args = planning_args("claude");
        args.team_id = Some("team-a".into());
        args.root_agent = Some("root-agent-1".into());
        let mut resolved = preview_plan(&adapter, &args);

        let bound = resolved.bind(&stub_handle(Some("team-a")));
        let identity = bound.spec().expect("spec").identity();

        assert_eq!(identity.agent_id, "test-agent", "the identity the launch presented");
        assert_eq!(identity.team_id.as_deref(), Some("team-a"));
        assert_eq!(identity.lineage, vec!["root-agent-1".to_string()]);
        assert_eq!(identity.depth(), 1);
    }

    /// The credential posture has to distinguish authority we *removed* from
    /// authority we merely *inherited* — ADR 0035 §9, and the difference between
    /// a least-authority run and one that only looks like one.
    ///
    /// Both halves are asserted against a variable this test plants, so the
    /// assertion does not depend on what the developer's shell happens to carry:
    /// `ANTHROPIC_API_KEY` is credential-shaped *and* removed by the adapter, so
    /// it must be recorded as removed and must not appear as ambient; the planted
    /// token is credential-shaped and not removed, so it must appear as ambient.
    #[test]
    fn the_credential_posture_separates_removed_authority_from_inherited_authority() {
        let _guard = crate::test_support::env_guard();
        let prior_key = std::env::var("ANTHROPIC_API_KEY").ok();
        let prior_token = std::env::var("AASM_TEST_PLANTED_TOKEN").ok();
        std::env::set_var("ANTHROPIC_API_KEY", "sk-inherited");
        std::env::set_var("AASM_TEST_PLANTED_TOKEN", "planted");

        let adapter = StubEnvContributing;
        let args = planning_args("claude");
        let mut resolved = preview_plan(&adapter, &args);
        let bound = resolved.bind(&stub_handle(None));
        let credentials = bound.spec().expect("spec").credentials().clone();

        match prior_key {
            Some(v) => std::env::set_var("ANTHROPIC_API_KEY", v),
            None => std::env::remove_var("ANTHROPIC_API_KEY"),
        }
        match prior_token {
            Some(v) => std::env::set_var("AASM_TEST_PLANTED_TOKEN", v),
            None => std::env::remove_var("AASM_TEST_PLANTED_TOKEN"),
        }

        assert!(
            credentials.removed.contains(&"ANTHROPIC_API_KEY".to_string()),
            "a variable the adapter unsets must be recorded as removed: {credentials:?}"
        );
        assert!(
            !credentials.ambient_unremoved.contains(&"ANTHROPIC_API_KEY".to_string()),
            "a removed variable must not also be reported as reaching the child: {credentials:?}"
        );
        assert!(
            credentials
                .ambient_unremoved
                .contains(&"AASM_TEST_PLANTED_TOKEN".to_string()),
            "an inherited credential-shaped variable reaches the child and must be recorded: \
             {credentials:?}"
        );
        assert!(
            credentials.has_unremoved_ambient_authority(),
            "the child inherits the operator's environment, so this run is not least-authority \
             and must not report itself as one"
        );
        assert!(
            credentials.delegated.is_empty(),
            "`aasm run` hands the launched tool no credential of its own: {credentials:?}"
        );
    }

    /// The name heuristic is a lower bound, and its two callers depend on that
    /// bias in opposite directions — over-masking a preview, over-recording
    /// ambient authority. Pins the shapes it must catch, and that an ordinary
    /// name is not swept in.
    #[test]
    fn the_credential_name_heuristic_catches_secrets_and_connection_strings() {
        for name in [
            "ANTHROPIC_API_KEY",
            "AA_JWT_SECRET",
            "DB_PASSWORD",
            "GITHUB_TOKEN",
            "AWS_SESSION_TOKEN",
            "DATABASE_URL",
            "MONGODB_URI",
            "PG_DSN",
            "some_lowercase_token",
        ] {
            assert!(
                looks_like_credential_name(name),
                "{name} must be treated as credential-shaped"
            );
        }
        for name in ["LOG_LEVEL", "HOME", "PATH", "AA_TRACE_ID"] {
            assert!(!looks_like_credential_name(name), "{name} must not be swept in");
        }
    }

    // --- the generic command target (AAASM-5706) ---

    /// AC 2 at the CLI boundary: the argv a shell would mangle survives parsing.
    ///
    /// Every element here is one a quoting round-trip loses: an embedded space,
    /// a leading hyphen, a second `--`, an empty string, and a glob character a
    /// re-parse would expand. `--agent-id` and `--workdir` sit before the `--`
    /// and must be read as run-options, not as arguments to the program.
    #[test]
    fn parse_exec_target_keeps_run_options_and_forwards_argv_verbatim() {
        let cli = TestCli::try_parse_from([
            "aasm",
            "run",
            "exec",
            "--agent-id",
            "a1",
            "--workdir",
            "/tmp",
            "--",
            "python3",
            "agent.py",
            "--flag",
            "two words",
            "--",
            "",
            "*.py",
        ])
        .unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert_eq!(args.tool, EXEC_TARGET);
                assert_eq!(args.agent_id.as_deref(), Some("a1"));
                assert_eq!(args.workdir.as_deref(), Some(std::path::Path::new("/tmp")));
                assert_eq!(
                    args.tool_args,
                    vec!["python3", "agent.py", "--flag", "two words", "--", "", "*.py"],
                    "argv must survive parsing element for element"
                );
            }
        }
    }

    /// The reserved word must not collide with an id a tool already answers to,
    /// under **either** spelling — the short registry token or the longer
    /// Developer-Integration id `aasm integrations list` prints.
    ///
    /// Driven from the registry rather than a hand-written list, so a tool added
    /// later is covered without an edit here.
    #[test]
    fn exec_target_is_not_an_id_any_supported_tool_answers_to() {
        assert!(
            canonical_tool_id(EXEC_TARGET).is_none(),
            "`{EXEC_TARGET}` resolves to a supported tool, so the generic target would shadow it"
        );
        for tool in aa_devtool::registry::SUPPORTED_TOOLS {
            assert_ne!(tool, EXEC_TARGET, "a tool is registered under the reserved word");
        }
    }

    /// `aasm run exec` with nothing after `--` names no program. The two ways to
    /// paper over that — defaulting to `sh` or to `$SHELL` — would reintroduce
    /// the shell reconstruction this target exists to avoid, so it refuses.
    #[test]
    fn a_generic_target_refuses_an_empty_argv() {
        let err = plan::RunTarget::command(&[]).expect_err("no program is not a launchable target");
        assert!(
            err.to_string().contains("needs a program to launch"),
            "the refusal must say what is missing; got: {err}"
        );
    }

    /// The first element is the program; the rest are its argv, in order, with
    /// nothing added, removed, joined or re-split.
    #[test]
    fn a_generic_target_splits_argv_into_a_program_and_its_arguments() {
        let argv: Vec<String> = ["python3", "agent.py", "--flag", "two words", "--"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        match plan::RunTarget::command(&argv).expect("a program is present") {
            plan::RunTarget::Command { program, args } => {
                assert_eq!(program, std::ffi::OsString::from("python3"));
                assert_eq!(
                    args,
                    vec![
                        std::ffi::OsString::from("agent.py"),
                        std::ffi::OsString::from("--flag"),
                        std::ffi::OsString::from("two words"),
                        std::ffi::OsString::from("--"),
                    ]
                );
            }
            other => panic!("expected a command target, got {other:?}"),
        }
    }

    /// A generic plan binds the operator's own command **and** this session's
    /// governance identity.
    ///
    /// Both halves matter. The command half is the AC 2 claim at the point the
    /// child is actually constructed; the identity half is the AC 4/5 claim that
    /// a generic launch is governed like any other, and asserting only the first
    /// would let a target that carries no identity pass.
    #[test]
    fn a_generic_plan_binds_the_operators_command_with_the_session_identity() {
        let mut args = planning_args(EXEC_TARGET);
        args.tool_args = ["python3", "agent.py", "--flag", "two words"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let target = plan::RunTarget::command(&args.tool_args).expect("a program is present");
        let mut resolved = plan::RunPlanner::new(&args, target, None)
            .resolve(plan::PlanPosture::Preview)
            .expect("a preview reports refusals rather than raising them");
        let handle = stub_handle(Some("team-a"));
        let bound = resolved.bind(&handle);

        assert_eq!(bound.command().get_program(), std::ffi::OsStr::new("python3"));
        assert_eq!(
            bound.command().get_args().collect::<Vec<_>>(),
            vec![
                std::ffi::OsStr::new("agent.py"),
                std::ffi::OsStr::new("--flag"),
                std::ffi::OsStr::new("two words"),
            ],
            "the bound command must carry the operator's argv unchanged"
        );
        assert_eq!(
            bound.child_env().get("AA_AGENT_ID").map(String::as_str),
            Some("test-agent"),
            "a generic child must be handed the same governance identity a dev-tool child is"
        );
        assert_eq!(
            bound.child_env().get("AA_TEAM_ID").map(String::as_str),
            Some("team-a"),
            "team lineage must reach a generic child too"
        );
        assert!(
            bound.adapter_error().is_none(),
            "there is no adapter behind a generic command, so there is no adapter error"
        );
    }

    /// `--workdir` is applied where both postures bind, so the directory the
    /// preview prints is the directory the launch starts in.
    #[test]
    fn a_generic_preview_shows_the_working_directory_and_no_managed_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut args = planning_args(EXEC_TARGET);
        args.tool_args = ["python3", "agent.py"].iter().map(|s| (*s).to_string()).collect();
        args.workdir = Some(dir.path().to_path_buf());
        args.dry_run = true;

        let target = plan::RunTarget::command(&args.tool_args).expect("a program is present");
        let output = dry_run_preview(target, None, &args);

        assert!(
            output.contains(&format!("working_dir: {}", dir.path().display())),
            "the working directory a live launch would use must be visible in the preview: {output}"
        );
        assert!(
            output.contains("python3 agent.py"),
            "the preview must show the command that would run: {output}"
        );
        assert!(
            output.contains("forwarded verbatim"),
            "a generic command has no adapter, so the preview must not claim adapter fidelity: {output}"
        );
        assert!(
            output.contains("no dev-tool managed settings"),
            "the preview must say no settings file is written for a generic command: {output}"
        );
    }

    /// A dev-tool preview still reports an inherited working directory when the
    /// operator names none — the new line must not turn absence into a claim.
    #[test]
    fn a_preview_without_workdir_reports_an_inherited_working_directory() {
        let mut args = planning_args(EXEC_TARGET);
        args.tool_args = vec!["python3".to_string()];

        let target = plan::RunTarget::command(&args.tool_args).expect("a program is present");
        let output = dry_run_preview(target, None, &args);

        assert!(
            output.contains("working_dir: <inherited from this shell>"),
            "with no --workdir the preview must say the child inherits this shell's directory: {output}"
        );
    }
}
