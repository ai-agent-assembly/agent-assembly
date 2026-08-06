//! `aasm run` — launch an AI dev tool with governance wiring.

use std::collections::{BTreeMap, HashMap};
use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use uuid::Uuid;

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

use aa_core::{DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel};

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
    /// The AI development tool to launch (claude, codex, copilot, windsurf).
    ///
    /// The longer ids `aasm integrations list` prints — claude-code,
    /// github-copilot, windsurf-cascade — name the same tools and are accepted
    /// here too (AAASM-5503).
    pub tool: String,

    /// Arguments forwarded verbatim to the launched tool.
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
    /// This is an explicit opt-out of Layer 2 interception: the tool's traffic
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
async fn register_with_gateway(info: &DevToolInfo, args: &RunArgs) -> Result<GovernedRegistration> {
    let agent_id = args.agent_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let governance_level = info.governance_level.to_string();

    run_registration::register(run_registration::SessionDescriptor {
        agent_id: &agent_id,
        name: &dev_tool_kind_str(&info.kind),
        version: info.version.as_deref().unwrap_or("unknown"),
        team_id: args.team_id.as_deref(),
        parent_agent_id: args.root_agent.as_deref(),
        enforcement_mode: args.resolved_enforcement_mode(),
        governance_level: &governance_level,
    })
    .await
    .map_err(|e| anyhow::anyhow!("refusing to launch unregistered: {e}"))
}

/// Sandbox banner printed to stderr when `--observe` is in effect. The text is
/// stable so audit / log scrapers can match on it; future copy changes should
/// extend rather than replace the existing lines.
fn emit_observe_banner() {
    eprintln!("⚠️  [AAASM] Running in sandbox/observe mode.");
    eprintln!("    Policy decisions are recorded but NOT enforced.");
    eprintln!("    Review captured events: aasm audit list --dry-run-only");
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
fn no_proxy_refusal(tool: &str) -> Option<crate::commands::run_no_proxy_guard::RefusalSource> {
    let kind = aa_devtool::registry::kind_for(tool)?;
    let scope = aa_core::integration::step::SettingsScope::User;

    let receipt_profile = aa_core::integration::ReceiptStore::default_location()
        .ok()
        .and_then(|store| store.load_receipt(&kind, scope).ok().flatten())
        .map(|receipt| receipt.profile);

    let managed = aa_devtool_claude_code::managed_settings::managed_installation_evidence().ok();

    crate::commands::run_no_proxy_guard::refusal_for(&kind, scope, receipt_profile, managed)
}

fn resolve_launch_proxy(no_proxy: bool) -> Result<Option<String>> {
    if no_proxy {
        eprintln!(
            "warning: --no-proxy — launching WITHOUT interception. This session's traffic is not \
             inspected and no egress policy applies to it."
        );
        return Ok(None);
    }
    let url = crate::commands::proxy::trust::resolve_trusted_endpoint()
        .map_err(|e| anyhow::anyhow!("refusing to launch ungoverned: {e}"))?;
    // `Url` appends a path; a proxy variable wants the bare origin.
    Ok(Some(format!(
        "{}://{}:{}",
        url.scheme(),
        url.host_str().unwrap_or_default(),
        url.port().unwrap_or_default()
    )))
}

/// Synthesize a `RegistrationHandle` for `--dry-run` without contacting the
/// gateway. Used by the dry-run short-circuit so the planning preview works
/// in CI runners where no AI dev tool is installed and no gateway is reachable.
///
/// The locally-minted correlation ids are prefixed `dry-run-` to make it obvious
/// in stdout that no real registration occurred. The caller-supplied
/// `--agent-id` / `--team-id` overrides are honored verbatim so the printed plan
/// reflects what the live run *would* have submitted.
///
/// `registration_did` and `registration_id`, by contrast, are **not** faked: both
/// are pure derivations of the identity the live run would present, so the
/// preview can show the DID that would be registered and the registry key it
/// would occupy. Substituting a `dry-run-` placeholder there would hide the one
/// thing about the identity worth previewing.
fn dry_run_handle(args: &RunArgs) -> RegistrationHandle {
    let agent_id = args
        .agent_id
        .clone()
        .unwrap_or_else(|| format!("dry-run-{}", Uuid::new_v4()));
    let registration_did = run_registration::registration_did(&agent_id);
    RegistrationHandle {
        registration_id: run_registration::registry_id(args.team_id.as_deref(), &registration_did),
        agent_id,
        registration_did,
        trace_id: format!("dry-run-{}", Uuid::new_v4()),
        session_id: format!("dry-run-{}", Uuid::new_v4()),
        team_id: args.team_id.clone(),
    }
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
    if upper.ends_with("_URL") || upper.ends_with("_DSN") || upper.ends_with("_URI") {
        return redact_database_url(value);
    }
    const SECRET_SUBSTRINGS: [&str; 7] = ["TOKEN", "KEY", "SECRET", "PASSWORD", "PASS", "CREDENTIAL", "AUTH"];
    if SECRET_SUBSTRINGS.iter().any(|needle| upper.contains(needle)) {
        return "***MASKED***".into();
    }
    redact_database_url(value)
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
    /// The adapter could not supply one; the preview is missing whatever it sets.
    Degraded(String),
}

/// Ask the adapter for the command this launch would run, for preview purposes.
///
/// **`--dry-run` deliberately still works when the tool is not installed**
/// (AAASM-5329 AC 3). Requiring installation would be the tidier contract, but it
/// would break previewing a launch from CI or from a machine being set up — the
/// case the flag is most useful for — and `--dry-run` has been safe to run
/// anywhere since it was introduced. What is *not* acceptable is the old
/// behaviour of silently printing a preview missing the adapter's contribution,
/// so an un-derivable command is reported in the output as degraded.
///
/// Nothing here starts, writes or applies anything: `detect()` inspects the host
/// and `build_launch_command` constructs a `Command` without running it.
fn dry_run_launch_command(
    adapter: &dyn DevToolAdapter,
    args: &RunArgs,
    handle: &RegistrationHandle,
    proxy: Option<&str>,
) -> (std::process::Command, PreviewFidelity) {
    let fallback = || {
        let mut cmd = std::process::Command::new(&args.tool);
        cmd.args(&args.tool_args);
        cmd
    };

    if adapter.detect().is_none() {
        return (
            fallback(),
            PreviewFidelity::Degraded(format!(
                "{} is not installed on this host, so the adapter could not be asked what it \
                 would run. The command and environment below omit everything the adapter \
                 contributes — including NODE_EXTRA_CA_CERTS and the normalised proxy URL, \
                 whose absence is what makes a session ungoverned. Install the tool and \
                 re-run to preview the real launch.",
                args.tool
            )),
        );
    }

    match adapter.build_launch_command(&args.tool_args, &handle.agent_id, handle.team_id.as_deref(), proxy) {
        Ok(cmd) => (cmd, PreviewFidelity::FromAdapter),
        Err(e) => (
            fallback(),
            PreviewFidelity::Degraded(format!(
                "the {} adapter could not build a launch command ({e}), so the command and \
                 environment below omit everything it contributes. A live `aasm run` with \
                 these flags would fail here.",
                args.tool
            )),
        ),
    }
}

/// Build the structured dry-run output string.
///
/// The `--- policy ---` section is the preview's receipt of which of the four
/// effective-policy states this launch resolved to. It is printed for all four,
/// including the two that would refuse: a preview that showed a policy section
/// only when one loaded would make "no policy at all" look like a formatting
/// quirk rather than the reason the live run stops.
fn format_dry_run_output(
    handle: &RegistrationHandle,
    policy: &run_policy::PolicyResolution,
    no_proxy: bool,
    settings: &str,
    cmd: &std::process::Command,
    env: &HashMap<String, String>,
    fidelity: &PreviewFidelity,
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
        PreviewFidelity::Degraded(why) => format!("DEGRADED — {why}"),
    };

    format!(
        "--- aasm run dry-run ---\nagent_id:    {}\nagent_did:   {}\ntrace_id:    {}\nsession_id:  {}\n\n--- preview fidelity ---\n{}\n\n--- protection ---\nstate:  {}\ndetail: {}\n\n--- policy ---\nstate:  {}\nsource: {}\ndetail: {}\n\n--- managed settings ---\n{}\n\n--- launch command ---\n{}\n\n--- environment ---\n{}",
        handle.agent_id,
        handle.registration_did,
        handle.trace_id,
        handle.session_id,
        fidelity_line,
        crate::commands::run_audit::protection_label(no_proxy),
        if no_proxy {
            "--no-proxy: nothing is intercepted, no egress policy applies, and nothing is inspected"
        } else {
            "a trusted proxy endpoint was resolved and injected; whether interception works is \
             adjudicated later, not asserted here"
        },
        policy.state_token(),
        policy.source().map_or("<none>".to_string(), |p| p.display().to_string()),
        policy.summary(),
        truncated_settings,
        cmd_line,
        env_lines,
    )
}

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
fn unknown_tool_error(tool: &str) -> anyhow::Error {
    anyhow::anyhow!("unknown tool: {tool}, supported: {}", accepted_tool_ids())
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
async fn spawn_and_wait(cmd: std::process::Command, child_env: &HashMap<String, String>) -> Result<i32> {
    let (effective, removed) = effective_child_env(&cmd, child_env);

    let mut tokio_cmd = tokio::process::Command::new(cmd.get_program());
    tokio_cmd.args(cmd.get_args());
    tokio_cmd.envs(&effective);
    for name in &removed {
        tokio_cmd.env_remove(name);
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

/// Render the `--dry-run` preview for `args`.
///
/// Returns the payload instead of printing it so a test can assert on the whole
/// thing — including that it came from the adapter. When this was inlined in
/// `execute_with_adapters`, reverting it to build its own command would have left
/// every test passing, because nothing could observe what the branch produced.
///
/// Nothing here launches, registers, or writes: `resolve_launch_proxy` and
/// `resolve_policy` report rather than refuse, since the operator ran this to
/// find out what a live run *would* do — and "it would refuse" is only useful if
/// they are shown it.
fn dry_run_preview(adapter: &dyn DevToolAdapter, args: &RunArgs, mode: aa_core::EnforcementMode) -> String {
    let handle = dry_run_handle(args);

    // A preview launches nothing, so an unresolvable endpoint is reported rather
    // than fatal — but it *is* reported, because a preview that silently omits
    // the proxy reads exactly like a governed one.
    let proxy = match resolve_launch_proxy(args.no_proxy) {
        Ok(proxy) => proxy,
        Err(e) => {
            eprintln!("warning: {e}");
            eprintln!("warning: a live `aasm run` with these flags would refuse to launch.");
            None
        }
    };

    let resolution = resolve_policy(args);
    if let Err(e) = resolution.clone().into_enforceable() {
        eprintln!("warning: {e}");
        eprintln!("warning: a live `aasm run` with these flags would refuse to launch.");
    }

    let mut child_env = build_child_env(&handle, proxy.as_deref(), args.no_proxy, mode);
    resolution.annotate_env(&mut child_env);
    let settings = "<dry-run: managed settings not generated>".to_string();

    // The whole point of a preview is to answer "will this launch be protected",
    // and the two variables that decide it — `NODE_EXTRA_CA_CERTS` and the
    // normalised proxy URL — come from the adapter, not from here. Building our
    // own command, as this did before AAASM-5329, previewed a launch that was not
    // the launch (AAASM-5327 fixed the same omission on the live path).
    let (cmd, fidelity) = dry_run_launch_command(adapter, args, &handle, proxy.as_deref());

    format_dry_run_output(
        &handle,
        &resolution,
        args.no_proxy,
        &settings,
        &cmd,
        &child_env,
        &fidelity,
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
    let adapter = adapters
        .get(args.tool.as_str())
        .ok_or_else(|| unknown_tool_error(&args.tool))?;

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
        print!("{}", dry_run_preview(adapter.as_ref(), args, mode));
        return Ok(0);
    }

    let info = adapter
        .detect()
        .ok_or_else(|| anyhow::anyhow!("{} is not installed", args.tool))?;

    eprintln!(
        "tool={} version={} path={} governance_level={}",
        args.tool,
        info.version.as_deref().unwrap_or("unknown"),
        info.install_path.display(),
        info.governance_level,
    );

    // Resolved before registration on purpose: a launch that is going to be
    // refused should not first create a gateway registration it then abandons.
    let proxy = resolve_launch_proxy(args.no_proxy)?;

    // AAASM-5350 AC 1: `--no-proxy` is refused where a party other than the
    // invoking user has already decided this host runs managed. Checked here,
    // before the policy resolves and before anything is registered or started,
    // for the same reason the policy refusal is: refusing after a launch has
    // begun is not refusing.
    if args.no_proxy {
        if let Some(refusal) = no_proxy_refusal(&args.tool) {
            anyhow::bail!("{refusal}");
        }
    }

    // Same reason, and the same ordering rule: a session with no effective
    // policy is refused here, before any registration exists, because a
    // registered session that never launched is a governed identity with no
    // process behind it — and because there is nothing to govern a tool with.
    // An absent policy is not permission (AAASM-5349).
    let resolution = resolve_policy(args);
    let policy = resolution.clone().into_enforceable()?;

    // Fatal on failure, and fatal *before* anything is launched: a session the
    // gateway did not accept has no governed identity, and a tool started under
    // no identity is an ungoverned process wearing a governed launch's name.
    let registration = register_with_gateway(&info, args).await?;
    let handle = RegistrationHandle::of(&registration);

    // Recorded now, not at exit: an audit trail that only learns about a session
    // when it ends loses every session still running and every one that does not
    // end cleanly. Reachable only for a policy that permitted the launch — the
    // two refusing states are refused above, before any registration exists, so
    // they cannot reach the trail at all (see `run_audit`'s module docs).
    run_registration::report_launch(
        &registration,
        &handle.trace_id,
        &handle.session_id,
        &args.tool,
        &args.tool_args,
        &resolution.posture(),
        args.no_proxy,
    )
    .await;
    let mut child_env = build_child_env(&handle, proxy.as_deref(), args.no_proxy, mode);
    resolution.annotate_env(&mut child_env);

    let settings = adapter
        .generate_managed_settings(&policy)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate managed settings: {e}"))?;

    adapter
        .apply_settings(&settings)
        .await
        .map_err(|e| anyhow::anyhow!("failed to apply settings: {e}"))?;

    let cmd = adapter
        .build_launch_command(
            &args.tool_args,
            &handle.agent_id,
            handle.team_id.as_deref(),
            proxy.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("failed to build launch command: {e}"))?;
    // No `cmd.envs(&child_env)` here: `spawn_and_wait` applies both sources with
    // the adapter's on top, and overlaying `child_env` onto the command first
    // would overwrite the adapter's values inside `cmd` — the merge would then
    // faithfully carry forward the very values it is meant to override.

    let mut guard = RegistrationGuard {
        registration: registration.clone(),
        deregistered: false,
    };

    let code = spawn_and_wait(cmd, &child_env).await?;

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
    args.tool = canonical_tool_id(&args.tool)
        .ok_or_else(|| unknown_tool_error(&args.tool))?
        .to_string();

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
            dry_run: false,
            enforcement_mode: None,
            observe: false,
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
        let (cmd, fidelity) = dry_run_launch_command(&StubNotInstalled, &args, &handle, None);

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

        let output = dry_run_preview(&StubEnvContributing, &args, aa_core::EnforcementMode::Enforce);

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
        let (_, fidelity) = dry_run_launch_command(&StubEnvContributing, &args, &handle, Some("127.0.0.1:8080"));
        assert!(matches!(fidelity, PreviewFidelity::FromAdapter));
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
                let output =
                    format_dry_run_output(&handle, state, false, "{}", &cmd, &env, &PreviewFidelity::FromAdapter);
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
}
