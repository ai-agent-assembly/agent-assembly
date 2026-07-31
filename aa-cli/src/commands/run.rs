//! `aasm run` — launch an AI dev tool with governance wiring.

use std::collections::HashMap;
use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use uuid::Uuid;

#[cfg(unix)]
use tokio::signal::unix::SignalKind;

use aa_core::{DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, PolicyDocument, PolicyRule};

use crate::commands::run_registration::{self, GovernedRegistration};
use crate::commands::status::models::redact_database_url;
use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for the `aasm run <tool> [args...]` subcommand.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The AI development tool to launch (claude, codex, copilot, windsurf).
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

/// Construct a default policy document used until a real loader is wired in.
fn load_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "default".into(),
        rules: Vec::<PolicyRule>::new(),
        enforcement_mode: aa_core::EnforcementMode::default(),
    }
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

/// Build the structured dry-run output string.
fn format_dry_run_output(
    handle: &RegistrationHandle,
    settings: &str,
    cmd: &std::process::Command,
    env: &HashMap<String, String>,
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

    let mut sorted_env: Vec<(&String, &String)> = env.iter().collect();
    sorted_env.sort_by_key(|(k, _)| k.as_str());
    let env_lines: String = sorted_env
        .iter()
        .map(|(k, v)| format!("{}={}\n", k, mask_value(k, v)))
        .collect();

    format!(
        "--- aasm run dry-run ---\nagent_id:    {}\nagent_did:   {}\ntrace_id:    {}\nsession_id:  {}\n\n--- managed settings ---\n{}\n\n--- launch command ---\n{}\n\n--- environment ---\n{}",
        handle.agent_id,
        handle.registration_did,
        handle.trace_id,
        handle.session_id,
        truncated_settings,
        cmd_line,
        env_lines,
    )
}

/// Return the adapter for `tool`, or an error for unrecognised tool names.
///
/// Resolution goes through [`aa_devtool::registry`] — the same table
/// `aasm tools list` discovers with — so a tool cannot be launched with a
/// different adapter than the one discovery advertised (AAASM-5274). There is
/// no placeholder fallback: an unregistered tool is an error, never a silently
/// inert adapter.
fn resolve_adapter(tool: &str) -> Result<Box<dyn DevToolAdapter>> {
    aa_devtool::registry::adapter_for(tool).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown tool: {tool}, supported: {}",
            aa_devtool::registry::SUPPORTED_TOOLS.join(", ")
        )
    })
}

/// Release the registration over the gRPC service that issued it.
///
/// Errors are silently discarded — the session is already over, and a gateway
/// that has gone away leaves the caller nothing to do about it.
async fn deregister_with_gateway(registration: &GovernedRegistration) {
    run_registration::deregister(registration, "aasm run session ended").await;
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
    let mut tokio_cmd = tokio::process::Command::new(cmd.get_program());
    tokio_cmd.args(cmd.get_args());
    tokio_cmd.envs(child_env);
    // `get_envs` yields `None` for a variable the adapter wants *removed* from
    // the child, which is not the same request as setting it empty — an adapter
    // that unsets a variable to disable a tool behaviour must not have that
    // turned into an empty-but-present variable the tool then honours.
    for (name, value) in cmd.get_envs() {
        match value {
            Some(value) => tokio_cmd.env(name, value),
            None => tokio_cmd.env_remove(name),
        };
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

/// Testable core of `execute`: detect, register, apply settings, spawn child.
///
/// Returns the child process exit code, or 0 on `--dry-run`.
///
/// `--dry-run` short-circuits *before* `adapter.detect()` and
/// `register_with_gateway()` so the planning preview works even when no AI
/// dev tool is installed and no gateway is reachable (e.g. CI runners). The
/// printed plan reflects what the live run *would* do with the same flags.
/// `ctx` is deliberately absent. It named the `:8080` HTTP/OpenAPI surface, and
/// registration no longer travels over it — keeping the parameter would suggest
/// `--api-url` still steers where a session registers, which it does not
/// (AAASM-5323). The gateway gRPC endpoint is resolved by
/// [`crate::commands::run_registration::gateway_endpoint`].
pub async fn execute_with_adapters(args: &RunArgs, adapters: &HashMap<&str, Box<dyn DevToolAdapter>>) -> Result<i32> {
    let adapter = adapters.get(args.tool.as_str()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown tool: {}, supported: {}",
            args.tool,
            aa_devtool::registry::SUPPORTED_TOOLS.join(", ")
        )
    })?;

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
        let handle = dry_run_handle(args);
        // A preview launches nothing, so an unresolvable endpoint is reported
        // rather than fatal — but it is reported, because a preview that
        // silently omits the proxy reads exactly like a governed one.
        let proxy = match resolve_launch_proxy(args.no_proxy) {
            Ok(proxy) => proxy,
            Err(e) => {
                eprintln!("warning: {e}");
                eprintln!("warning: a live `aasm run` with these flags would refuse to launch.");
                None
            }
        };
        let child_env = build_child_env(&handle, proxy.as_deref(), args.no_proxy, mode);
        let settings = "<dry-run: managed settings not generated>".to_string();
        let mut cmd = std::process::Command::new(&args.tool);
        cmd.args(&args.tool_args);
        cmd.envs(&child_env);
        print!("{}", format_dry_run_output(&handle, &settings, &cmd, &child_env));
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

    // Fatal on failure, and fatal *before* anything is launched: a session the
    // gateway did not accept has no governed identity, and a tool started under
    // no identity is an ungoverned process wearing a governed launch's name.
    let registration = register_with_gateway(&info, args).await?;
    let handle = RegistrationHandle::of(&registration);
    let child_env = build_child_env(&handle, proxy.as_deref(), args.no_proxy, mode);

    let policy = load_policy();
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
pub async fn execute(args: RunArgs) -> Result<i32> {
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
    use aa_core::{AdapterError, DevToolInfo, DevToolKind, McpServerInfo};
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

    #[tokio::test]
    async fn dry_run_short_circuits_before_adapter_detect_and_gateway() {
        // Adapter whose detect() returns None and whose other methods panic
        // — proves --dry-run skips detect / generate_managed_settings /
        // apply_settings / build_launch_command. The dummy ctx points at a
        // port nothing's listening on; if --dry-run touched the gateway the
        // POST would fail and the test would too.
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert("claude", Box::new(StubNotInstalled));

        let mut args = run_args("claude");
        args.dry_run = true;

        let result = execute_with_adapters(&args, &adapters).await;
        assert!(
            result.is_ok(),
            "--dry-run should succeed without detect() or gateway: {result:?}",
        );
        assert_eq!(result.unwrap(), 0, "--dry-run should exit 0");
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

        let output = format_dry_run_output(&handle, settings, &cmd, &env);

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

        let output = format_dry_run_output(&handle, "{}", &cmd, &env);

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

        let output = format_dry_run_output(&handle, "{}", &cmd, &env);

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
}
