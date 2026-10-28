//! `ProxyGuard` — the per-launch dedicated `aa-proxy` (AAASM-5857).
//!
//! One governed launch = one registered agent identity = one dedicated proxy
//! lifecycle = one attributable policy/audit context. This is the mechanism
//! half of that principle: spawning the proxy, waiting for it to become
//! ready, and tearing it down. What identity/paths it is spawned *with* is
//! the caller's job ([`ProxyGuardOptions`]); this module does not derive them.
//!
//! Deliberately unlike standalone `aasm proxy start`
//! (`aa-cli/src/commands/proxy/start.rs`), which is designed to *outlive*
//! the command that started it (`process_group(0)`, no parent-liveness
//! watch, PID/state file written for a later `aasm proxy stop` to find): a
//! `ProxyGuard` is scoped to the Rust value's own lifetime. It writes no
//! PID/state file (AAASM-5861 design constraint C3: the standalone registry
//! is a *singleton* and concurrent per-launch proxies would clobber it or
//! each other), and its spawned child is configured with
//! `AA_PROXY_PARENT_PID` so the proxy itself shuts down if this process is
//! `SIGKILL`'d before `Drop` can run.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

use super::build_identity::{probe, ProxyBuildEvidence};
#[cfg(unix)]
use super::ctl_path::FALLBACK_BASE;
use super::readiness::{wait_for_ready_file, ReadyFileOutcome};
#[cfg(not(unix))]
const FALLBACK_BASE: &str = "/tmp";

/// How long to wait for the dedicated proxy to report readiness before
/// treating the launch as failed. Generous relative to a normal bind (which
/// is near-instant): the same process may also be doing first-run CA
/// creation and, when `system_trust_install` is `Auto`, a macOS Keychain
/// trust prompt that requires operator interaction (`aa-proxy/src/lib.rs::run`)
/// — a short timeout here would turn "waiting on the operator" into a
/// spurious refusal. Not reachable on a managed launch whose adapter reports
/// process-scoped CA trust (AAASM-5978): that path sets `Never`, so no
/// Keychain prompt exists to wait on.
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait after `SIGTERM` before escalating to `SIGKILL` on drop.
/// Matches the standalone `aasm proxy stop` ladder
/// (`aa-cli/src/commands/proxy/stop.rs`) — the same proxy binary, so the same
/// grace period is the right default for "let it finish flushing audit
/// evidence" either way it is torn down.
const GRACEFUL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything a caller supplies to spawn a dedicated proxy. Identity and
/// storage-layout decisions are deliberately the caller's, not this
/// module's — see the crate doc for why.
pub struct ProxyGuardOptions {
    /// Where to write `AA_PROXY_READY_FILE`. The caller owns this path's
    /// lifecycle (typically a per-launch temp directory, AAASM-5862); this
    /// module only writes to and reads from it, and removes it on drop.
    pub ready_file: PathBuf,
    /// Shared CA material directory. **Must be the same value across every
    /// launch on this machine** — a per-launch `ca_dir` mints a fresh CA on
    /// every `aasm run`, which on macOS re-prompts for Keychain trust every
    /// time and breaks the CA trust an installed developer integration
    /// already established (`ProxyConfig::agent_id`-adjacent constraint;
    /// see the design validation behind AAASM-5857 for the full reasoning).
    pub ca_dir: PathBuf,
    /// The registered launch identity (`aa-cli/src/commands/run_registration.rs`),
    /// or `None` in contexts with no registered agent. Exported as
    /// `AA_AGENT_ID` into the spawned proxy's own process env — the fix
    /// AAASM-5855 could not complete for the standalone-shared-proxy shape,
    /// because a dedicated per-launch proxy has exactly one identity to
    /// carry for its entire lifetime.
    pub agent_id: Option<String>,
    /// `aa-gateway` PolicyService endpoint, if this launch is gateway-managed.
    pub gateway_endpoint: Option<String>,
    /// Where to persist this launch's audit JSONL, if at all.
    pub audit_jsonl_path: Option<PathBuf>,
    /// Whether the spawned proxy should attempt the macOS System Keychain CA
    /// install (AAASM-5978). `Never` when the launched adapter reports it
    /// already provides process-scoped CA trust for this launch
    /// ([`aa_core::DevToolAdapter::process_scoped_ca_trust_var`]); `Auto`
    /// (the default, unchanged historical behaviour) otherwise.
    pub system_trust_install: aa_proxy::config::SystemTrustInstall,
}

/// Why [`ProxyGuard::spawn`] failed. Every variant is a *managed launch must
/// refuse* case (AAASM-5857 requirement 2: fail closed, never fall back to
/// launching the tool ungoverned).
#[derive(Debug)]
pub enum ProxyGuardError {
    /// The `aa-proxy` binary could not be located (see
    /// `aa-cli/src/commands/proxy/start.rs::resolve_binary`).
    BinaryNotFound,
    /// The OS refused to spawn the process at all.
    SpawnFailed(std::io::Error),
    /// The proxy neither became ready nor exited within [`READINESS_TIMEOUT`].
    /// The child has already been reaped (SIGTERM→poll→SIGKILL) by the time
    /// this is returned — never a caller obligation.
    ReadinessTimeout,
    /// The proxy process exited before reporting readiness. Its exit status
    /// is the closest thing to a root cause a caller has (stderr, if wanted,
    /// belongs to a later increment's log-capture work — out of scope here).
    ChildExitedBeforeReady(ExitStatus),
    /// This launch brokers a provider credential, which must be revocable while
    /// the launch runs, and no working revoke path could be established. The
    /// launch is refused rather than started with a credential nobody can revoke
    /// (AAASM-6262, AC3).
    RevocationUnavailable(String),
}

impl std::fmt::Display for ProxyGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound => write!(
                f,
                "aa-proxy binary not found; install with `cargo install aa-proxy` or ensure it is beside \
                 the `aasm` executable, on PATH, or in ~/.cargo/bin"
            ),
            Self::SpawnFailed(e) => write!(f, "failed to spawn aa-proxy: {e}"),
            Self::ReadinessTimeout => {
                write!(f, "aa-proxy did not report readiness within {READINESS_TIMEOUT:?}")
            }
            Self::ChildExitedBeforeReady(status) => {
                write!(f, "aa-proxy exited before reporting readiness (status: {status})")
            }
            Self::RevocationUnavailable(why) => write!(
                f,
                "refusing to launch: this launch brokers a provider credential, which must be revocable while it \
                 runs, but its revocation control socket is unavailable ({why}). Shorten AASM_STATE_DIR or the \
                 agent id, or fix the fallback directory, and retry."
            ),
        }
    }
}

impl std::error::Error for ProxyGuardError {}

/// Build the (unspawned) command for a dedicated proxy from `opts`.
///
/// Separated from [`ProxyGuard::spawn`] so the env-var wiring is unit-testable
/// on its own — asserting over `Command::get_envs()` needs no real binary, no
/// PATH, and no timeout, unlike `spawn()` itself, which review found had *no*
/// coverage proving any of this wiring actually happens (a deleted line here
/// would pass every existing test silently).
///
/// Test-only: the real spawn decides the control-socket path itself
/// ([`ProxyGuard::spawn_with_binary_in`]) and calls
/// [`build_command_with_control`]; this derives the in-launch-directory path the
/// tests expect for a short launch directory.
#[cfg(test)]
fn build_command(binary: &std::path::Path, opts: &ProxyGuardOptions) -> std::process::Command {
    #[cfg(unix)]
    let control = opts.ready_file.parent().and_then(super::ctl_path::primary_socket);
    #[cfg(not(unix))]
    let control: Option<PathBuf> = None;
    build_command_with_control(binary, opts, control.as_deref())
}

/// [`build_command`] with the control-socket path decided by the caller.
///
/// `None` removes `AA_PROXY_CONTROL_SOCKET` explicitly: an ambient value must
/// never decide whether this launch has a control socket.
fn build_command_with_control(
    binary: &std::path::Path,
    opts: &ProxyGuardOptions,
    control_socket: Option<&std::path::Path>,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    cmd.env("AA_PROXY_ADDR", "127.0.0.1:0");
    cmd.env("AA_PROXY_READY_FILE", &opts.ready_file);
    cmd.env("AA_CA_DIR", &opts.ca_dir);
    cmd.env("AA_PROXY_PARENT_PID", std::process::id().to_string());
    // AAASM-5978: always set, both values — deliberately not following this
    // function's usual "omit when None, let the child's own default apply"
    // shape. Unset isn't a distinct meaning here (there is a default), and
    // AAASM-5924 found that "omit and let ambient env decide" turns a real
    // product decision into one an attacker's pre-launch env can override
    // (`AA_PROXY_TRUSTED_CONFIG_PATH`). Setting it explicitly here makes this
    // launch's decision unforgeable by ambient environment.
    cmd.env(
        "AA_PROXY_SYSTEM_TRUST_INSTALL",
        match opts.system_trust_install {
            aa_proxy::config::SystemTrustInstall::Auto => "auto",
            aa_proxy::config::SystemTrustInstall::Never => "never",
        },
    );
    if let Some(agent_id) = &opts.agent_id {
        cmd.env("AA_AGENT_ID", agent_id);
    }
    if let Some(endpoint) = &opts.gateway_endpoint {
        cmd.env("AA_PROXY_GATEWAY_ENDPOINT", endpoint);
        // Same reasoning as standalone start's proxy_child_env: a
        // gateway-managed launch needs non-LLM MCP hosts intercepted and
        // routed to the gateway's PolicyService, not transparently
        // tunnelled past enforcement.
        cmd.env("AA_PROXY_LLM_ONLY", "false");
    }
    if let Some(audit_path) = &opts.audit_jsonl_path {
        cmd.env("AA_PROXY_AUDIT_JSONL_PATH", audit_path);
    }
    // AAASM-6262: a revoke-only control socket inside this launch's own private
    // directory, so `aasm proxy revoke-credential --agent <id>` can revoke a
    // brokered credential in this running proxy. Set (or removed) explicitly
    // rather than inherited, for the reason given for the settings above: an
    // ambient `AA_PROXY_CONTROL_SOCKET` must not decide this launch's surface.
    //
    // The revocation record is deliberately NOT wired: a per-launch proxy lives
    // for exactly one launch and is never restarted, so there is no restart for a
    // durable record to survive, and a record shared across launches would carry
    // a revocation into every later launch with nothing to undo it. A revoke here
    // is therefore reported as memory-only (`aasm` exit status 3), which is
    // accurate. The socket path must also fit in `sun_path`: the caller picks it
    // (`ctl_path::plan`), using a short private fallback when the launch directory
    // is too long, and refuses a launch that brokers a credential when no path works.
    #[cfg(unix)]
    {
        match control_socket {
            Some(socket) => {
                cmd.env("AA_PROXY_CONTROL_SOCKET", socket);
            }
            None => {
                cmd.env_remove("AA_PROXY_CONTROL_SOCKET");
            }
        }
        cmd.env_remove("AA_PROXY_REVOCATIONS_FILE");
    }
    // AAASM-5923/F2 (independent review): `aa-proxy`'s own doc comment on
    // `ProxyConfig::from_env` says explicitly that `AA_PROXY_TRUSTED_CONFIG_PATH`
    // is what `aasm run`/`ProxyGuard` is expected to pass at spawn time — but
    // nothing did, making `aasm integrations install ... --trusted-upstream-proxy`
    // write an artifact no spawned proxy was ever told to read. Wired here
    // unconditionally on existence, not behind a new opt-in flag: the
    // artifact's presence on disk already **is** the operator's declared
    // intent (the install command is the only thing that ever writes it),
    // matching this function's existing "if the caller/environment already
    // decided this, pass it through" shape rather than adding a second place
    // to decide the same thing.
    if let Some(path) = crate::commands::trusted_upstream_path::trusted_upstream_config_path() {
        if path.exists() {
            cmd.env("AA_PROXY_TRUSTED_CONFIG_PATH", &path);
        }
    }
    // No log file wired up in this increment (unlike standalone start's
    // --log-file): this proxy's stdout/stderr have no operator watching a
    // terminal for them the way `aasm proxy start` does. Discarding rather
    // than inheriting keeps a governed tool's own stdout/stderr clean of
    // interleaved proxy log lines. Structured log capture for a per-launch
    // proxy, if wanted, is separate scope from spawning it.
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());
    // AAASM-6395: provider keys travel on stdin, never in this proxy's (or the
    // governed tool's) environment. Must follow the `stdin(null)` above.
    super::provider_keys::configure(&mut cmd);

    // ADR 0036 D6: this boundary has no `--no-proxy` concept (it spawns the
    // dedicated `aa-proxy` itself, not a governed tool) and never has a
    // trusted value to inject, so step 3 of the D6 invariant is always a
    // no-op here — unconditional removal of all 8 case variants is the whole
    // rule for this spawn.
    for name in crate::commands::run_env_sanitize::PROXY_EXCLUSION_AND_ROUTING_VARS {
        cmd.env_remove(name);
    }
    cmd
}

/// A per-launch dedicated `aa-proxy`, alive for as long as this value is.
///
/// No `Clone`, no `Copy`: exactly one `ProxyGuard` owns exactly one spawned
/// process, which is the whole point (AAASM-5857's "one governed launch = one
/// dedicated proxy lifecycle" principle would not hold if two guards could
/// reference the same child).
pub struct ProxyGuard {
    child: Child,
    ready_file: PathBuf,
    bound_addr: SocketAddr,
    build_evidence: ProxyBuildEvidence,
    /// A control socket kept outside the launch directory (the short-path
    /// fallback); the launch directory is not removed with the guard, so this is.
    fallback_socket: Option<PathBuf>,
}

impl ProxyGuard {
    /// Spawn a dedicated proxy and block until it is ready to serve traffic
    /// or has definitively failed to start.
    ///
    /// Synchronous and blocking (`std::thread::sleep` inside
    /// [`wait_for_ready_file`]) rather than `async`, matching every other
    /// process-lifecycle function in this module (`aa-cli/src/commands/proxy/
    /// start.rs`, `stop.rs`) and `aasm run`'s own launched-tool spawn
    /// (`std::process::Command`, `aa-cli/src/commands/run.rs`) — this crate
    /// does not otherwise run a Tokio reactor for its CLI-side process
    /// management, so introducing one here for symmetry with the async
    /// `aa-proxy` binary itself would be a bigger change than this increment
    /// needs.
    pub fn spawn(opts: ProxyGuardOptions) -> Result<Self, ProxyGuardError> {
        let binary = super::start::resolve_binary().ok_or(ProxyGuardError::BinaryNotFound)?;
        let binary = super::start::canonical_binary(binary);
        Self::spawn_with_binary(&binary, opts)
    }

    /// The spawn itself, over a caller-named binary. Split out from
    /// [`Self::spawn`] so the identity probe and evidence plumbing
    /// (AAASM-5984) can be driven against a fixture binary in tests without
    /// mutating `$PATH`/`HOME` to fool `resolve_binary()`.
    pub(crate) fn spawn_with_binary(
        binary: &std::path::Path,
        opts: ProxyGuardOptions,
    ) -> Result<Self, ProxyGuardError> {
        Self::spawn_with_binary_in(binary, opts, std::path::Path::new(FALLBACK_BASE))
    }

    /// [`Self::spawn_with_binary`] with the base directory of the short-path
    /// fallback named by the caller, so tests never touch the real `/tmp`.
    pub(crate) fn spawn_with_binary_in(
        binary: &std::path::Path,
        opts: ProxyGuardOptions,
        fallback_base: &std::path::Path,
    ) -> Result<Self, ProxyGuardError> {
        // AAASM-5984: ask the resolved binary what build it is before
        // spawning it long-running — see `build_identity`'s module doc for
        // why this is a separate bounded probe rather than capturing the
        // child's own startup log.
        let build_evidence = probe(binary);

        // AAASM-6395: refuse a launch whose provider keys the proxy would refuse,
        // before anything is spawned.
        super::provider_keys::preflight(binary)
            .map_err(|reason| ProxyGuardError::SpawnFailed(std::io::Error::other(reason)))?;

        // AAASM-6262 (AC3): a launch that brokers a credential must be able to
        // revoke it while it runs. The control socket is therefore required for
        // such a launch: it is placed in the launch directory when that fits, in a
        // short private fallback otherwise, and the launch is refused when neither
        // works. A launch that brokers nothing keeps its previous behaviour
        // (a socket when the path fits, none otherwise, nothing created).
        let brokered = super::provider_keys::delivering();
        let (control_path, fallback_socket) = Self::plan_control_socket(&opts, brokered, fallback_base)?;
        let discard_fallback = |socket: &Option<PathBuf>| {
            if let Some(socket) = socket {
                let _ = std::fs::remove_file(socket);
            }
        };

        let mut cmd = build_command_with_control(binary, &opts, control_path.as_deref());
        let mut child = cmd.spawn().map_err(ProxyGuardError::SpawnFailed)?;
        if let Err(e) = super::provider_keys::deliver(&mut child) {
            // A proxy without its keys would forward the agent's own credential
            // header unchanged, so the launch is refused rather than degraded.
            terminate_gracefully(&mut child);
            let _ = std::fs::remove_file(&opts.ready_file);
            discard_fallback(&fallback_socket);
            return Err(ProxyGuardError::SpawnFailed(e));
        }

        match wait_for_ready_file(&opts.ready_file, READINESS_TIMEOUT, &mut child) {
            ReadyFileOutcome::Ready(bound_addr) => {
                // The proxy binds the control socket before it reports ready, so a
                // socket that was required and is not answering is a proxy that
                // cannot be revoked. Prove it answers, and that it is THIS proxy
                // that answers, before the launch is allowed to proceed.
                if brokered {
                    let proven = control_path
                        .as_deref()
                        .is_some_and(|socket| Self::control_socket_answers(socket, child.id()));
                    if !proven {
                        terminate_gracefully(&mut child);
                        let _ = std::fs::remove_file(&opts.ready_file);
                        discard_fallback(&fallback_socket);
                        return Err(ProxyGuardError::RevocationUnavailable(
                            "the proxy's control socket did not answer as the spawned proxy".to_string(),
                        ));
                    }
                }
                Ok(ProxyGuard {
                    child,
                    ready_file: opts.ready_file,
                    bound_addr,
                    build_evidence,
                    fallback_socket,
                })
            }
            ReadyFileOutcome::Timeout => {
                // Not yet a ProxyGuard, so Drop will never run for this
                // child — the same graceful-then-forceful teardown has to
                // happen here explicitly, or a refused launch would leak
                // exactly the process the refusal is supposed to prevent.
                terminate_gracefully(&mut child);
                let _ = std::fs::remove_file(&opts.ready_file);
                discard_fallback(&fallback_socket);
                Err(ProxyGuardError::ReadinessTimeout)
            }
            ReadyFileOutcome::ChildExited(status) => {
                let _ = std::fs::remove_file(&opts.ready_file);
                discard_fallback(&fallback_socket);
                Err(ProxyGuardError::ChildExitedBeforeReady(status))
            }
        }
    }

    /// Decide this launch's control socket: `(path handed to the proxy, fallback socket to remove)`.
    ///
    /// A launch that brokers a credential must be revocable while it runs, so for
    /// one the answer is a working path or an error. A launch that brokers nothing
    /// keeps its previous behaviour. On a platform without Unix sockets nothing can
    /// revoke, so a brokered launch is refused there too rather than started blind.
    #[cfg(unix)]
    fn plan_control_socket(
        opts: &ProxyGuardOptions,
        brokered: bool,
        fallback_base: &std::path::Path,
    ) -> Result<(Option<PathBuf>, Option<PathBuf>), ProxyGuardError> {
        let plan = match opts.ready_file.parent() {
            Some(dir) => super::ctl_path::plan(dir, brokered, fallback_base)
                .map_err(|e| ProxyGuardError::RevocationUnavailable(e.to_string()))?,
            None if brokered => {
                return Err(ProxyGuardError::RevocationUnavailable(
                    "the launch has no directory to hold a control socket".to_string(),
                ))
            }
            None => None,
        };
        let fallback = plan
            .as_ref()
            .filter(|p| p.is_fallback())
            .map(|p| p.path().to_path_buf());
        Ok((plan.map(|p| p.path().to_path_buf()), fallback))
    }

    #[cfg(not(unix))]
    fn plan_control_socket(
        _opts: &ProxyGuardOptions,
        brokered: bool,
        _fallback_base: &std::path::Path,
    ) -> Result<(Option<PathBuf>, Option<PathBuf>), ProxyGuardError> {
        if brokered {
            return Err(ProxyGuardError::RevocationUnavailable(
                "credential revocation needs Unix sockets, which this platform does not provide".to_string(),
            ));
        }
        Ok((None, None))
    }

    /// Whether `socket` answers a ping as the process we spawned.
    #[cfg(unix)]
    fn control_socket_answers(socket: &std::path::Path, pid: u32) -> bool {
        // The proxy binds the socket before it reports ready, so a healthy one answers the first
        // time. The retries only absorb a heavily loaded host, so a slow answer is not mistaken
        // for the absence of a revoke path (which would refuse a healthy launch).
        (0..3).any(|attempt| {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(300));
            }
            super::revoke::ping_as(socket, Some(pid))
        })
    }

    #[cfg(not(unix))]
    fn control_socket_answers(_socket: &std::path::Path, _pid: u32) -> bool {
        false
    }

    /// The address to route this launch's tool at (`HTTPS_PROXY`/`HTTP_PROXY`).
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// The spawned proxy's OS pid. Exposed for tests and diagnostics
    /// (leak-freedom verification, AAASM-5865, needs to assert this pid is
    /// gone after drop) — not meant for a caller to signal directly; use
    /// `Drop` for that.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// What build the spawned `aa-proxy` claims to be (AAASM-5984). Read by
    /// `run_audit.rs` so a redaction-evidence claim can attribute itself to a
    /// named commit rather than to whatever answered.
    pub fn build_evidence(&self) -> &ProxyBuildEvidence {
        &self.build_evidence
    }
}

impl Drop for ProxyGuard {
    /// Graceful-then-forceful teardown: `SIGTERM`, wait up to
    /// [`GRACEFUL_SHUTDOWN_TIMEOUT`] for the process to exit on its own (so
    /// it can flush pending audit evidence — the whole reason this is not
    /// a plain `SIGKILL`), then `SIGKILL` if it hasn't.
    ///
    /// This is a `std::process::Child`, not Tokio's — there is no
    /// `kill_on_drop` builtin to layer under as a backstop the way
    /// `aa-runtime/src/runtime.rs` does for its Tokio-spawned gateway; this
    /// `Drop` impl *is* the complete teardown path, not a fallback for one.
    /// It runs during an unwinding panic the same as any other `Drop` (Rust
    /// guarantees this unless a second panic occurs), so a panicking caller
    /// still reaps its proxy.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ready_file);
        terminate_gracefully(&mut self.child);
        if let Some(socket) = &self.fallback_socket {
            let _ = std::fs::remove_file(socket);
        }
    }
}

/// `SIGTERM` → poll → `SIGKILL`, reusing the exact ladder shape already
/// proven in `aa-cli/src/commands/proxy/stop.rs` (standalone `aasm proxy
/// stop`) and `aa-cli/src/commands/stop.rs` (`aasm stop`) — same signals,
/// same escalation logic, applied to an owned [`Child`] handle instead of a
/// PID read from a state file.
#[cfg(unix)]
fn terminate_gracefully(child: &mut Child) {
    let pid = child.id() as libc::pid_t;
    // SIGTERM may already be moot if the child exited on its own since the
    // last check (e.g. it crashed) — kill() returning an error here (ESRCH)
    // just means there is nothing left to signal, not a problem to surface.
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };

    let deadline = Instant::now() + GRACEFUL_SHUTDOWN_TIMEOUT;
    loop {
        // `Err` (e.g. `ECHILD`, meaning something else already reaped this
        // child) must end the wait the same as `Ok(Some(_))` — treating it
        // as "still running" would poll out the full timeout and then
        // SIGKILL a pid this process no longer owns. Nothing today reaps a
        // ProxyGuard's child except this function, so this is currently
        // unreachable, but it is cheap to close now rather than leave a
        // TOCTOU waiting for a future caller that does add another reaper.
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    // Reap unconditionally: an un-`wait`ed child is a zombie entry in this
    // process's table until someone reaps it, and nothing else will.
    let _ = child.wait();
}

#[cfg(not(unix))]
fn terminate_gracefully(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shell one-liner that traps SIGTERM and exits 0 on receiving it,
    /// rather than dying to the signal's default disposition. Distinguishing
    /// "exited because it handled SIGTERM" from "exited because SIGKILL
    /// killed it" is exactly what the graceful-vs-forceful assertion below
    /// needs, and a plain `sleep` cannot provide that signal.
    /// A shell script that installs a SIGTERM trap, signals that the trap is
    /// actually installed by touching `marker` (so a caller can wait on a
    /// real event instead of a fixed sleep — a fixed sleep either pads every
    /// run with dead time or, if too short, races the shell's own startup
    /// and lets SIGTERM arrive before `trap` has executed, silently taking
    /// the default disposition instead of the handler), then loops.
    fn trap_term_script(marker: &std::path::Path) -> String {
        format!(
            "trap 'exit 0' TERM; touch {}; while true; do sleep 0.05; done",
            marker.display()
        )
    }

    /// Poll for `marker` to exist, for up to 2s. Used only to synchronize a
    /// test with a spawned shell's own startup — never a substitute for the
    /// production readiness protocol (`wait_for_ready_file`), which has its
    /// own, stronger guarantee (an atomic rename, not a bare file-exists
    /// check racing a partial write from a shell `touch`).
    fn wait_for_marker(marker: &std::path::Path) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !marker.exists() {
            assert!(
                Instant::now() < deadline,
                "marker file never appeared: {}",
                marker.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Proves `terminate_gracefully` takes the SIGTERM path when the child
    /// cooperates, not the SIGKILL escalation — a graceful shutdown that
    /// silently always escalated to SIGKILL would still pass a test that
    /// only checked "the process is gone afterward".
    #[test]
    fn terminate_gracefully_uses_sigterm_when_the_child_cooperates() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("trap-installed");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(trap_term_script(&marker))
            .spawn()
            .expect("spawn sh");
        wait_for_marker(&marker);

        let start = Instant::now();
        terminate_gracefully(&mut child);
        let elapsed = start.elapsed();

        let status = child
            .try_wait()
            .expect("child must be reaped by now")
            .expect("child must have exited");
        assert!(
            status.success(),
            "a child that trapped SIGTERM and exited 0 must be observed as a clean exit, got: {status:?}"
        );
        assert!(
            elapsed < GRACEFUL_SHUTDOWN_TIMEOUT,
            "a cooperating child must not need the full escalation timeout: took {elapsed:?}"
        );
    }

    /// The escalation half: a child that ignores SIGTERM entirely must still
    /// be gone by the time `terminate_gracefully` returns, via SIGKILL.
    #[test]
    fn terminate_gracefully_escalates_to_sigkill_when_the_child_ignores_sigterm() {
        use std::os::unix::process::ExitStatusExt;

        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("trap-installed");
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap '' TERM; touch {}; while true; do sleep 0.05; done",
                marker.display()
            ))
            .spawn()
            .expect("spawn sh");
        wait_for_marker(&marker);

        terminate_gracefully(&mut child);

        let status = child
            .try_wait()
            .expect("child must be reaped by now")
            .expect("child must have exited");
        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL),
            "an uncooperative child must be killed by SIGKILL, got: {status:?}"
        );
    }

    fn options_with_ready_file(ready_file: &std::path::Path) -> ProxyGuardOptions {
        ProxyGuardOptions {
            ready_file: ready_file.to_path_buf(),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: Some("agent-under-test".to_string()),
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Never,
        }
    }

    /// `AA_PROXY_CONTROL_SOCKET` as `build_command_with_control` leaves it on the
    /// command: `Some(Some(v))` set, `Some(None)` explicitly removed, `None` untouched.
    fn control_env(cmd: &std::process::Command) -> Option<Option<std::ffi::OsString>> {
        cmd.get_envs()
            .find(|(k, _)| *k == std::ffi::OsStr::new("AA_PROXY_CONTROL_SOCKET"))
            .map(|(_, v)| v.map(std::ffi::OsStr::to_os_string))
    }

    #[test]
    fn the_control_socket_variable_is_set_when_given_and_removed_when_not() {
        let opts = options_with_ready_file(std::path::Path::new("/tmp/runs/a-1/ready"));
        let bin = std::path::Path::new("/usr/bin/aa-proxy");
        let with = build_command_with_control(bin, &opts, Some(std::path::Path::new("/tmp/x/ctl.sock")));
        assert_eq!(
            control_env(&with),
            Some(Some(std::ffi::OsString::from("/tmp/x/ctl.sock")))
        );
        // None must REMOVE it explicitly, so an ambient value cannot decide the launch's surface.
        let without = build_command_with_control(bin, &opts, None);
        assert_eq!(control_env(&without), Some(None));
        // The default builder derives the in-launch-directory socket when it fits.
        assert_eq!(
            control_env(&build_command(bin, &opts)),
            Some(Some(std::ffi::OsString::from("/tmp/runs/a-1/ctl.sock")))
        );
    }

    /// A stand-in `aa-proxy` for the spawn-level tests. As the SAME process (`exec`),
    /// it reads the delivered payload, binds the control socket it was given when
    /// `serve_control`, reports ready, and answers pings with a pong, like the real
    /// proxy's order of startup. Records its pid and the control-socket variable it
    /// saw, and touches `marker` only on a real start (not for `--version` /
    /// `--capabilities` probes).
    #[cfg(unix)]
    fn write_stub_proxy(
        dir: &std::path::Path,
        ready: &std::path::Path,
        serve_control: bool,
    ) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        assert!(
            std::process::Command::new("python3")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success()),
            "the spawn-level proxy tests need python3 on PATH"
        );
        let marker = dir.join("started.marker");
        let pidfile = dir.join("stub.pid");
        let ctlenv = dir.join("ctlenv.txt");
        let py = dir.join("stub_proxy.py");
        std::fs::write(
            &py,
            r#"import os, sys, socket, time
ready, pidfile, ctlenv, serve = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1"
open(pidfile, "w").write(str(os.getpid()))
sock = os.environ.get("AA_PROXY_CONTROL_SOCKET")
open(ctlenv, "w").write(repr(sock))
sys.stdin.read()
if serve and sock:
    s = socket.socket(socket.AF_UNIX); s.bind(sock); os.chmod(sock, 0o600); s.listen(4)
open(ready + ".tmp", "w").write("127.0.0.1:59999\n"); os.rename(ready + ".tmp", ready)
while True:
    if serve and sock:
        c, _ = s.accept(); c.recv(1024); c.sendall(b'{"outcome":"pong"}\n'); c.close()
    else:
        time.sleep(0.05)
"#,
        )
        .unwrap();
        let stub = dir.join("aa-proxy");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh
                 if [ \"$1\" = \"--version\" ]; then echo 'aa-proxy 0.0.1-rc.8'; echo 'build-sha: {sha}'; \
                 echo 'build-identity-source: checkout'; exit 0; fi
                 if [ \"$1\" = \"--capabilities\" ]; then echo provider-keys-stdin; exit 0; fi
                 touch \"{marker}\"
                 exec python3 \"{py}\" \"{ready}\" \"{pidfile}\" \"{ctlenv}\" {serve}
",
                sha = "f".repeat(40),
                marker = marker.display(),
                py = py.display(),
                ready = ready.display(),
                pidfile = pidfile.display(),
                ctlenv = ctlenv.display(),
                serve = u8::from(serve_control),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        (stub, marker, pidfile, ctlenv)
    }

    /// Sets (or clears) the brokered-credential variable for one test and always
    /// clears it again, including when an assertion panics first.
    #[cfg(unix)]
    struct BrokeredEnv;

    #[cfg(unix)]
    impl BrokeredEnv {
        fn set() -> Self {
            std::env::set_var("AA_PROXY_PROVIDER_KEYS", "api.anthropic.com=sk-ant-QA6262-synthetic");
            Self
        }

        fn unset() -> Self {
            std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
            Self
        }
    }

    #[cfg(unix)]
    impl Drop for BrokeredEnv {
        fn drop(&mut self) {
            std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
        }
    }

    /// A launch directory whose `ctl.sock` cannot fit a socket address, under a
    /// short temp root so the FALLBACK path does fit.
    #[cfg(unix)]
    fn long_launch(root: &std::path::Path) -> PathBuf {
        let dir = root
            .join("s".repeat(aa_proxy::control::MAX_SOCKET_PATH_BYTES))
            .join("runs")
            .join("agent-x-AbC123");
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn short_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new().tempdir_in("/tmp").unwrap()
    }

    #[cfg(unix)]
    fn pid_gone(pidfile: &std::path::Path) -> bool {
        let pid: i32 = std::fs::read_to_string(pidfile).unwrap().trim().parse().unwrap();
        // The child was already waited on by the guard, so a gone process fails kill(0).
        unsafe { libc::kill(pid, 0) != 0 }
    }

    /// AC3: a brokered launch whose launch directory is too long for a socket still
    /// gets a WORKING revoke path, at the short private fallback, proven by a ping
    /// answered by the spawned proxy itself; and the fallback socket is removed with
    /// the launch.
    #[cfg(unix)]
    #[test]
    fn a_brokered_launch_with_a_long_path_gets_a_working_fallback_socket() {
        let _lock = crate::test_support::env_guard();
        let _keys = BrokeredEnv::set();
        let root = short_tempdir();
        let fallback_base = short_tempdir();
        let launch = long_launch(root.path());
        assert!(
            super::super::ctl_path::primary_socket(&launch).is_none(),
            "precondition"
        );
        let ready = launch.join("ready");
        let (stub, _marker, _pid, ctlenv) = write_stub_proxy(root.path(), &ready, true);

        let guard = ProxyGuard::spawn_with_binary_in(&stub, options_with_ready_file(&ready), fallback_base.path());
        let guard = guard.expect("a brokered launch with a long path must get the fallback socket");

        let socket = guard.fallback_socket.clone().expect("the fallback was used");
        assert!(socket.starts_with(super::super::ctl_path::fallback_dir_in(fallback_base.path())));
        assert_eq!(
            std::fs::read_to_string(&ctlenv).unwrap(),
            format!("{:?}", socket.to_string_lossy()).replace('"', "'")
        );
        assert!(
            super::super::revoke::ping_as(&socket, Some(guard.pid())),
            "the spawned proxy answers on it"
        );
        drop(guard);
        assert!(!socket.exists(), "the fallback socket is removed with the launch");
    }

    /// Fail closed: with nowhere trustworthy to put the socket, a brokered launch is
    /// REFUSED before anything is started. The control for the refusal is the test
    /// above (the same launch with a sound fallback directory is admitted).
    #[cfg(unix)]
    #[test]
    fn a_brokered_launch_is_refused_when_no_control_path_can_be_made() {
        use std::os::unix::fs::PermissionsExt;
        let _lock = crate::test_support::env_guard();
        let _keys = BrokeredEnv::set();
        let root = short_tempdir();
        let fallback_base = short_tempdir();
        let bad = super::super::ctl_path::fallback_dir_in(fallback_base.path());
        std::fs::create_dir(&bad).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
        let launch = long_launch(root.path());
        let ready = launch.join("ready");
        let (stub, marker, _pid, _ctlenv) = write_stub_proxy(root.path(), &ready, true);

        let outcome = ProxyGuard::spawn_with_binary_in(&stub, options_with_ready_file(&ready), fallback_base.path());
        assert!(
            matches!(outcome, Err(ProxyGuardError::RevocationUnavailable(_))),
            "got {:?}",
            outcome.err().map(|e| e.to_string())
        );
        assert!(!marker.exists(), "the proxy must not have been started");
    }

    #[cfg(unix)]
    #[test]
    fn a_brokered_launch_with_no_launch_directory_is_refused_before_anything_starts() {
        let _lock = crate::test_support::env_guard();
        let _keys = BrokeredEnv::set();
        let root = short_tempdir();
        let (stub, marker, _pid, _ctlenv) = write_stub_proxy(root.path(), &root.path().join("ready"), true);
        // `/` has no parent, so there is nowhere to hold a control socket.
        let outcome =
            ProxyGuard::spawn_with_binary_in(&stub, options_with_ready_file(std::path::Path::new("/")), root.path());
        assert!(matches!(outcome, Err(ProxyGuardError::RevocationUnavailable(_))));
        assert!(!marker.exists(), "the proxy must not have been started");
    }

    /// "Working" is demonstrated, not assumed: a proxy that reports ready but does
    /// not answer on its control socket cannot be revoked, so the launch is refused
    /// and the proxy it started is stopped.
    #[cfg(unix)]
    #[test]
    fn a_brokered_launch_is_refused_when_the_ready_proxy_has_no_working_control_socket() {
        let _lock = crate::test_support::env_guard();
        let _keys = BrokeredEnv::set();
        let root = short_tempdir();
        let launch = root.path().join("runs").join("agent-x-AbC123");
        std::fs::create_dir_all(&launch).unwrap();
        let ready = launch.join("ready");
        let (stub, marker, pidfile, _ctlenv) = write_stub_proxy(root.path(), &ready, false);

        let outcome = ProxyGuard::spawn_with_binary_in(&stub, options_with_ready_file(&ready), root.path());
        assert!(matches!(outcome, Err(ProxyGuardError::RevocationUnavailable(_))));
        assert!(marker.exists(), "control: it WAS started, then refused");
        assert!(
            pid_gone(&pidfile),
            "the refused proxy must be stopped, not left running"
        );
    }

    /// The default for a launch that brokers nothing is unchanged: a long path just
    /// has no control socket, nothing is created, and the launch is not refused.
    #[cfg(unix)]
    #[test]
    fn a_launch_that_brokers_nothing_keeps_its_old_behaviour_with_a_long_path() {
        let _lock = crate::test_support::env_guard();
        let _keys = BrokeredEnv::unset();
        let root = short_tempdir();
        let fallback_base = short_tempdir();
        let launch = long_launch(root.path());
        let ready = launch.join("ready");
        let (stub, _marker, _pid, ctlenv) = write_stub_proxy(root.path(), &ready, false);

        let guard = ProxyGuard::spawn_with_binary_in(&stub, options_with_ready_file(&ready), fallback_base.path())
            .expect("nothing brokered, nothing to refuse");
        assert!(guard.fallback_socket.is_none());
        assert_eq!(
            std::fs::read_to_string(&ctlenv).unwrap(),
            "None",
            "no control socket was handed to the proxy"
        );
        assert!(
            !super::super::ctl_path::fallback_dir_in(fallback_base.path()).exists(),
            "the default path must not create the fallback directory"
        );
    }

    /// Machine-checks the env-var wiring `ProxyGuard::spawn` depends on,
    /// without spawning anything: review found `spawn()` had no coverage
    /// proving this wiring happens at all, so a deleted `cmd.env(...)` line
    /// — including `AA_PROXY_PARENT_PID`, which the parent-watch shutdown
    /// path (`aa-proxy/src/proxy/mod.rs`) depends on entirely — would have
    /// passed every existing test silently.
    #[test]
    fn build_command_sets_every_env_var_it_promises() {
        let opts = ProxyGuardOptions {
            ready_file: PathBuf::from("/tmp/ready"),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: Some("did:key:test".to_string()),
            gateway_endpoint: Some("http://127.0.0.1:50051".to_string()),
            audit_jsonl_path: Some(PathBuf::from("/tmp/audit.jsonl")),
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let cmd = build_command(std::path::Path::new("/usr/bin/aa-proxy"), &opts);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_ADDR")).copied().flatten(),
            Some(std::ffi::OsStr::new("127.0.0.1:0"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_READY_FILE")).copied().flatten(),
            Some(std::ffi::OsStr::new("/tmp/ready"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_CA_DIR")).copied().flatten(),
            Some(std::ffi::OsStr::new("/tmp/ca"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_PARENT_PID")).copied().flatten(),
            Some(std::process::id().to_string())
                .as_deref()
                .map(std::ffi::OsStr::new)
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_AGENT_ID")).copied().flatten(),
            Some(std::ffi::OsStr::new("did:key:test"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_GATEWAY_ENDPOINT"))
                .copied()
                .flatten(),
            Some(std::ffi::OsStr::new("http://127.0.0.1:50051"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_LLM_ONLY")).copied().flatten(),
            Some(std::ffi::OsStr::new("false")),
            "a gateway-managed launch must intercept non-LLM MCP hosts too"
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_AUDIT_JSONL_PATH"))
                .copied()
                .flatten(),
            Some(std::ffi::OsStr::new("/tmp/audit.jsonl"))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_SYSTEM_TRUST_INSTALL"))
                .copied()
                .flatten(),
            Some(std::ffi::OsStr::new("auto"))
        );
    }

    /// AAASM-5978: the `Never` half of `system_trust_install` — a managed
    /// launch whose adapter reports process-scoped CA trust must still see
    /// the variable set (never omitted), just with the other value, so a
    /// spawned `aa-proxy` makes zero System Keychain calls for it.
    #[test]
    fn build_command_sets_never_when_system_trust_install_is_never() {
        let opts = ProxyGuardOptions {
            ready_file: PathBuf::from("/tmp/ready"),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Never,
        };
        let cmd = build_command(std::path::Path::new("/usr/bin/aa-proxy"), &opts);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_SYSTEM_TRUST_INSTALL"))
                .copied()
                .flatten(),
            Some(std::ffi::OsStr::new("never"))
        );
    }

    /// The `None` half of the optional fields: nothing gateway/agent/audit-
    /// shaped should appear at all, not even as an empty string — an absent
    /// `AA_AGENT_ID` and an `AA_AGENT_ID=""` mean different things to
    /// `ProxyConfig::from_env`'s `env_optional`.
    #[test]
    fn build_command_omits_unset_optional_env_vars_entirely() {
        let opts = ProxyGuardOptions {
            ready_file: PathBuf::from("/tmp/ready"),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let cmd = build_command(std::path::Path::new("/usr/bin/aa-proxy"), &opts);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        for key in [
            "AA_AGENT_ID",
            "AA_PROXY_GATEWAY_ENDPOINT",
            "AA_PROXY_LLM_ONLY",
            "AA_PROXY_AUDIT_JSONL_PATH",
        ] {
            assert!(
                !env.contains_key(std::ffi::OsStr::new(key)),
                "{key} must not be set when its opt is None"
            );
        }
    }

    /// AAASM-5923/F2 (independent review): a written trusted-config artifact
    /// must actually reach the spawned proxy — `aa-proxy`'s own
    /// `ProxyConfig::from_env` reads only `AA_PROXY_TRUSTED_CONFIG_PATH`, with
    /// no other fallback, and nothing set it before this fix, making the
    /// whole install-flags feature inert.
    #[test]
    fn build_command_sets_trusted_config_path_when_the_artifact_exists() {
        let _guard = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AASM_STATE_DIR", dir.path());
        let expected = crate::commands::trusted_upstream_path::trusted_upstream_config_path().unwrap();
        std::fs::create_dir_all(expected.parent().unwrap()).unwrap();
        std::fs::write(&expected, "{}").unwrap();

        let opts = ProxyGuardOptions {
            ready_file: PathBuf::from("/tmp/ready"),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let cmd = build_command(std::path::Path::new("/usr/bin/aa-proxy"), &opts);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        std::env::remove_var("AASM_STATE_DIR");

        assert_eq!(
            env.get(std::ffi::OsStr::new("AA_PROXY_TRUSTED_CONFIG_PATH"))
                .copied()
                .flatten(),
            Some(expected.as_os_str())
        );
    }

    /// Negative control for the test above: no artifact on disk means no env
    /// var — proves the wiring is conditional on the file actually existing,
    /// not merely on `AASM_STATE_DIR` being resolvable.
    #[test]
    fn build_command_omits_trusted_config_path_when_no_artifact_exists() {
        let _guard = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AASM_STATE_DIR", dir.path());

        let opts = ProxyGuardOptions {
            ready_file: PathBuf::from("/tmp/ready"),
            ca_dir: PathBuf::from("/tmp/ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let cmd = build_command(std::path::Path::new("/usr/bin/aa-proxy"), &opts);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        std::env::remove_var("AASM_STATE_DIR");

        assert!(!env.contains_key(std::ffi::OsStr::new("AA_PROXY_TRUSTED_CONFIG_PATH")));
    }

    /// ADR 0036 D6/Test 6/7: `build_command`'s `env_remove` calls must reach
    /// the real spawned `aa-proxy` child, not just the pre-spawn `Command`'s
    /// map — proven here by actually spawning a stub that dumps its received
    /// environment, the same "probe the real child" discipline as
    /// `spawn_and_wait`'s tests in `run.rs` (AAASM-5923).
    #[test]
    fn build_command_strips_ambient_proxy_vars_from_the_real_child() {
        let _lock = crate::test_support::env_guard();
        let mut prior = Vec::new();
        let ambient = [
            ("HTTPS_PROXY", "http://attacker.example:8080"),
            ("HTTP_PROXY", "http://attacker.example:8080"),
            ("ALL_PROXY", "http://attacker.example:8080"),
            ("NO_PROXY", "internal.example"),
            ("https_proxy", "http://attacker.example:8080"),
            ("http_proxy", "http://attacker.example:8080"),
            ("all_proxy", "http://attacker.example:8080"),
            ("no_proxy", "internal.example"),
        ];
        for (key, value) in ambient {
            prior.push((key, std::env::var(key).ok()));
            std::env::set_var(key, value);
        }

        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("aa-proxy");
        let out = dir.path().join("env.txt");
        std::fs::write(&stub, format!("#!/bin/sh\nenv > {}\n", out.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let opts = ProxyGuardOptions {
            ready_file: dir.path().join("ready"),
            ca_dir: dir.path().join("ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let mut cmd = build_command(&stub, &opts);
        let mut child = cmd.spawn().expect("stub must spawn");
        let status = child.wait().expect("stub must exit");
        assert!(status.success(), "stub exited non-zero: {status:?}");

        for (key, prior) in prior {
            match prior {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        let real_env = std::fs::read_to_string(&out).expect("read captured env");
        for (key, _) in ambient {
            assert!(
                !real_env.contains(&format!("{key}=")),
                "`{key}` leaked into the real spawned aa-proxy child's environment"
            );
        }
    }

    /// AAASM-5924 (ADR 0036 Test 8): an ambient `AA_PROXY_TRUSTED_CONFIG_PATH`
    /// (set in this process's own environment before launch, not by this
    /// boundary) reaches the real spawned child when no legitimate artifact
    /// exists on disk to override it — `build_command` never `env_remove`s
    /// this name, and `PROXY_EXCLUSION_AND_ROUTING_VARS` does not contain it.
    ///
    /// This is the honest, currently-true claim, not "not adopted" (see the
    /// filed follow-up bug against ADR 0036 Test 8's row wording): the only
    /// ambient channel into `aa-proxy`'s trusted config is this path pointer
    /// plus `AASM_STATE_DIR` (already disclosed, gap #3), and this is the
    /// more direct half of that same channel.
    #[test]
    fn ambient_trusted_config_path_reaches_the_real_child_when_no_artifact_overrides_it() {
        let _lock = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        // AASM_STATE_DIR resolves to an empty dir — no artifact for
        // `build_command` to find, so it sets nothing itself.
        std::env::set_var("AASM_STATE_DIR", dir.path());
        let prior_ambient = std::env::var("AA_PROXY_TRUSTED_CONFIG_PATH").ok();
        std::env::set_var("AA_PROXY_TRUSTED_CONFIG_PATH", "/attacker/controlled/path.json");

        let stub = dir.path().join("aa-proxy");
        let out = dir.path().join("env.txt");
        std::fs::write(&stub, format!("#!/bin/sh\nenv > {}\n", out.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let opts = ProxyGuardOptions {
            ready_file: dir.path().join("ready"),
            ca_dir: dir.path().join("ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let mut cmd = build_command(&stub, &opts);
        let mut child = cmd.spawn().expect("stub must spawn");
        let status = child.wait().expect("stub must exit");
        assert!(status.success());

        std::env::remove_var("AASM_STATE_DIR");
        match prior_ambient {
            Some(v) => std::env::set_var("AA_PROXY_TRUSTED_CONFIG_PATH", v),
            None => std::env::remove_var("AA_PROXY_TRUSTED_CONFIG_PATH"),
        }

        let real_env = std::fs::read_to_string(&out).expect("read captured env");
        assert!(
            real_env.contains("AA_PROXY_TRUSTED_CONFIG_PATH=/attacker/controlled/path.json"),
            "the ambient value must reach the real child when no artifact overrides it \
             (this is the currently-true claim ADR 0036 Test 8 must be corrected to state): {real_env}"
        );
    }

    /// Row 8's sibling: when a legitimate artifact DOES exist, this
    /// boundary's own resolved path wins over whatever ambient value was
    /// present — proves the test above is measuring an absence of an
    /// override, not that the ambient value always wins outright.
    #[test]
    fn a_real_artifact_overrides_an_ambient_trusted_config_path() {
        let _lock = crate::test_support::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("AASM_STATE_DIR", dir.path());
        let expected = crate::commands::trusted_upstream_path::trusted_upstream_config_path().unwrap();
        std::fs::create_dir_all(expected.parent().unwrap()).unwrap();
        std::fs::write(&expected, "{}").unwrap();
        let prior_ambient = std::env::var("AA_PROXY_TRUSTED_CONFIG_PATH").ok();
        std::env::set_var("AA_PROXY_TRUSTED_CONFIG_PATH", "/attacker/controlled/path.json");

        let stub = dir.path().join("aa-proxy");
        let out = dir.path().join("env.txt");
        std::fs::write(&stub, format!("#!/bin/sh\nenv > {}\n", out.display())).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let opts = ProxyGuardOptions {
            ready_file: dir.path().join("ready"),
            ca_dir: dir.path().join("ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let mut cmd = build_command(&stub, &opts);
        let mut child = cmd.spawn().expect("stub must spawn");
        let status = child.wait().expect("stub must exit");
        assert!(status.success());

        std::env::remove_var("AASM_STATE_DIR");
        match prior_ambient {
            Some(v) => std::env::set_var("AA_PROXY_TRUSTED_CONFIG_PATH", v),
            None => std::env::remove_var("AA_PROXY_TRUSTED_CONFIG_PATH"),
        }

        let real_env = std::fs::read_to_string(&out).expect("read captured env");
        assert!(
            real_env.contains(&format!("AA_PROXY_TRUSTED_CONFIG_PATH={}", expected.display())),
            "the boundary's own resolved artifact path must win over an ambient value: {real_env}"
        );
        assert!(
            !real_env.contains("/attacker/controlled/path.json"),
            "the ambient value must not survive when a real artifact exists: {real_env}"
        );
    }

    /// `ProxyGuard::spawn` failing at the readiness stage must not leak the
    /// child it spawned — no `ProxyGuard` exists yet for `Drop` to reap it.
    /// Uses a real stub "proxy" that never writes a ready file, so the
    /// timeout path is genuinely exercised rather than assumed.
    #[test]
    fn spawn_reaps_the_child_on_readiness_timeout() {
        // A stub aa-proxy: binds nothing, writes nothing, just sleeps —
        // standing in for a proxy that hung before reporting readiness.
        // Resolved directly rather than through `resolve_binary` (which
        // looks for a real `aa-proxy` on PATH) so this test does not depend
        // on one being installed.
        let dir = tempfile::tempdir().unwrap();
        let stub = dir.path().join("aa-proxy");
        std::fs::write(&stub, "#!/bin/sh\nsleep 60\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let opts = ProxyGuardOptions {
            ready_file: dir.path().join("ready"),
            ca_dir: dir.path().join("ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };

        // Exercise the same spawn + wait_for_ready_file sequence spawn()
        // uses internally, but against the stub directly and a short
        // timeout — spawn() itself always uses resolve_binary() plus the
        // real 30s READINESS_TIMEOUT, too slow and too binary-dependent for
        // a unit test. This test's job is the reap-on-timeout behavior, not
        // re-testing wait_for_ready_file's own timeout detection (that's
        // readiness.rs's job) or resolve_binary (start.rs's).
        let mut child = std::process::Command::new(&stub)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn stub");
        let child_pid = child.id();

        match wait_for_ready_file(&opts.ready_file, Duration::from_millis(300), &mut child) {
            ReadyFileOutcome::Timeout => {
                terminate_gracefully(&mut child);
            }
            other => panic!("expected Timeout against a stub that never writes the ready file, got {other:?}"),
        }

        assert!(
            !pid_is_alive_for_test(child_pid),
            "the timed-out child must be reaped, not left running"
        );
    }

    /// Test-only liveness probe, mirroring `aa-proxy`'s own `pid_is_alive`
    /// (`aa-proxy/src/proxy/mod.rs`) — duplicated rather than shared because
    /// pulling a cross-crate dependency in just for one test assertion is a
    /// worse trade than five lines of duplication.
    #[cfg(unix)]
    fn pid_is_alive_for_test(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    /// AAASM-5984 AC5 + falsification 1: a foreign `aa-proxy` at the resolved
    /// path — same version line, a different `build-sha` — must be named as
    /// such in the guard's own evidence, not silently trusted because it
    /// answered readiness correctly. Deleting the probe call in
    /// `spawn_with_binary` reddens this.
    #[cfg(unix)]
    #[test]
    fn a_foreign_proxy_build_is_named_in_the_guards_evidence() {
        const FOREIGN_SHA: &str = "ffffffffffffffffffffffffffffffffffffffff";

        let dir = tempfile::tempdir().unwrap();
        let ready_file = dir.path().join("ready");
        let stub = dir.path().join("aa-proxy");
        // `--version` answers a foreign identity; any other invocation writes
        // the ready file (atomically, matching `write_ready_file`'s own
        // rename-into-place guarantee) and sleeps, exactly like the real
        // `aa-proxy` binary's readiness protocol.
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"--version\" ]; then\n\
                 echo 'aa-proxy 0.0.1-rc.6'\n\
                 echo 'build-sha: {FOREIGN_SHA}'\n\
                 echo 'build-identity-source: checkout'\n\
                 exit 0\n\
                 fi\n\
                 tmp=\"{ready}.tmp\"\n\
                 printf '127.0.0.1:59999\\n' > \"$tmp\"\n\
                 mv \"$tmp\" \"{ready}\"\n\
                 while true; do sleep 0.05; done\n",
                ready = ready_file.display(),
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let opts = ProxyGuardOptions {
            ready_file,
            ca_dir: dir.path().join("ca"),
            agent_id: None,
            gateway_endpoint: None,
            audit_jsonl_path: None,
            system_trust_install: aa_proxy::config::SystemTrustInstall::Auto,
        };
        let guard = ProxyGuard::spawn_with_binary(&stub, opts).expect("stub must report ready");

        assert_eq!(guard.build_evidence().identity.build_sha, FOREIGN_SHA);
        assert_ne!(
            guard.build_evidence().identity.build_sha,
            aa_runtime::build_identity::BUILD_SHA,
            "the fixture must actually differ from this build's own SHA"
        );
        assert_eq!(guard.build_evidence().executable, stub);
    }
}
