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

use super::readiness::{wait_for_ready_file, ReadyFileOutcome};

/// How long to wait for the dedicated proxy to report readiness before
/// treating the launch as failed. Generous relative to a normal bind (which
/// is near-instant): the same process may also be doing first-run CA
/// creation and, on macOS, a Keychain trust prompt that requires operator
/// interaction (`aa-proxy/src/lib.rs::run`) — a short timeout here would
/// turn "waiting on the operator" into a spurious refusal.
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
}

impl std::fmt::Display for ProxyGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinaryNotFound => write!(
                f,
                "aa-proxy binary not found; install with `cargo install aa-proxy` or ensure it is on PATH \
                 or in ~/.cargo/bin"
            ),
            Self::SpawnFailed(e) => write!(f, "failed to spawn aa-proxy: {e}"),
            Self::ReadinessTimeout => {
                write!(f, "aa-proxy did not report readiness within {READINESS_TIMEOUT:?}")
            }
            Self::ChildExitedBeforeReady(status) => {
                write!(f, "aa-proxy exited before reporting readiness (status: {status})")
            }
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
fn build_command(binary: &std::path::Path, opts: &ProxyGuardOptions) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    cmd.env("AA_PROXY_ADDR", "127.0.0.1:0");
    cmd.env("AA_PROXY_READY_FILE", &opts.ready_file);
    cmd.env("AA_CA_DIR", &opts.ca_dir);
    cmd.env("AA_PROXY_PARENT_PID", std::process::id().to_string());
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

        let mut cmd = build_command(&binary, &opts);
        let mut child = cmd.spawn().map_err(ProxyGuardError::SpawnFailed)?;

        match wait_for_ready_file(&opts.ready_file, READINESS_TIMEOUT, &mut child) {
            ReadyFileOutcome::Ready(bound_addr) => Ok(ProxyGuard {
                child,
                ready_file: opts.ready_file,
                bound_addr,
            }),
            ReadyFileOutcome::Timeout => {
                // Not yet a ProxyGuard, so Drop will never run for this
                // child — the same graceful-then-forceful teardown has to
                // happen here explicitly, or a refused launch would leak
                // exactly the process the refusal is supposed to prevent.
                terminate_gracefully(&mut child);
                let _ = std::fs::remove_file(&opts.ready_file);
                Err(ProxyGuardError::ReadinessTimeout)
            }
            ReadyFileOutcome::ChildExited(status) => {
                let _ = std::fs::remove_file(&opts.ready_file);
                Err(ProxyGuardError::ChildExitedBeforeReady(status))
            }
        }
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
}
