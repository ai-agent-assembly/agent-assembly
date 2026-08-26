//! `aasm proxy start` — spawn the aa-proxy sidecar as a background process.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

use clap::Args;

use super::pid::{self, ProxyState};
use super::{identity, trust};

/// Arguments for `aasm proxy start`.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Address the proxy should listen on.
    #[arg(long, default_value = "127.0.0.1:8899", env = "AA_PROXY_ADDR")]
    pub listen: String,
    /// Gateway URL to forward policy decisions to.
    #[arg(long, env = "AA_GATEWAY_URL")]
    pub gateway: Option<String>,
    /// Directory for CA certificate and key storage.
    #[arg(long, env = "AA_CA_DIR")]
    pub ca_dir: Option<PathBuf>,
    /// Run in the foreground instead of daemonizing.
    #[arg(long)]
    pub no_detach: bool,
    /// File to redirect proxy stdout/stderr to (background mode only).
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    // The doc comment is the `--help` text clap shows, so it is written for the
    // operator reading it; the reasoning behind the refusal lives on
    // `checked_listen`.
    /// State that a non-loopback `--listen` address is intended
    ///
    /// Intent is not authorization. A proxy reachable from other hosts also
    /// needs TLS on its listener and client authentication, neither of which
    /// aa-proxy implements — so this option currently changes only which
    /// refusal you get, and never permits the bind.
    #[arg(long)]
    pub allow_remote_clients: bool,
}

/// Whether a proxy may be started on `listen`, or the message to print instead.
///
/// AAASM-5348. Before this check, `aasm proxy start --listen 0.0.0.0:PORT`
/// succeeded and `aasm proxy status` reported a healthy proxy, while every
/// `aasm run` refused to route a governed tool at it — [`trust::verify_endpoint`]
/// requires a loopback literal. The operator was left holding a proxy that
/// worked for everything except the one job it exists to do, with nothing
/// explaining the contradiction. Applying the same loopback rule here is what
/// removes that split: an address `aasm run` will never trust is one
/// `aasm proxy start` never produces.
///
/// Refusing rather than teaching `aasm run` to accept a remote endpoint is the
/// deliberate direction. `aasm run` refuses because the endpoint is reachable
/// off-host, and reachability is not authorization: `aa-proxy` has no listener
/// TLS and no client authentication ([`aa_proxy::config::REMOTE_PROTECTIONS`]),
/// so a routable listener is an interception endpoint that reads traffic under
/// a CA this machine trusts and spends the operator's provider keys for anyone
/// who connects. Until it can tell clients apart, the honest answer at start
/// time is no.
///
/// Separate from [`dispatch`] so the decision is testable without spawning a
/// process, and called from its first statement so a refusal happens before any
/// socket is bound and before any state file is written.
fn checked_listen(listen: &str, allow_remote_clients: bool) -> Result<(), String> {
    // Parsed here rather than left to the child: the loopback question cannot be
    // asked of a string, and a `--listen` the proxy could not parse already
    // failed — just later, as an opaque "did not bind within 5s".
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| format!("invalid --listen {listen:?}: it is not an `ip:port` literal"))?;
    // Standalone `aasm proxy start` never sets AA_PROXY_READY_FILE, so a
    // port-0 --listen stays refused here exactly as before (AAASM-5859).
    aa_proxy::config::check_bind_addr(addr, allow_remote_clients, false).map_err(|refusal| refusal.to_string())
}

fn default_log_path() -> PathBuf {
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("logs")
        .join("proxy.log")
}

/// Resolve the aa-proxy binary by trying, in order:
/// 1. `which aa-proxy` (checks PATH)
/// 2. `~/.cargo/bin/aa-proxy`
///
/// The former `./target/release/aa-proxy` cwd-relative fallback was dropped
/// (AAASM-4020): resolving a binary relative to the current working directory
/// lets whoever controls where `aasm` is invoked substitute an attacker-planted
/// `aa-proxy`. Only trusted, absolute locations (PATH, the cargo bin dir) are
/// honored.
pub fn resolve_binary() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        if let Ok(out) = std::process::Command::new("which").arg("aa-proxy").output() {
            if out.status.success() {
                let p = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        let cargo_bin = home.join(".cargo").join("bin").join("aa-proxy");
        if cargo_bin.exists() {
            return Some(cargo_bin);
        }
    }

    None
}

/// Build the environment overrides applied to the spawned `aa-proxy` child.
///
/// AAASM-4127: the proxy reads its gateway endpoint from
/// `AA_PROXY_GATEWAY_ENDPOINT` — **not** `AA_GATEWAY_URL`, which it ignores — and
/// only performs MCP `tools/call` enforcement when that endpoint is set. A prior
/// version exported `AA_GATEWAY_URL`, so `aasm proxy start --gateway <url>` left
/// `gateway_endpoint = None` → raw passthrough with MCP enforcement silently OFF.
///
/// When a gateway is configured we also force `AA_PROXY_LLM_ONLY=false` so
/// non-LLM MCP hosts are intercepted and routed to the gateway's PolicyService
/// rather than transparently tunnelled before enforcement can run.
fn proxy_child_env(listen: &str, gateway: Option<&str>) -> Vec<(&'static str, String)> {
    let mut env = vec![("AA_PROXY_ADDR", listen.to_string())];
    if let Some(gw) = gateway {
        env.push(("AA_PROXY_GATEWAY_ENDPOINT", gw.to_string()));
        env.push(("AA_PROXY_LLM_ONLY", "false".to_string()));
    }
    env
}

/// Build the state record for a proxy just spawned as `child_pid` from `binary`.
///
/// The record carries process-identity evidence because `aasm run` decides
/// whether to launch a governed tool from it, and a PID plus an address cannot
/// support that decision (see [`super::trust`]). The two evidence fields are
/// captured differently on purpose:
///
/// * the **start time** is read back from the kernel for `child_pid`. It is set
///   at fork and is not changed by the subsequent `exec`, so reading it now is
///   race-free even though the child may not have exec'd yet.
/// * the **executable** is the path that was spawned, not a read-back of the
///   live image, because the read-back *does* race the exec. The caller
///   canonicalises before spawning ([`canonical_binary`]), which matches what
///   the kernel will later report — `/proc/<pid>/exe` and `proc_pidpath` both
///   name the resolved image — so the comparison holds even when the proxy was
///   invoked through a symlink.
///
/// A field the platform cannot supply is left empty, which makes the record
/// unusable to the trust check — deliberately: an unverifiable proxy must fail
/// the launch, not silently pass it.
fn state_for_child(child_pid: u32, binary: &Path, listen_addr: &str) -> ProxyState {
    ProxyState {
        pid: child_pid,
        listen_addr: listen_addr.to_string(),
        start_token: identity::start_token(child_pid).unwrap_or_default(),
        exe_path: binary.to_path_buf(),
    }
}

/// The path the proxy must actually be spawned from: the resolved one.
///
/// Spawning the canonical path rather than the one `PATH` happened to yield is
/// what keeps `argv[0]` and the recorded executable the same string. That
/// matters because `aa-proxy` marks itself non-dumpable at startup (AAASM-3584),
/// after which the kernel will not name its image to `aasm run` and `argv[0]` is
/// the only image fact left (see [`super::identity`]). Resolving here also means
/// the record names the file that was executed rather than a symlink that could
/// be repointed afterwards.
pub(super) fn canonical_binary(binary: PathBuf) -> PathBuf {
    std::fs::canonicalize(&binary).unwrap_or(binary)
}

pub fn dispatch(args: StartArgs) -> ExitCode {
    // First, before the binary is resolved, before anything is spawned, and
    // before a state file exists: a refused start must not leave the operator
    // with a half-started proxy to clean up.
    if let Err(reason) = checked_listen(&args.listen, args.allow_remote_clients) {
        eprintln!("error: {reason}");
        return ExitCode::FAILURE;
    }

    let Some(binary) = resolve_binary() else {
        eprintln!(
            "error: aa-proxy binary not found.\n\
             Install with `cargo install aa-proxy` or ensure it is on PATH \
             or in ~/.cargo/bin."
        );
        return ExitCode::FAILURE;
    };
    let binary = canonical_binary(binary);

    let mut cmd = build_start_command(&binary, &args);

    if args.no_detach {
        // Foreground: inherit stdio, block until the process exits.
        return run_foreground(&mut cmd);
    }

    run_background(cmd, args, &binary)
}

/// Build the (unspawned) command for standalone `aasm proxy start`.
///
/// Separated from [`dispatch`] so the env-var wiring, including the ADR 0036
/// D6 removal, is unit-testable without resolving a real binary or spawning
/// anything — mirroring [`super::guard::build_command`]'s reasoning for the
/// per-launch dedicated proxy.
///
/// # ADR 0036 D6
///
/// [`proxy_child_env`] returns a `Vec` and cannot express removal, so the D6
/// invariant's removal step is applied here, immediately before the
/// `Command` is handed back to `dispatch` for spawn. This boundary has no
/// `--no-proxy` concept and never injects a trusted `HTTPS_PROXY`/
/// `HTTP_PROXY` value, so unconditional removal of all 8 case variants is
/// the whole rule for this spawn.
fn build_start_command(binary: &Path, args: &StartArgs) -> std::process::Command {
    let mut cmd = std::process::Command::new(binary);
    for (key, value) in proxy_child_env(&args.listen, args.gateway.as_deref()) {
        cmd.env(key, value);
    }
    if let Some(ref ca_dir) = args.ca_dir {
        cmd.env("AA_CA_DIR", ca_dir);
    }
    for name in crate::commands::run_env_sanitize::PROXY_EXCLUSION_AND_ROUTING_VARS {
        cmd.env_remove(name);
    }
    cmd
}

/// Foreground start: inherit stdio and block until the process exits.
fn run_foreground(cmd: &mut std::process::Command) -> ExitCode {
    match cmd.status() {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("error: failed to run aa-proxy: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Open (creating) the log file and a duplicated handle for stderr.
fn open_log_handles(log_file: &std::path::Path) -> Result<(std::fs::File, std::fs::File), ExitCode> {
    if let Some(parent) = log_file.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("warning: could not create log directory {}: {e}", parent.display());
        }
    }

    let log_out = match std::fs::OpenOptions::new().create(true).append(true).open(log_file) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not open log file {}: {e}", log_file.display());
            return Err(ExitCode::FAILURE);
        }
    };
    let log_err = match log_out.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: could not duplicate log file handle: {e}");
            return Err(ExitCode::FAILURE);
        }
    };
    Ok((log_out, log_err))
}

/// Record the spawned child's PID state, warning (never failing) on any gap that
/// would stop `aasm run` verifying this proxy later.
fn record_proxy_state(child_pid: u32, binary: &std::path::Path, listen: &str) {
    let state = state_for_child(child_pid, binary, listen);
    // A record `aasm run` cannot verify is worth saying out loud here rather
    // than only at the next launch: the operator is standing in front of this
    // command, not the one that will refuse.
    if state.start_token.is_empty() {
        eprintln!(
            "warning: this platform ({}) does not report process start times, so `aasm run` \
             will not be able to verify this proxy and will refuse to launch.",
            std::env::consts::OS
        );
    }
    if let Err(e) = trust::verify_proxy_binary(&state.exe_path) {
        eprintln!("warning: {e}; `aasm run` will refuse to launch against this proxy.");
    }
    if let Err(e) = pid::write_state(&state) {
        eprintln!("warning: could not write PID file: {e}");
    }
}

/// Background start: redirect stdio to the log file, spawn detached, record the
/// PID state, then wait for the proxy to bind.
fn run_background(mut cmd: std::process::Command, args: StartArgs, binary: &std::path::Path) -> ExitCode {
    let log_file = args.log_file.unwrap_or_else(default_log_path);
    let (log_out, log_err) = match open_log_handles(&log_file) {
        Ok(handles) => handles,
        Err(code) => return code,
    };

    cmd.stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .stdin(Stdio::null());

    // Create a new process group so the child isn't killed by the parent's SIGHUP.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to spawn aa-proxy from {}: {e}", binary.display());
            return ExitCode::FAILURE;
        }
    };

    let child_pid = child.id();
    record_proxy_state(child_pid, binary, &args.listen);

    println!("Starting aa-proxy on {} (PID {child_pid})...", args.listen);

    if super::readiness::wait_for_port(&args.listen, Duration::from_secs(5)) {
        println!("Proxy started on http://{}", args.listen);
        println!("Logs: {}", log_file.display());
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "error: aa-proxy did not bind to {} within 5s.\nCheck logs: {}",
            args.listen,
            log_file.display()
        );
        let _ = pid::remove_pid();
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Wrapper {
        #[command(flatten)]
        inner: StartArgs,
    }

    #[test]
    fn start_args_default_listen_address() {
        let w = Wrapper::parse_from(["test"]);
        assert_eq!(w.inner.listen, "127.0.0.1:8899");
    }

    #[test]
    fn start_args_custom_listen_address() {
        let w = Wrapper::parse_from(["test", "--listen", "0.0.0.0:9000"]);
        assert_eq!(w.inner.listen, "0.0.0.0:9000");
    }

    /// The default is the address `aasm run` will trust, so the shipped
    /// behaviour must survive the guard untouched.
    #[test]
    fn the_default_listen_address_is_accepted() {
        let default = Wrapper::parse_from(["test"]).inner.listen;
        assert_eq!(checked_listen(&default, false), Ok(()), "default {default} must start");
    }

    #[test]
    fn an_explicit_loopback_listen_address_is_accepted() {
        assert_eq!(checked_listen("127.0.0.1:9000", false), Ok(()));
        assert_eq!(checked_listen("[::1]:9000", false), Ok(()));
    }

    /// AAASM-5348: the address that used to start a proxy `aasm run` would
    /// never trust. The diagnostic has to carry the reason, since the operator
    /// asked for this address on purpose.
    #[test]
    fn a_bare_non_loopback_listen_address_is_refused() {
        let reason = checked_listen("0.0.0.0:9000", false)
            .expect_err("a proxy reachable from other hosts must not start by default");
        assert!(reason.contains("0.0.0.0:9000"), "must name the address, got: {reason}");
        assert!(
            reason.contains("not a loopback address"),
            "must say what disqualified it, got: {reason}"
        );
        assert!(
            reason.contains("--allow-remote-clients"),
            "must point at the option that states the intent, got: {reason}"
        );
    }

    /// The opt-in records intent; it cannot supply protections the proxy does
    /// not have. Naming them is the point — "refused" alone would read as a bug.
    #[test]
    fn the_opt_in_does_not_authorize_an_unprotected_remote_listener() {
        let reason = checked_listen("0.0.0.0:9000", true)
            .expect_err("--allow-remote-clients must not open an unauthenticated listener");
        assert!(
            reason.contains("TLS on the proxy listener"),
            "must name the missing transport protection, got: {reason}"
        );
        assert!(
            reason.contains("client authentication and authorization"),
            "must name the missing client-identity protection, got: {reason}"
        );
    }

    /// A `--listen` the proxy cannot parse is refused here rather than becoming
    /// an opaque "did not bind within 5s" after a process has been spawned.
    #[test]
    fn an_unparseable_listen_address_is_refused() {
        let reason = checked_listen("localhost:9000", false).expect_err("a hostname is not an ip:port literal");
        assert!(reason.contains("localhost:9000"), "must quote the input, got: {reason}");
    }

    #[test]
    fn start_args_allow_remote_clients_defaults_false() {
        assert!(!Wrapper::parse_from(["test"]).inner.allow_remote_clients);
        assert!(
            Wrapper::parse_from(["test", "--allow-remote-clients"])
                .inner
                .allow_remote_clients
        );
    }

    #[test]
    fn start_args_gateway_is_optional() {
        let w = Wrapper::parse_from(["test"]);
        assert!(w.inner.gateway.is_none());
    }

    #[test]
    fn start_args_no_detach_defaults_false() {
        let w = Wrapper::parse_from(["test"]);
        assert!(!w.inner.no_detach);
    }

    #[test]
    fn start_args_no_detach_flag() {
        let w = Wrapper::parse_from(["test", "--no-detach"]);
        assert!(w.inner.no_detach);
    }

    #[test]
    fn proxy_child_env_gateway_uses_proxy_endpoint_var() {
        // AAASM-4127 regression guard: aa-proxy reads AA_PROXY_GATEWAY_ENDPOINT,
        // so `--gateway <url>` must export that exact name. A prior bug exported
        // AA_GATEWAY_URL (which aa-proxy ignores), leaving gateway_endpoint None
        // → raw passthrough with MCP enforcement silently OFF.
        let env = proxy_child_env("127.0.0.1:8899", Some("http://127.0.0.1:50051"));
        assert!(
            env.contains(&("AA_PROXY_GATEWAY_ENDPOINT", "http://127.0.0.1:50051".to_string())),
            "gateway must be exported as AA_PROXY_GATEWAY_ENDPOINT, got: {env:?}"
        );
        // llm_only disabled so non-LLM MCP hosts reach the gateway routing
        // instead of being transparently tunnelled before enforcement.
        assert!(env.contains(&("AA_PROXY_LLM_ONLY", "false".to_string())));
        // The old, ignored variable name must never be exported to the child.
        assert!(
            !env.iter().any(|(k, _)| *k == "AA_GATEWAY_URL"),
            "AA_GATEWAY_URL must not be exported (aa-proxy ignores it)"
        );
    }

    #[test]
    fn proxy_child_env_omits_gateway_vars_when_absent() {
        let env = proxy_child_env("127.0.0.1:8899", None);
        assert!(!env.iter().any(|(k, _)| *k == "AA_PROXY_GATEWAY_ENDPOINT"));
        assert!(!env.iter().any(|(k, _)| *k == "AA_PROXY_LLM_ONLY"));
        // The listen address is always exported.
        assert!(env.contains(&("AA_PROXY_ADDR", "127.0.0.1:8899".to_string())));
    }

    /// ADR 0036 D6 (map level): `build_start_command`'s `env_remove` calls
    /// must be present in the returned `Command`'s own `get_envs()` — the
    /// `Command` here *is* the object that gets spawned, so this is not a
    /// pre-spawn-map-vs-real-child gap the way `aa-cli/src/commands/run.rs`'s
    /// `spawn_and_wait` had (AAASM-5923/F4).
    #[test]
    fn build_start_command_removes_all_eight_ambient_proxy_variants() {
        let args = Wrapper::parse_from(["test"]).inner;
        let cmd = build_start_command(std::path::Path::new("/usr/bin/aa-proxy"), &args);
        let env: std::collections::HashMap<_, _> = cmd.get_envs().collect();

        for name in crate::commands::run_env_sanitize::PROXY_EXCLUSION_AND_ROUTING_VARS {
            assert_eq!(
                env.get(std::ffi::OsStr::new(name)),
                Some(&None),
                "`{name}` must be explicitly removed (env_remove), not merely absent from the map"
            );
        }
    }

    /// The same guarantee, proven at the real spawned child (not the
    /// pre-spawn `Command`) — the discipline ADR 0036's Test 6/7 requires,
    /// applied here even though `build_start_command_removes_all_eight_ambient_proxy_variants`
    /// above already covers the map-level case, so a future refactor that
    /// stops building `Command` directly (e.g. via an intermediate `Vec`)
    /// cannot silently regress this boundary the way F4 did for `run.rs`.
    #[test]
    fn build_start_command_strips_ambient_proxy_vars_from_the_real_child() {
        let _lock = crate::test_support::env_guard();
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
        let mut prior = Vec::new();
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

        let args = Wrapper::parse_from(["test"]).inner;
        let mut cmd = build_start_command(&stub, &args);
        let status = cmd.status().expect("stub must spawn and exit");

        for (key, prior) in prior {
            match prior {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        assert!(status.success(), "stub exited non-zero: {status:?}");
        let real_env = std::fs::read_to_string(&out).expect("read captured env");
        for (key, _) in ambient {
            assert!(
                !real_env.contains(&format!("{key}=")),
                "`{key}` leaked into the real spawned aa-proxy child's environment"
            );
        }
    }

    /// The record's executable field and the child's `argv[0]` have to be the
    /// same string, because on Linux `argv[0]` is the only image fact the kernel
    /// still publishes once the proxy has hardened itself (AAASM-5323). They are
    /// the same string only if what gets spawned is already resolved, so a
    /// symlinked install must be followed here rather than at record time.
    #[test]
    fn the_spawned_path_is_resolved_not_the_symlink_it_was_found_through() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("aa-proxy");
        std::fs::write(&real, "not really a binary").unwrap();
        let link = tmp.path().join("aa-proxy-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert_eq!(
            canonical_binary(link),
            std::fs::canonicalize(&real).unwrap(),
            "a proxy found through a symlink must be spawned from the file the link resolves to"
        );
    }

    /// Whatever path the caller spawned is what the record must name — the
    /// resolution happens before the spawn, not after it, so the two cannot
    /// disagree.
    #[test]
    fn the_record_names_the_path_that_was_spawned() {
        let state = state_for_child(std::process::id(), Path::new("/opt/aa/aa-proxy"), "127.0.0.1:8899");
        assert_eq!(state.exe_path, PathBuf::from("/opt/aa/aa-proxy"));
    }
}
