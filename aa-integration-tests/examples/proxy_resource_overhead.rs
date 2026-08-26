//! AAASM-5868 — resource-overhead benchmark for the per-launch dedicated
//! `aa-proxy` (AAASM-5857/`ProxyGuard`, `aa-cli/src/commands/proxy/guard.rs`).
//!
//! # What this measures
//!
//! At 1 / 5 / 10 / 20 concurrent `aasm run` launches, each with its own
//! dedicated proxy: per-proxy RSS, idle CPU, active-forwarding CPU,
//! startup/readiness latency, FD count, cleanup latency after the launched
//! tool exits, and whether anything is left running once every launch has
//! terminated. This is the architecture acceptance evidence AAASM-5857's
//! design calls for the per-launch-proxy resource cost — see
//! `verification-reports/verification-report-AAASM-5868-proxy-resource-benchmark.md`
//! for the numbers this produced and the environment they were measured on.
//!
//! # Why a standalone driver, not a `#[test]`
//!
//! This is a slow, multi-minute measurement run whose value is the numbers it
//! prints, not a pass/fail assertion `cargo nextest` should gate CI on. An
//! `examples/` binary is the existing convention for that shape in this crate
//! (`proxy_with_mock_upstream.rs`) — auto-discovered by cargo, never picked up
//! by `cargo test`/`cargo nextest`.
//!
//! # Why the launched proxy is not the real `aa-proxy` binary
//!
//! The real `aa-proxy` installs its CA into the macOS System Keychain on
//! first use of a not-yet-trusted `ca_dir` (`aa-proxy/src/lib.rs::run`),
//! which blocks on a GUI authentication dialog this benchmark cannot click
//! through. `aa_proxy_no_keychain.rs` (this crate's own `examples/`) is the
//! same production `ProxyConfig::from_env()` load and the same
//! `proxy::ProxyServer` engine, with only that keychain-install step
//! omitted — see its own module doc. `ProxyGuard` cannot tell the
//! difference: it resolves whatever is on `PATH` named `aa-proxy` and drives
//! it through the same `AA_PROXY_READY_FILE`/`AA_PROXY_PARENT_PID` protocol
//! either way.
//!
//! # Running it
//!
//! Requires prebuilt **release** binaries — this measures resource cost, and
//! a debug build's numbers would not describe production:
//!
//! ```text
//! export CARGO_TARGET_DIR=/some/private/dir   # avoid the shared workspace target
//! cargo build --release -p aa-cli -p aa-proxy
//! cargo run --release -p aa-integration-tests --example proxy_resource_overhead
//! ```
//!
//! `CARGO_TARGET_DIR` must stay set for the `cargo run` invocation too, both
//! so it finds the release `aasm` binary above and so the private
//! `aa_proxy_no_keychain` example this binary also builds lands in the same
//! tree. Output: a human-readable table on stdout and a JSON dump at
//! `AA_BENCH_OUTPUT` (default `proxy_resource_overhead.json` in the current
//! directory).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_gateway::registry::AgentRegistry;
use aa_gateway::service::{AgentLifecycleServiceImpl, PolicyServiceImpl};
use aa_gateway::PolicyEngine;
use aa_proto::assembly::agent::v1::agent_lifecycle_service_server::AgentLifecycleServiceServer;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use tokio::net::TcpListener;
use tonic::transport::Server;

/// A gateway serving both `AgentLifecycleService` (so a launch can register —
/// `grpc_gateway_support::GrpcGateway`'s subject) and `PolicyService` with a
/// network-egress policy that allows everything (`spec.network.allowlist:
/// ["*"]`) — needed because `ProxyGuard` always sets
/// `AA_PROXY_GATEWAY_ENDPOINT` (AAASM-5851: every managed launch's egress is
/// gateway-authoritative, not the local `AA_PROXY_NETWORK_ALLOWLIST`), so a
/// stub gateway that only implements registration would fail-closed-deny the
/// active-forwarding CONNECT this benchmark drives. Modeled on
/// `e2e_network_egress_gateway.rs::start_gateway` + this crate's own
/// `grpc_gateway_support::GrpcGateway`, combined onto one listener since both
/// `AA_GATEWAY_ENDPOINT` and `AA_PROXY_GATEWAY_ENDPOINT` name the same
/// address for a real launch.
async fn start_combined_gateway() -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let policy_tmp = tempfile::tempdir()?;
    let policy_path = policy_tmp.path().join("policy.yaml");
    std::fs::write(
        &policy_path,
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n\
         \x20 name: aaasm5868-bench-allow-all\n\
         \x20 version: \"0.1.0\"\n\
         spec:\n\
         \x20 network:\n\
         \x20   allowlist:\n\
         \x20     - \"*\"\n",
    )?;
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(
        PolicyEngine::load_from_file(&policy_path, alert_tx)
            .map_err(|e| anyhow::anyhow!("policy fixture must load cleanly: {e:?}"))?,
    );
    // Leaked deliberately: this benchmark process is short-lived and the
    // gateway must outlive every scenario, not just this function's scope —
    // matches `e2e_network_egress_gateway.rs::start_gateway`'s own reasoning.
    std::mem::forget(policy_tmp);

    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel::<aa_core::AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let policy_service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );
    let lifecycle_service = AgentLifecycleServiceImpl::new(Arc::clone(&registry));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = Server::builder()
            .add_service(AgentLifecycleServiceServer::new(lifecycle_service))
            .add_service(PolicyServiceServer::new(policy_service))
            .serve_with_incoming(incoming)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    Ok((addr, handle))
}

/// Launch counts the AAASM-5857 design calls for evidence at.
const CONCURRENCY_LEVELS: [usize; 4] = [1, 5, 10, 20];

/// Wall-clock window each idle-CPU sample brackets. macOS `ps -o time` is a
/// cumulative counter, not an instantaneous rate, so idle CPU is computed as
/// Δcputime / Δwall over this fixed window rather than read as a single
/// snapshot (a proxy that burned CPU at startup then went idle would
/// otherwise misreport as "still busy").
const IDLE_WINDOW: Duration = Duration::from_secs(3);

/// How long to wait for a launch's dedicated proxy to appear as a child
/// process and for its tool to start. Generous for a loaded dev machine
/// running several concurrent sessions (`cli_run_leak_freedom.rs` uses the
/// same 45s figure for the same reason) — widened once already while
/// chasing a scheduling-granularity issue unrelated to correctness.
const READY_PATIENCE: Duration = Duration::from_secs(45);

/// How long to wait for a dedicated proxy's pid to disappear after its
/// launcher is signalled to terminate.
const CLEANUP_PATIENCE: Duration = Duration::from_secs(15);

const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn main() -> anyhow::Result<()> {
    let target_dir = cargo_target_dir();
    eprintln!("[bench] using CARGO_TARGET_DIR = {}", target_dir.display());

    let aasm = release_binary(&target_dir, "AASM_BIN_PATH", "aasm")?;
    let proxy_bin_dir = build_and_stage_proxy(&target_dir)?;
    eprintln!("[bench] aasm = {}", aasm.display());
    eprintln!(
        "[bench] dedicated-proxy stand-in staged at {}/aa-proxy",
        proxy_bin_dir.display()
    );

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let (gateway_addr, _gateway_handle) = rt.block_on(start_combined_gateway())?;
    let gateway_endpoint = format!("http://{gateway_addr}");

    let ca_root = tempfile::tempdir()?;
    let ca_dir = ca_root.path().join("ca");
    std::fs::create_dir_all(&ca_dir)?;

    // Pre-warm: one throwaway launch mints the CA keypair on this shared
    // `ca_dir` before any concurrency scenario times its own launches — a
    // `ProxyGuardOptions::ca_dir` is required to be the same value across
    // every launch on a machine (`guard.rs` doc), and 20 cold launches
    // racing first-use CA minting on the same directory would measure that
    // race, not per-launch proxy overhead.
    eprintln!("[bench] pre-warming shared CA dir...");
    let prewarm = run_one_launch(&LaunchInput {
        idx: "prewarm".to_string(),
        aasm: aasm.clone(),
        proxy_bin_dir: proxy_bin_dir.clone(),
        ca_dir: ca_dir.clone(),
        gateway_endpoint: gateway_endpoint.clone(),
        drive_traffic: false,
    })?;
    eprintln!(
        "[bench] pre-warm launch complete (proxy pid {} was pid-gone: {})",
        prewarm.proxy_pid,
        prewarm.cleanup_latency_ms.is_some()
    );

    let mut scenarios = Vec::new();
    for &n in &CONCURRENCY_LEVELS {
        eprintln!("[bench] === concurrency level {n} ===");
        let scenario = run_scenario(n, &aasm, &proxy_bin_dir, &ca_dir, &gateway_endpoint)?;
        print_scenario(&scenario);
        scenarios.push(scenario);
    }

    let out_path = std::env::var("AA_BENCH_OUTPUT").unwrap_or_else(|_| "proxy_resource_overhead.json".to_string());
    let json = serde_json::to_string_pretty(&scenarios)?;
    std::fs::write(&out_path, &json)?;
    eprintln!("[bench] wrote {out_path}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Binary resolution / staging
// ---------------------------------------------------------------------------

fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("aa-integration-tests always has a workspace-root parent")
                .join("target")
        })
}

/// Resolve a **release** binary, refusing to silently fall back to a debug
/// build — a debug `aasm`/`aa-proxy` would make every RSS/CPU number in this
/// benchmark describe the wrong artefact.
fn release_binary(target_dir: &Path, env_var: &str, name: &str) -> anyhow::Result<PathBuf> {
    if let Some(explicit) = std::env::var_os(env_var) {
        return Ok(std::fs::canonicalize(&explicit)?);
    }
    let candidate = target_dir.join("release").join(name);
    anyhow::ensure!(
        candidate.is_file(),
        "no release `{name}` at {} — run `cargo build --release -p aa-cli -p aa-proxy` with the \
         same CARGO_TARGET_DIR first (see this file's module doc), or set {env_var}",
        candidate.display(),
    );
    Ok(std::fs::canonicalize(candidate)?)
}

/// Build `aa_proxy_no_keychain` (release) and copy it to a fresh temp
/// directory under the name `aa-proxy` — `ProxyGuard`/`aa-cli`'s binary
/// resolution looks for that literal name on `PATH`
/// (`aa-cli/src/commands/proxy/start.rs::resolve_binary`), the same trick
/// `proxy_trust_support::TrustedProxy::start_intercepting` already uses for
/// the standalone-proxy path.
fn build_and_stage_proxy(target_dir: &Path) -> anyhow::Result<PathBuf> {
    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--release",
            "--quiet",
            "-p",
            "aa-integration-tests",
            "--example",
            "aa_proxy_no_keychain",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("CARGO_TARGET_DIR", target_dir)
        .status()?;
    anyhow::ensure!(status.success(), "failed to build aa_proxy_no_keychain example");

    let built = target_dir.join("release/examples/aa_proxy_no_keychain");
    anyhow::ensure!(built.is_file(), "expected artefact at {}", built.display());

    let stage_root = tempfile::tempdir()?.keep();
    let bin_dir = stage_root.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let dest = bin_dir.join("aa-proxy");
    std::fs::copy(&built, &dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(bin_dir)
}

fn prefixed_path(dirs: &[PathBuf]) -> anyhow::Result<std::ffi::OsString> {
    let mut parts = dirs.to_vec();
    parts.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    Ok(std::env::join_paths(parts)?)
}

// ---------------------------------------------------------------------------
// Per-launch stub tool
// ---------------------------------------------------------------------------

/// Markers this stub writes for the harness to bracket the active-forwarding
/// CPU window around, and the go-file it blocks on before making its one
/// real request — so idle-CPU sampling (which must happen first) never races
/// the curl call.
struct StubPaths {
    bin: PathBuf,
    dump: PathBuf,
    go: PathBuf,
    curl_start: PathBuf,
    curl_done: PathBuf,
    curl_result: PathBuf,
}

fn write_stub(dir: &Path, ca_dir: &Path, drive_traffic: bool) -> anyhow::Result<StubPaths> {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = dir.join("bin");
    std::fs::create_dir_all(&bin_dir)?;
    let bin = bin_dir.join("claude");
    let dump = dir.join("child-env.txt");
    let go = dir.join("go");
    let curl_start = dir.join("curl_start");
    let curl_done = dir.join("curl_done");
    let curl_result = dir.join("curl_result.txt");

    // `--cacert` (not system trust): a gateway-managed launch forces
    // `AA_PROXY_LLM_ONLY=false` (`guard.rs::build_command`), so this proxy
    // MitMs this CONNECT the same as it would an LLM host in production —
    // the whole point of driving traffic through it. `curl` verifying that
    // MitM leaf against the launch's own CA (not the macOS System Keychain,
    // which this benchmark never touches — see `aa_proxy_no_keychain.rs`)
    // is what turns this into a genuine decrypt+relay round trip instead of
    // a TLS handshake that fails before the proxy does any real work.
    let ca_cert = ca_dir.join("ca-cert.pem");
    let traffic_block = if drive_traffic {
        format!(
            "while [ ! -f {go:?} ]; do sleep 0.05; done\n\
             touch {curl_start:?}\n\
             curl -sS -m 10 --cacert {ca_cert:?} -o /dev/null -w '%{{http_code}}' -x \"$HTTPS_PROXY\" \
               https://example.com > {curl_result:?} 2>&1\n\
             touch {curl_done:?}\n"
        )
    } else {
        String::new()
    };

    std::fs::write(
        &bin,
        format!(
            r#"#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "2.1.999 (Claude Code)"
  exit 0
fi
{{
  echo "AA_AGENT_ID=$AA_AGENT_ID"
  echo "HTTPS_PROXY=$HTTPS_PROXY"
}} > {dump:?}
{traffic_block}trap 'exit 0' TERM
while true; do sleep 0.2; done
"#
        ),
    )?;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;

    Ok(StubPaths {
        bin,
        dump,
        go,
        curl_start,
        curl_done,
        curl_result,
    })
}

fn write_test_policy(dir: &Path) -> std::io::Result<PathBuf> {
    let path = dir.join("policy.yaml");
    std::fs::write(
        &path,
        "apiVersion: agent-assembly/v1\n\
         kind: Policy\n\
         metadata:\n\
         \x20 name: aaasm5868-resource-overhead\n\
         spec:\n\
         \x20 tools:\n\
         \x20   read_file:\n\
         \x20     allow: true\n\
         \x20   shell:\n\
         \x20     allow: false\n",
    )?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Process introspection (macOS/BSD `ps`/`lsof` — this benchmark is
// dev-machine-only, see the verification report's environment section)
// ---------------------------------------------------------------------------

/// A direct child of `parent_pid` whose command line names `aa-proxy` — this
/// launch's own dedicated proxy. Mirrors
/// `cli_run_leak_freedom.rs::find_proxy_child_pid`; see that function's
/// comment for why `split_whitespace` (not a fixed-width split) is required.
fn find_proxy_child_pid(parent_pid: u32) -> Option<u32> {
    let out = Command::new("ps").args(["-eo", "pid,ppid,command"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let Some(pid) = cols.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Some(ppid) = cols.next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let command: String = cols.collect::<Vec<_>>().join(" ");
        if ppid == parent_pid && command.contains("aa-proxy") {
            return Some(pid);
        }
    }
    None
}

fn pid_is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 sends nothing; it only probes existence/permission.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn wait_for_pid_alive(parent_pid: u32, patience: Duration) -> Option<u32> {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if let Some(pid) = find_proxy_child_pid(parent_pid) {
            return Some(pid);
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    None
}

fn wait_for_pid_gone(pid: u32, patience: Duration) -> bool {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if !pid_is_alive(pid) {
            return true;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    !pid_is_alive(pid)
}

fn wait_for_file(path: &Path, patience: Duration) -> Option<()> {
    let deadline = Instant::now() + patience;
    while Instant::now() < deadline {
        if path.exists() {
            return Some(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    None
}

/// RSS in KiB, from `ps -o rss=` (already KiB on macOS/BSD, matching Linux).
fn rss_kb(pid: u32) -> Option<u64> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Cumulative CPU time in seconds, from `ps -o time=` (`[[dd-]hh:]mm:ss.ss`).
/// A cumulative counter, not an instantaneous rate — callers bracket two
/// samples around a wall-clock window and divide, see `IDLE_WINDOW`'s doc.
fn cputime_seconds(pid: u32) -> Option<f64> {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    parse_ps_time(&raw)
}

fn parse_ps_time(raw: &str) -> Option<f64> {
    let (days, rest) = match raw.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().ok()?, r),
        None => (0.0, raw),
    };
    let parts: Vec<&str> = rest.split(':').collect();
    let mut seconds = 0.0f64;
    for p in &parts {
        seconds = seconds * 60.0 + p.parse::<f64>().ok()?;
    }
    Some(days * 86_400.0 + seconds)
}

/// Open file descriptor count for `pid`, via `lsof -a -p <pid> -n -P`
/// (`-n -P`: skip hostname/service-name resolution, much faster on a loaded
/// box). Subtracts the header line.
fn fd_count(pid: u32) -> Option<usize> {
    let out = Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-n", "-P"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let lines = text.lines().count();
    Some(lines.saturating_sub(1))
}

// ---------------------------------------------------------------------------
// One launch
// ---------------------------------------------------------------------------

/// Owned (not borrowed) so a concurrency scenario's per-launch
/// `std::thread::spawn` closures can move one in without needing a leaked
/// `'static` reference — every field here is already an independent owned
/// copy by the time a launch thread is spawned.
struct LaunchInput {
    idx: String,
    aasm: PathBuf,
    proxy_bin_dir: PathBuf,
    ca_dir: PathBuf,
    gateway_endpoint: String,
    drive_traffic: bool,
}

#[derive(serde::Serialize, Clone)]
struct LaunchResult {
    id: String,
    aasm_pid: u32,
    proxy_pid: u32,
    /// Wall time from spawning `aasm run` to the launched tool actually
    /// starting (its env dump appearing) — the closest externally-observable
    /// bound on readiness: `ProxyGuard::spawn` blocks the whole launch until
    /// the dedicated proxy reports ready, and the tool is spawned
    /// immediately after, so this interval is readiness latency plus a small,
    /// consistent tool-exec overhead, not readiness latency alone.
    startup_latency_ms: f64,
    proxy_rss_kb: Option<u64>,
    proxy_fd_count: Option<usize>,
    idle_cpu_pct: Option<f64>,
    active_cpu_pct: Option<f64>,
    curl_http_code: Option<String>,
    cleanup_latency_ms: Option<f64>,
    proxy_leaked: bool,
}

fn run_one_launch(input: &LaunchInput) -> anyhow::Result<LaunchResult> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let home = root.join("home");
    let project = root.join("project");
    std::fs::create_dir_all(home.join(".claude"))?;
    std::fs::create_dir_all(&project)?;
    let policy = write_test_policy(root)?;
    let stub = write_stub(root, &input.ca_dir, input.drive_traffic)?;

    let agent_id = format!("aaasm5868-bench-{}", input.idx);
    let path_var = prefixed_path(&[
        stub.bin.parent().expect("stub has a parent").to_path_buf(),
        input.proxy_bin_dir.clone(),
    ])?;

    let mut cmd = Command::new(&input.aasm);
    cmd.current_dir(&project)
        .env("HOME", &home)
        .env("PATH", &path_var)
        .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
        .env("AASM_STATE_DIR", root.join("state"))
        .env("AA_CA_DIR", &input.ca_dir)
        .env("AASM_CLAUDE_MANAGED_ROOT", root.join("managed"))
        .env("AA_TEST_ENV_DUMP", &stub.dump)
        .env("AA_GATEWAY_ENDPOINT", &input.gateway_endpoint)
        .args([
            "run",
            "claude",
            "--policy",
            policy.to_str().expect("temp path is utf-8"),
            "--agent-id",
            &agent_id,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let t0 = Instant::now();
    let mut child: Child = cmd.spawn()?;
    let aasm_pid = child.id();

    let proxy_pid = match wait_for_pid_alive(aasm_pid, READY_PATIENCE) {
        Some(pid) => pid,
        None => {
            // Diagnostic-only path: give `aasm run` a moment to fail closed
            // and exit on its own (a refusal, e.g. an unreachable gateway,
            // exits fast) so its stdout/stderr is captured instead of lost
            // to a hard `kill()`.
            let _ = wait_child(&mut child, Duration::from_secs(2));
            let _ = child.kill();
            let output = child.wait_with_output();
            let (out, err) = match output {
                Ok(o) => (
                    String::from_utf8_lossy(&o.stdout).into_owned(),
                    String::from_utf8_lossy(&o.stderr).into_owned(),
                ),
                Err(_) => (String::new(), String::new()),
            };
            anyhow::bail!(
                "launch {}: dedicated proxy never appeared as a child of pid {aasm_pid}\nstdout:\n{out}\nstderr:\n{err}",
                input.idx
            );
        }
    };

    if wait_for_file(&stub.dump, READY_PATIENCE).is_none() {
        anyhow::bail!("launch {}: tool never started (no env dump written)", input.idx);
    }
    let startup_latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let proxy_rss_kb = rss_kb(proxy_pid);
    let proxy_fd_count = fd_count(proxy_pid);

    // Idle CPU: bracketed before any traffic is triggered.
    let idle_cpu_pct = cputime_seconds(proxy_pid).and_then(|c0| {
        std::thread::sleep(IDLE_WINDOW);
        cputime_seconds(proxy_pid).map(|c1| ((c1 - c0) / IDLE_WINDOW.as_secs_f64()) * 100.0)
    });

    let (active_cpu_pct, curl_http_code) = if input.drive_traffic {
        std::fs::write(&stub.go, b"go")?;
        if wait_for_file(&stub.curl_start, Duration::from_secs(15)).is_some() {
            let ca = cputime_seconds(proxy_pid);
            let ta = Instant::now();
            if wait_for_file(&stub.curl_done, Duration::from_secs(15)).is_some() {
                let cb = cputime_seconds(proxy_pid);
                let dt = ta.elapsed().as_secs_f64().max(0.05);
                let pct = ca.zip(cb).map(|(a, b)| ((b - a) / dt) * 100.0);
                (pct, std::fs::read_to_string(&stub.curl_result).ok())
            } else {
                (None, None)
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let cleanup_t0 = Instant::now();
    // SAFETY: `aasm_pid` is this launch's own freshly spawned child.
    unsafe {
        libc::kill(aasm_pid as libc::pid_t, libc::SIGTERM);
    }
    let _ = wait_child(&mut child, Duration::from_secs(15));
    let proxy_gone = wait_for_pid_gone(proxy_pid, CLEANUP_PATIENCE);
    let cleanup_latency_ms = if proxy_gone {
        Some(cleanup_t0.elapsed().as_secs_f64() * 1000.0)
    } else {
        None
    };

    drop(tmp);

    Ok(LaunchResult {
        id: input.idx.clone(),
        aasm_pid,
        proxy_pid,
        startup_latency_ms,
        proxy_rss_kb,
        proxy_fd_count,
        idle_cpu_pct,
        active_cpu_pct,
        curl_http_code,
        cleanup_latency_ms,
        proxy_leaked: !proxy_gone,
    })
}

fn wait_child(child: &mut Child, patience: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + patience;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            anyhow::bail!("child did not exit within {patience:?} of SIGTERM");
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

// ---------------------------------------------------------------------------
// One concurrency scenario
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, Clone)]
struct Scenario {
    concurrency: usize,
    launches: Vec<LaunchResult>,
    /// Any `aa-proxy`-named process still under this benchmark's own staged
    /// bin dir after every launch in this scenario has terminated. Scoped by
    /// the staged `proxy_bin_dir` path (unique per benchmark run, embedded in
    /// the copied binary's own argv[0]) rather than by name alone, for the
    /// same reason `cli_run_leak_freedom.rs::all_aa_proxy_pids` scopes by
    /// `cargo_target_dir()` — this dev machine runs other concurrent
    /// sessions with their own `aa-proxy` processes.
    leaked_after_scenario: Vec<u32>,
}

fn run_scenario(
    n: usize,
    aasm: &Path,
    proxy_bin_dir: &Path,
    ca_dir: &Path,
    gateway_endpoint: &str,
) -> anyhow::Result<Scenario> {
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let input = LaunchInput {
                idx: format!("n{n}-{i}"),
                aasm: aasm.to_path_buf(),
                proxy_bin_dir: proxy_bin_dir.to_path_buf(),
                ca_dir: ca_dir.to_path_buf(),
                gateway_endpoint: gateway_endpoint.to_string(),
                drive_traffic: true,
            };
            std::thread::spawn(move || run_one_launch(&input))
        })
        .collect();

    let mut launches = Vec::with_capacity(n);
    for h in handles {
        match h.join() {
            Ok(Ok(r)) => launches.push(r),
            Ok(Err(e)) => eprintln!("[bench] launch failed: {e:#}"),
            Err(_) => eprintln!("[bench] launch thread panicked"),
        }
    }

    // Settle window before the leak scan — mirrors
    // `cli_run_leak_freedom.rs::proxy_start_failure_spawns_nothing_to_leak`'s
    // reasoning: even a clean teardown takes a moment for `ps` to reflect it.
    std::thread::sleep(Duration::from_millis(300));
    let marker = proxy_bin_dir.to_string_lossy().into_owned();
    let leaked_after_scenario = scan_for_marker(&marker);

    Ok(Scenario {
        concurrency: n,
        launches,
        leaked_after_scenario,
    })
}

fn scan_for_marker(marker: &str) -> Vec<u32> {
    let Ok(out) = Command::new("ps").args(["-eo", "pid,command"]).output() else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .skip(1)
        .filter(|l| l.contains(marker))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect()
}

fn print_scenario(s: &Scenario) {
    let ok: Vec<&LaunchResult> = s.launches.iter().collect();
    let n = ok.len().max(1) as f64;
    let rss: Vec<u64> = ok.iter().filter_map(|l| l.proxy_rss_kb).collect();
    let mean_rss = rss.iter().sum::<u64>() as f64 / rss.len().max(1) as f64;
    let max_rss = rss.iter().copied().max().unwrap_or(0);
    let sum_rss: u64 = rss.iter().sum();
    let mean_startup = ok.iter().map(|l| l.startup_latency_ms).sum::<f64>() / n;
    let cleanup: Vec<f64> = ok.iter().filter_map(|l| l.cleanup_latency_ms).collect();
    let mean_cleanup = cleanup.iter().sum::<f64>() / cleanup.len().max(1) as f64;
    let leaked_count = ok.iter().filter(|l| l.proxy_leaked).count();

    let concurrency = s.concurrency;
    let launches_ok = ok.len();
    let leaked_by_scan = s.leaked_after_scenario.len();
    println!(
        "concurrency={concurrency:<3} launches_ok={launches_ok:<3} mean_rss_kb={mean_rss:.0} \
         max_rss_kb={max_rss} sum_rss_kb={sum_rss} mean_startup_ms={mean_startup:.0} \
         mean_cleanup_ms={mean_cleanup:.0} leaked_by_pid={leaked_count} leaked_by_scan={leaked_by_scan}",
    );
}
