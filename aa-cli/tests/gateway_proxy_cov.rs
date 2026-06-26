//! Integration tests for `aasm gateway` and `aasm proxy` lifecycle dispatch
//! paths (AAASM-3804).
//!
//! These exercise the `status` / `stop` / `logs` / CA dispatch arms that the
//! existing inline unit tests don't reach. The PID-file location is isolated
//! per test via `AA_DATA_DIR` (honoured by `gateway::pid` / `proxy::pid`).
//! `AA_DATA_DIR` is process-global, so a module-wide mutex serialises every
//! test that mutates it — deterministic under both `cargo test` (threaded,
//! single process) and `cargo nextest` (process-per-test).
//!
//! Process-spawning paths (`start`), the blocking `follow` tail loops, and the
//! real keychain/trust-store mutation in `proxy install-ca --yes` are out of
//! scope: they require a live daemon or would mutate the host system.

use std::io::Write;
use std::process::ExitCode;
use std::sync::{Mutex, MutexGuard};

use aa_cli::commands::gateway;
use aa_cli::commands::proxy;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard that points `AA_DATA_DIR` at an isolated tempdir for the lifetime
/// of the guard, restoring the prior value (or unsetting) on drop.
struct DataDir {
    _lock: MutexGuard<'static, ()>,
    _tmp: tempfile::TempDir,
    prior: Option<String>,
}

impl DataDir {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let prior = std::env::var("AA_DATA_DIR").ok();
        std::env::set_var("AA_DATA_DIR", tmp.path());
        Self {
            _lock: lock,
            _tmp: tmp,
            prior,
        }
    }
}

impl Drop for DataDir {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var("AA_DATA_DIR", v),
            None => std::env::remove_var("AA_DATA_DIR"),
        }
    }
}

/// Spawn a trivial child, reap it, and return its now-dead PID. Safe to write
/// into a PID file so the "stale process" branch fires without targeting a real
/// live process.
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn 'true'");
    let pid = child.id();
    child.wait().expect("wait");
    pid
}

// ── gateway status ────────────────────────────────────────────────────

#[test]
fn gateway_status_not_running_exits_one() {
    let _dd = DataDir::new();
    // No PID file in the isolated dir → gateway reported not running.
    for json in [false, true] {
        let code = gateway::status::dispatch(gateway::status::StatusArgs { json });
        assert_eq!(code, ExitCode::from(1u8));
    }
}

#[test]
fn gateway_status_stale_pid_exits_one() {
    let _dd = DataDir::new();
    gateway::pid::write_pid(dead_pid(), "127.0.0.1:50051", "2026-05-18T00:00:00Z").unwrap();
    // The PID exists in the file but the process is dead → not running → exit 1.
    let code = gateway::status::dispatch(gateway::status::StatusArgs { json: false });
    assert_eq!(code, ExitCode::from(1u8));
}

// ── gateway logs ──────────────────────────────────────────────────────

#[test]
fn gateway_logs_missing_file_is_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("nope.log");
    let code = gateway::logs::dispatch(gateway::logs::LogsArgs {
        follow: false,
        lines: 50,
        level: None,
        log_file: Some(missing),
    });
    assert_eq!(code, ExitCode::FAILURE);
}

#[test]
fn gateway_logs_tail_existing_file_is_success() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    for i in 0..20 {
        writeln!(f, "{{\"level\":\"INFO\",\"fields\":{{\"message\":\"line {i}\"}}}}").unwrap();
    }
    writeln!(f, "{{\"level\":\"ERROR\",\"fields\":{{\"message\":\"boom\"}}}}").unwrap();
    let code = gateway::logs::dispatch(gateway::logs::LogsArgs {
        follow: false,
        lines: 5,
        level: None,
        log_file: Some(f.path().to_path_buf()),
    });
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn gateway_logs_tail_with_level_filter_is_success() {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "{{\"level\":\"INFO\",\"fields\":{{\"message\":\"ok\"}}}}").unwrap();
    writeln!(f, "{{\"level\":\"ERROR\",\"fields\":{{\"message\":\"bad\"}}}}").unwrap();
    let code = gateway::logs::dispatch(gateway::logs::LogsArgs {
        follow: false,
        lines: 50,
        level: Some(gateway::logs::LogLevel::Error),
        log_file: Some(f.path().to_path_buf()),
    });
    assert_eq!(code, ExitCode::SUCCESS);
}

// ── proxy status ──────────────────────────────────────────────────────

#[test]
fn proxy_status_not_running_is_success() {
    let _dd = DataDir::new();
    for json in [false, true] {
        let code = proxy::status::dispatch(proxy::status::StatusArgs { json });
        assert_eq!(code, ExitCode::SUCCESS);
    }
}

#[test]
fn proxy_status_stale_pid_cleans_up_and_succeeds() {
    let _dd = DataDir::new();
    // proxy::pid::write_pid writes the *current* process id, which is alive, so
    // craft a stale PID file directly via the gateway-independent path helper.
    let pid = dead_pid();
    std::fs::write(proxy::pid::pid_path(), format!("{pid}\n127.0.0.1:8899\n")).unwrap();
    for json in [false, true] {
        let pid2 = dead_pid();
        std::fs::write(proxy::pid::pid_path(), format!("{pid2}\n127.0.0.1:8899\n")).unwrap();
        let code = proxy::status::dispatch(proxy::status::StatusArgs { json });
        assert_eq!(code, ExitCode::SUCCESS);
        // The stale PID file is cleaned up by the dispatch.
        assert!(proxy::pid::read_pid().is_none());
    }
}

#[test]
fn gateway_status_running_and_serving_succeeds() {
    let _dd = DataDir::new();
    // Bind a real listener so the TCP health probe sees an open port, and use
    // our own (alive) PID so the liveness check passes → "running" branch.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    gateway::pid::write_pid(std::process::id(), &addr, "2026-01-01T00:00:00Z").unwrap();
    let code = gateway::status::dispatch(gateway::status::StatusArgs { json: false });
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn proxy_status_running_and_serving_succeeds() {
    let _dd = DataDir::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    // proxy::pid::write_pid records the current (alive) process id.
    std::fs::write(proxy::pid::pid_path(), format!("{}\n{}\n", std::process::id(), addr)).unwrap();
    let code = proxy::status::dispatch(proxy::status::StatusArgs { json: true });
    assert_eq!(code, ExitCode::SUCCESS);
}

// ── proxy stop ────────────────────────────────────────────────────────

#[test]
fn proxy_stop_no_pid_file_is_success() {
    let _dd = DataDir::new();
    assert_eq!(proxy::stop::dispatch(), ExitCode::SUCCESS);
}

// ── proxy CA (abort path) ─────────────────────────────────────────────
//
// With `--yes` unset and no interactive `y` on stdin, `confirm()` reads EOF and
// returns false, so both commands abort cleanly with SUCCESS without touching
// the system trust store. `ca_dir` is pointed at a tempdir so the default
// `~/.aa/ca` resolution is bypassed.

#[test]
fn proxy_install_ca_aborts_without_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let code = proxy::ca::install(proxy::ca::CaArgs {
        ca_dir: Some(tmp.path().to_path_buf()),
        yes: false,
    });
    assert_eq!(code, ExitCode::SUCCESS);
}

#[test]
fn proxy_uninstall_ca_aborts_without_confirmation() {
    let tmp = tempfile::tempdir().unwrap();
    let code = proxy::ca::uninstall(proxy::ca::CaArgs {
        ca_dir: Some(tmp.path().to_path_buf()),
        yes: false,
    });
    assert_eq!(code, ExitCode::SUCCESS);
}
