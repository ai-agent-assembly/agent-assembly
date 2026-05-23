//! Out-of-process gateway fixture for tests that need a real
//! `aa-gateway` binary (e.g. AAASM-1601's
//! `audit_chain_survives_gateway_restart`).
//!
//! Unlike `TopologyTestEnv` (which boots an in-process Axum router for
//! the HTTP plane), `BinaryGateway` spawns the actual `aa-gateway` Rust
//! binary so we can exercise process-boundary behaviours: hash-chain
//! resumption via `AuditWriter::read_last_hash`, SIGTERM graceful
//! drain, restart durability.
//!
//! Isolation is achieved via two environment hooks:
//!
//! 1. `HOME` is pointed at a per-test temp directory so the gateway's
//!    SQLite-backed `local.storage_path` and `budget.json` land
//!    outside the engineer's real `~/.aasm` / `~/.aa` dirs.
//! 2. `AA_AUDIT_DIR` (or the equivalent `--audit-dir` CLI flag, also
//!    introduced under AAASM-1601) redirects the audit JSONL to a
//!    per-test directory so multiple tests don't clobber each other.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// Handle to a spawned `aa-gateway` subprocess.
///
/// The `Drop` impl unconditionally kills the child if it is still alive,
/// so test panics never leave dangling gateways. For clean shutdown
/// (e.g. between spawn / respawn cycles), call
/// [`Self::sigterm_and_wait`] explicitly.
pub struct BinaryGateway {
    child: Option<Child>,
    listen_addr: String,
    audit_dir: PathBuf,
    home_dir: PathBuf,
    policy_path: PathBuf,
}

impl BinaryGateway {
    /// Spawn `aa-gateway --policy ... --listen ... --audit-dir ...`
    /// with `HOME` and `AA_AUDIT_DIR` pointed at the supplied per-test
    /// temp directories, then wait until the gRPC listener accepts a
    /// TCP connection (≤ 30 s).
    pub fn spawn(audit_dir: PathBuf, home_dir: PathBuf, policy_path: PathBuf, listen_addr: String) -> Result<Self> {
        let bin = locate_gateway_binary().context("locating aa-gateway binary for BinaryGateway::spawn")?;
        let child = Command::new(&bin)
            .arg("--policy")
            .arg(&policy_path)
            .arg("--listen")
            .arg(&listen_addr)
            .arg("--audit-dir")
            .arg(&audit_dir)
            .env("HOME", &home_dir)
            .env("AA_AUDIT_DIR", &audit_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {} failed", bin.display()))?;
        let gw = Self {
            child: Some(child),
            listen_addr,
            audit_dir,
            home_dir,
            policy_path,
        };
        gw.await_ready(Duration::from_secs(30))?;
        Ok(gw)
    }

    /// Return the TCP listen address (`"127.0.0.1:<port>"`).
    pub fn listen_addr(&self) -> &str {
        &self.listen_addr
    }

    /// Return the configured audit directory.
    pub fn audit_dir(&self) -> &Path {
        &self.audit_dir
    }

    /// Process ID of the live child, if any.
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Send `SIGTERM` to the child and wait for graceful exit (≤ `timeout`).
    ///
    /// Hard-kills the child via `Child::kill()` if it has not exited
    /// within the timeout — prevents the test from hanging when the
    /// gateway gets stuck in a shutdown handler. Returns an error in
    /// the hard-kill case so the test can decide whether to fail.
    ///
    /// On non-Unix platforms (effectively only Windows) falls back to
    /// the std `Child::kill()` non-graceful path; the audit-chain
    /// scenario this fixture exists for runs on Linux + macOS only.
    pub fn sigterm_and_wait(&mut self, timeout: Duration) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        #[cfg(unix)]
        {
            let pid = child.id();
            // SAFETY: `pid` is a valid PID we own — std::process::Child guarantees
            // it has not been reaped yet (Self::take() is exclusive).
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }
        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait()? {
                Some(_status) => return Ok(()),
                None => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(anyhow!(
                            "aa-gateway did not exit within {timeout:?} of SIGTERM; SIGKILL'd as a safety net",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    fn await_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if std::net::TcpStream::connect_timeout(
                &self.listen_addr.parse().context("parsing listen addr")?,
                Duration::from_millis(200),
            )
            .is_ok()
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(anyhow!(
                    "aa-gateway at {} did not start accepting connections within {timeout:?}",
                    self.listen_addr,
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for BinaryGateway {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Try a graceful kill (SIGKILL via std), then reap — never
            // panic in Drop so test failures still produce a clean
            // teardown.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Locate the `aa-gateway` binary on disk.
///
/// Looks in this order: `target/debug/aa-gateway`, `target/release/aa-gateway`
/// (resolved relative to the current `CARGO_MANIFEST_DIR`'s workspace root),
/// `$PATH`, `$HOME/.cargo/bin/aa-gateway`. Returns an error when nothing is
/// found so the test can either skip or trigger a `cargo build -p aa-gateway`.
fn locate_gateway_binary() -> Result<PathBuf> {
    // Workspace target dir first — this is what `cargo nextest run --workspace`
    // produces and matches the CI Integration tests job's layout.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let workspace_root = Path::new(&manifest).parent().context("manifest has no parent")?;
    for profile in ["debug", "release"] {
        let candidate = workspace_root.join("target").join(profile).join("aa-gateway");
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    // `$PATH` fallback (used by engineers who `cargo install`-ed the binary).
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join("aa-gateway");
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = PathBuf::from(home).join(".cargo").join("bin").join("aa-gateway");
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(anyhow!(
        "aa-gateway binary not found — run `cargo build -p aa-gateway` first or include it in CI's build step"
    ))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata().is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.exists()
}
