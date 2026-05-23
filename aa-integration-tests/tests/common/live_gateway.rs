//! Out-of-process gateway fixture for the e2e_sdk_node tests
//! (AAASM-1602).
//!
//! Each `real_*` test in `e2e_sdk_node.rs` invokes the TypeScript
//! fixture under `tests/fixtures/agents/typescript/` against a real
//! gRPC `aa-gateway` listener — so the test needs an *out-of-process*
//! gateway, distinct from the in-process Axum harness in
//! `TopologyTestEnv`. `LiveGateway::spawn` does exactly that: picks a
//! free TCP port, launches the workspace's `aa-gateway` binary, and
//! waits for the listener to accept connections.
//!
//! Isolation: `HOME` is pinned to a per-test temp directory so the
//! spawned gateway's SQLite-backed `local.storage_path`, default
//! `~/.aa/audit` directory, and budget JSON all land outside the
//! engineer's real `~/.aasm` / `~/.aa` dirs. The public surface is
//! one-shot — there is no SIGTERM/respawn cycle, just `spawn` →
//! `Drop`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// Handle to a spawned `aa-gateway` subprocess.
///
/// On drop the child is killed (and reaped) so a panicking test never
/// leaves a stray gateway listening on the chosen port. `spawn`
/// returns once the gRPC listener is accepting TCP connections.
pub struct LiveGateway {
    child: Option<Child>,
    addr: String,
    _home_tmp: tempfile::TempDir,
    _policy_tmp: tempfile::TempDir,
}

impl LiveGateway {
    /// Spawn `aa-gateway` on a free port with isolated `HOME` and audit
    /// dir. Returns a handle whose `addr()` is the live gRPC endpoint
    /// (`"127.0.0.1:<port>"`). Waits up to 30 s for the listener to
    /// accept TCP connections.
    pub fn spawn() -> Result<Self> {
        let bin = locate_gateway_binary().context("locating aa-gateway binary for LiveGateway::spawn")?;
        let home_tmp = tempfile::tempdir().context("creating HOME tempdir")?;
        let policy_tmp = tempfile::tempdir().context("creating policy tempdir")?;
        let policy_path = policy_tmp.path().join("policy.yaml");
        std::fs::write(
            &policy_path,
            "apiVersion: agent-assembly.dev/v1alpha1\nkind: GovernancePolicy\nspec:\n  rules: []\n",
        )
        .context("writing minimal policy YAML")?;

        let port = free_port().context("picking a free TCP port")?;
        let addr = format!("127.0.0.1:{port}");

        // HOME isolation is enough: `dirs::data_dir()` and the SQLite
        // backend both resolve relative to `$HOME` on Linux + macOS, so
        // the spawned gateway's audit JSONL, budget cache, and local
        // `.aasm` DB land entirely inside the temp dir.
        let child = Command::new(&bin)
            .arg("--policy")
            .arg(&policy_path)
            .arg("--listen")
            .arg(&addr)
            .env("HOME", home_tmp.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawning {} failed", bin.display()))?;

        let gw = Self {
            child: Some(child),
            addr: addr.clone(),
            _home_tmp: home_tmp,
            _policy_tmp: policy_tmp,
        };
        gw.await_ready(Duration::from_secs(30))?;
        Ok(gw)
    }

    /// The address the spawned gateway is listening on
    /// (`"127.0.0.1:<port>"`). Pass directly to TS fixtures via the
    /// `AA_GATEWAY_ADDR` env var.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    fn await_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let socket_addr: std::net::SocketAddr = self.addr.parse().context("parsing listen addr")?;
        loop {
            if std::net::TcpStream::connect_timeout(&socket_addr, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(anyhow!(
                    "aa-gateway at {} did not start accepting connections within {timeout:?}",
                    self.addr,
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for LiveGateway {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// `true` when the `aa-gateway` binary is locatable on disk — used by
/// the e2e_sdk_node tests to skip cleanly when the workspace hasn't
/// been built (e.g. running a single test crate without a prior
/// `cargo build -p aa-gateway`).
pub fn gateway_binary_locatable() -> bool {
    locate_gateway_binary().is_ok()
}

fn locate_gateway_binary() -> Result<PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    let workspace_root = Path::new(&manifest).parent().context("manifest has no parent")?;
    for profile in ["debug", "release"] {
        let candidate = workspace_root.join("target").join(profile).join("aa-gateway");
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
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

fn free_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind 127.0.0.1:0")?;
    let port = listener.local_addr().context("local_addr")?.port();
    Ok(port)
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
