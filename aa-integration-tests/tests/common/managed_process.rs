//! Real OS-process launcher with explicit readiness gates (AAASM-5902).
//!
//! Distinct from `binary_gateway.rs`'s `BinaryGateway` (which this module does
//! not replace — see that file for the narrower, single-purpose fixture it
//! remains): `ManagedProcess` is the general-purpose primitive other harness
//! pieces (e.g. `api_server.rs`) build on. Three differences matter:
//!
//! 1. **Multiple, composable readiness conditions** ([`Readiness`]), not just a
//!    TCP-connect poll — including a log-line condition, which is what lets a
//!    caller distinguish a process that came up healthy from one that came up
//!    *degraded* but still passes a bare TCP/HTTP check (see `api_server.rs`'s
//!    module docs for why that distinction is load-bearing).
//! 2. **Captured stdout/stderr**, piped and tee'd to files under `log_dir`
//!    rather than `Stdio::null()`. Readiness detection, cross-process
//!    correlation, and log-content assertions all need the real captured
//!    output; discarding it (as `binary_gateway.rs` does) would make all three
//!    impossible.
//! 3. **Leak-free teardown assertions** (`assert_no_leaks`) — not just "the
//!    child is dead" but "the PID was actually reaped, and every port this
//!    process owned is provably free again".

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};

/// A condition [`ManagedProcess::spawn`] blocks on before returning.
pub enum Readiness {
    /// A TCP connect to this address succeeds.
    TcpConnect(SocketAddr),
    /// A GET to this URL returns a 2xx status.
    HttpOk(String),
    /// This substring appears somewhere in the captured stdout+stderr so far.
    LogLine(&'static str),
}

/// Everything needed to launch and supervise a real OS process.
pub struct ProcessSpec {
    /// Human-readable name for error messages and log file naming.
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
    /// Every condition that must hold before `spawn` returns.
    pub ready: Vec<Readiness>,
    pub ready_timeout: Duration,
    /// Directory captured stdout/stderr are tee'd into.
    pub log_dir: PathBuf,
    /// Ports this process is expected to own, for `assert_no_leaks` to verify
    /// are re-bindable after `stop`.
    pub owned_ports: Vec<u16>,
}

/// A supervised, real OS child process.
pub struct ManagedProcess {
    name: String,
    child: Option<Child>,
    pid: u32,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    captured: Arc<Mutex<CapturedOutput>>,
    owned_ports: Vec<u16>,
}

// Manual impl: `std::process::Child` does not implement `Debug`, so `#[derive(Debug)]`
// is not available here. Tests assert on `Result::unwrap_err().to_string()`, which
// requires `Debug` on the Ok side even though only the error path is formatted.
impl std::fmt::Debug for ManagedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedProcess")
            .field("name", &self.name)
            .field("pid", &self.pid)
            .field("owned_ports", &self.owned_ports)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct CapturedOutput {
    combined: String,
}

impl ManagedProcess {
    /// Spawn `spec.program`, tee its stdout/stderr to `spec.log_dir`, and block
    /// until every `spec.ready` condition holds or `spec.ready_timeout` elapses.
    ///
    /// On a readiness timeout the child is killed and reaped before returning
    /// the error — never leaves a half-ready process behind for the caller to
    /// forget about, and never returns a handle to something that isn't ready.
    pub fn spawn(spec: ProcessSpec) -> Result<Self> {
        std::fs::create_dir_all(&spec.log_dir)
            .with_context(|| format!("creating log_dir {} for {}", spec.log_dir.display(), spec.name))?;
        let stdout_path = spec.log_dir.join(format!("{}.stdout.log", spec.name));
        let stderr_path = spec.log_dir.join(format!("{}.stderr.log", spec.name));

        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in &spec.env {
            cmd.env(k, v);
        }
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawning {} ({})", spec.name, spec.program.display()))?;
        let pid = child.id();

        let captured = Arc::new(Mutex::new(CapturedOutput::default()));
        spawn_tee(child.stdout.take(), stdout_path.clone(), Arc::clone(&captured));
        spawn_tee(child.stderr.take(), stderr_path.clone(), Arc::clone(&captured));

        let mut proc = Self {
            name: spec.name.clone(),
            child: Some(child),
            pid,
            stdout_path,
            stderr_path,
            captured,
            owned_ports: spec.owned_ports.clone(),
        };

        if let Err(e) = proc.await_ready(&spec.ready, spec.ready_timeout) {
            // Readiness failed — never hand back a not-ready handle. Best-effort
            // kill+reap, then surface the readiness error (not a kill error).
            let _ = proc.stop(Duration::from_secs(5));
            return Err(e);
        }

        Ok(proc)
    }

    fn await_ready(&mut self, ready: &[Readiness], timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        for condition in ready {
            loop {
                if self.check_ready(condition) {
                    break;
                }
                if let Some(status) = self.child.as_mut().and_then(|c| c.try_wait().ok().flatten()) {
                    return Err(anyhow!(
                        "{} exited with {status} before readiness condition was met — captured \
                         output:\n{}",
                        self.name,
                        self.combined_output(),
                    ));
                }
                if Instant::now() > deadline {
                    return Err(anyhow!(
                        "{} did not become ready within {timeout:?} — captured output:\n{}",
                        self.name,
                        self.combined_output(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }

    fn check_ready(&self, condition: &Readiness) -> bool {
        match condition {
            Readiness::TcpConnect(addr) => {
                std::net::TcpStream::connect_timeout(addr, Duration::from_millis(200)).is_ok()
            }
            Readiness::HttpOk(url) => http_get_is_2xx(url),
            Readiness::LogLine(needle) => self.combined_output().contains(needle),
        }
    }

    fn combined_output(&self) -> String {
        self.captured.lock().expect("captured-output mutex").combined.clone()
    }

    /// OS process id.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Path to the file captured stdout is tee'd into.
    pub fn stdout(&self) -> &Path {
        &self.stdout_path
    }

    /// Path to the file captured stderr is tee'd into.
    pub fn stderr(&self) -> &Path {
        &self.stderr_path
    }

    /// Everything captured on stdout+stderr so far, interleaved in arrival
    /// order.
    pub fn captured_output(&self) -> String {
        self.combined_output()
    }

    /// SIGTERM, wait up to `timeout`, SIGKILL as a safety net.
    ///
    /// Returns an error (but still reaps the process) if the SIGKILL safety net
    /// had to fire — a caller that wants to assert clean shutdown can propagate
    /// that; a caller that just wants teardown can ignore it.
    pub fn stop(&mut self, timeout: Duration) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };

        #[cfg(unix)]
        {
            // SAFETY: `self.pid` is a PID we own; `child` has not been reaped
            // yet (`self.child.take()` above is exclusive).
            unsafe {
                libc::kill(self.pid as libc::pid_t, libc::SIGTERM);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let deadline = Instant::now() + timeout;
        loop {
            match child.try_wait()? {
                Some(_status) => {
                    return Ok(());
                }
                None => {
                    if Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(anyhow!(
                            "{} did not exit within {timeout:?} of SIGTERM; SIGKILL'd as a safety net",
                            self.name,
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }

    /// Assert the process left no trace: the PID is reaped (no zombie, no
    /// still-alive process) and every `owned_ports` port can be bound again.
    ///
    /// Call after [`Self::stop`]. Panics with a specific reason on failure
    /// rather than returning a `Result`, so a caller can use it as a plain
    /// assertion at the end of a test.
    pub fn assert_no_leaks(&self) {
        assert!(
            self.child.is_none(),
            "{}: stop() was not called before assert_no_leaks",
            self.name
        );
        #[cfg(unix)]
        {
            let alive = unsafe { libc::kill(self.pid as libc::pid_t, 0) } == 0;
            assert!(!alive, "{}: PID {} is still alive after stop()", self.name, self.pid);
        }
        for port in &self.owned_ports {
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("valid loopback addr");
            let bind = TcpListener::bind(addr);
            assert!(
                bind.is_ok(),
                "{}: port {port} is not re-bindable after stop() — {}",
                self.name,
                bind.err().map(|e| e.to_string()).unwrap_or_default(),
            );
            // Explicitly drop rather than let the listener linger for the rest
            // of the assertion loop and potentially shadow a later port check.
            drop(bind);
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        // Safety net: never panic in Drop. Kill+reap best-effort so a test
        // panic before an explicit `stop()` still leaves no dangling process.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_tee<R>(reader: Option<R>, path: PathBuf, captured: Arc<Mutex<CapturedOutput>>)
where
    R: std::io::Read + Send + 'static,
{
    let Some(reader) = reader else { return };
    std::thread::spawn(move || {
        let mut file = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match buf_reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    let _ = file.write_all(line.as_bytes());
                    let _ = file.flush();
                    captured.lock().expect("captured-output mutex").combined.push_str(&line);
                }
            }
        }
    });
}

fn http_get_is_2xx(url: &str) -> bool {
    // A blocking, dependency-light GET rather than pulling `reqwest`'s async
    // client into a synchronous readiness poll: this crate already depends on
    // `reqwest`, but its client is async, and a readiness loop that must work
    // from both async and non-async spawn callers is simplest as a tiny raw
    // TCP + HTTP/1.1 request rather than spinning up a runtime here.
    let Ok(parsed) = url::Url::parse(url) else { return false };
    let host = parsed.host_str().unwrap_or("127.0.0.1");
    let port = parsed.port_or_known_default().unwrap_or(80);
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(
        &format!("{host}:{port}")
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:1".parse().unwrap()),
        Duration::from_millis(300),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let path = if parsed.path().is_empty() { "/" } else { parsed.path() };
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        match std::io::Read::read(&mut stream, &mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 32 {
                    break;
                }
            }
        }
    }
    let head = String::from_utf8_lossy(&buf);
    head.strip_prefix("HTTP/1.1 ")
        .or_else(|| head.strip_prefix("HTTP/1.0 "))
        .and_then(|rest| rest.get(0..3))
        .and_then(|code| code.parse::<u16>().ok())
        .is_some_and(|code| (200..300).contains(&code))
}

/// Bind-and-release a free loopback port, matching the pattern
/// `proxy_trust_support::TrustedProxy::start` already uses.
pub fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// The workspace `target/` directory, honoring `CARGO_TARGET_DIR`. Mirrors
/// `proxy_trust_support::cargo_target_dir`; duplicated rather than imported
/// because `common/` modules are shared across test binaries that do not all
/// declare `mod proxy_trust_support`.
pub fn cargo_target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("aa-integration-tests always has a workspace-root parent")
                .join("target")
        })
}
