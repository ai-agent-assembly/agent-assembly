//! Launcher for the SHIPPED `aa-api-server` binary (AAASM-5902).
//!
//! Not an in-process test harness: `aa-api/src/bin/aa-api-server.rs` is the
//! real released entrypoint (`aasm-api-server` in the release artefacts), and a
//! journey that claims cross-process telemetry evidence needs to measure that
//! binary, not a stand-in that merely calls the same library functions in-proc.
//!
//! # Why readiness is TWO conditions, not one
//!
//! `aa-api/src/server.rs::serve_local_telemetry_grpc` binds the redaction
//! telemetry ingest on a second port alongside the REST/health port. If that
//! bind loses a race for the port, it **degrades to a warning and continues** —
//! the process still comes up and `/api/v1/health` still answers 200 — rather
//! than failing to start (mirrors `serve_local_grpc`'s existing degrade
//! behaviour for the agent-registration gRPC port; both documented on those
//! functions). A harness that only polled `/api/v1/health` could not tell a
//! healthy telemetry-capable server apart from one silently missing its
//! telemetry ingest — exactly the "unavailable/unmeasured telemetry read as a
//! measured zero" failure AAASM-5875 exists to catch. So readiness here also
//! requires the exact log line `serve_local_telemetry_grpc` emits on a
//! successful bind: `"aa-api redaction telemetry ingest listening
//! (loopback-only)"` (verified against `aa-api/src/server.rs` at the time this
//! was written — re-check if that function is touched).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::managed_process::{ManagedProcess, ProcessSpec, Readiness};

/// The exact log line `aa-api::server::serve_local_telemetry_grpc` emits after
/// a successful bind of the redaction telemetry ingest. A port collision skips
/// this line entirely (see module docs) — that is the property this readiness
/// condition exists to detect.
pub const TELEMETRY_READY_LOG_LINE: &str = "aa-api redaction telemetry ingest listening (loopback-only)";

/// A running `aa-api-server` process, isolated per-instance state.
#[derive(Debug)]
pub struct ApiServerProcess {
    process: ManagedProcess,
    base_url: String,
    telemetry_addr: String,
    _tmp: tempfile::TempDir,
}

impl ApiServerProcess {
    /// Spawn `aa-api-server` on free loopback ports for both REST and
    /// telemetry gRPC, with an isolated `HOME`/data dir, auth disabled, and
    /// info-level logging. Blocks until both readiness conditions hold.
    pub fn spawn() -> Result<Self> {
        Self::spawn_with(None, Duration::from_secs(30))
    }

    /// As [`Self::spawn`], but with the telemetry port and readiness timeout
    /// overridable.
    ///
    /// Exists for `harness_primitives.rs`'s load-bearing
    /// `api_server_spawn_fails_when_the_telemetry_port_is_already_held` test,
    /// which must pre-bind the telemetry port to a value it controls before
    /// spawning, and needs a short timeout so the negative case doesn't cost
    /// the full 30s default. Not a general-purpose knob — production callers
    /// use [`Self::spawn`].
    pub fn spawn_with(telemetry_port_override: Option<u16>, ready_timeout: Duration) -> Result<Self> {
        let bin = resolve_binary()?;
        let tmp = tempfile::tempdir().context("creating temp HOME for ApiServerProcess")?;
        let home = tmp.path().to_path_buf();
        let log_dir = home.join("logs");

        let rest_port = super::managed_process::pick_free_port().context("picking REST port")?;
        let telemetry_port = match telemetry_port_override {
            Some(p) => p,
            None => super::managed_process::pick_free_port().context("picking telemetry port")?,
        };
        let rest_addr = format!("127.0.0.1:{rest_port}");
        let telemetry_addr = format!("127.0.0.1:{telemetry_port}");
        let base_url = format!("http://{rest_addr}");

        let spec = ProcessSpec {
            name: "aa-api-server".to_owned(),
            program: bin,
            args: Vec::new(),
            env: vec![
                ("HOME".to_owned(), home.to_string_lossy().into_owned()),
                ("AA_API_ADDR".to_owned(), rest_addr.clone()),
                ("AA_API_TELEMETRY_ADDR".to_owned(), telemetry_addr),
                ("AASM_API_AUTH".to_owned(), "off".to_owned()),
                ("RUST_LOG".to_owned(), "aa_api=info,info".to_owned()),
            ],
            cwd: None,
            ready: vec![
                Readiness::HttpOk(format!("{base_url}/api/v1/health")),
                Readiness::LogLine(TELEMETRY_READY_LOG_LINE),
            ],
            ready_timeout,
            log_dir,
            owned_ports: vec![rest_port, telemetry_port],
        };

        let process = ManagedProcess::spawn(spec)?;
        Ok(Self {
            process,
            base_url,
            telemetry_addr: format!("127.0.0.1:{telemetry_port}"),
            _tmp: tmp,
        })
    }

    /// Loopback `host:port` this server's redaction telemetry gRPC ingest is
    /// bound to (AAASM-5903) — what a cross-process journey points
    /// `AA_PROXY_TELEMETRY_ENDPOINT` at to route a real `aa-proxy`'s redaction
    /// reports here, exactly as `TrustedProxy::start_intercepting`'s
    /// `extra_env` is designed to carry.
    pub fn telemetry_addr(&self) -> &str {
        &self.telemetry_addr
    }

    /// Base URL of the REST surface, e.g. `http://127.0.0.1:54321`.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// OS process id.
    pub fn pid(&self) -> u32 {
        self.process.pid()
    }

    /// GET `/api/v1/alerts` and parse the response JSON.
    pub fn alerts(&self) -> Result<AlertsResponse> {
        let url = format!("{}/api/v1/alerts", self.base_url);
        let resp = reqwest::blocking::get(&url).with_context(|| format!("GET {url}"))?;
        anyhow::ensure!(resp.status().is_success(), "GET {url} returned {}", resp.status());
        resp.json::<AlertsResponse>()
            .with_context(|| format!("parsing JSON from {url}"))
    }

    /// Block until `/api/v1/alerts` reports at least `min_total` alerts, or
    /// `within` expires. Returns the last-observed response either way, so the
    /// caller asserts rather than hangs.
    pub fn wait_for_alerts(&self, min_total: u64, within: Duration) -> Result<AlertsResponse> {
        let deadline = std::time::Instant::now() + within;
        loop {
            let resp = self.alerts()?;
            if resp.total >= min_total || std::time::Instant::now() >= deadline {
                return Ok(resp);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Everything captured on stdout+stderr so far.
    pub fn logs(&self) -> String {
        self.process.captured_output()
    }

    /// SIGTERM, wait up to 5s, SIGKILL as a safety net.
    pub fn stop(&mut self) -> Result<()> {
        self.process.stop(Duration::from_secs(5))
    }

    /// Assert the process left no trace: PID reaped, both owned ports
    /// re-bindable. Call after [`Self::stop`].
    pub fn assert_no_leaks(&self) {
        self.process.assert_no_leaks();
    }
}

/// `{ items, total }` shape of `GET /api/v1/alerts` (`aa-api/src/routes/alerts.rs`
/// `PaginatedAlertResponse`). Only `total` is modeled here — callers that need
/// individual alert fields should extend this rather than re-parsing raw JSON.
#[derive(Debug, Deserialize)]
pub struct AlertsResponse {
    pub total: u64,
}

/// Resolve the `aa-api-server` binary: `AA_API_SERVER_BIN_PATH` override, else
/// build it unconditionally.
///
/// Mirrors `proxy_trust_support::build_binary`'s unconditional-build stance —
/// genuinely, not just in name: an earlier version of this function checked
/// `target/{debug,release}` for an existing artefact first and only built on a
/// miss, which is exactly the staleness hazard the original comment warned
/// about but didn't prevent. A `target/debug/aa-api-server` left over from an
/// earlier checkout state (normal on a dev machine or any CI runner with a
/// persistent cache) would be silently reused instead of measuring the
/// current tree. `cargo build` on an already-fresh target is fast (its own
/// incremental check is the freshness check), so there is no real cost to
/// invoking it every time. Memoized per test binary so repeated
/// `ApiServerProcess::spawn()` calls in one process don't re-invoke cargo.
fn resolve_binary() -> Result<PathBuf> {
    if let Ok(explicit) = std::env::var("AA_API_SERVER_BIN_PATH") {
        return std::fs::canonicalize(&explicit)
            .with_context(|| format!("AA_API_SERVER_BIN_PATH={explicit:?} could not be resolved"));
    }

    static BUILT: std::sync::OnceLock<std::sync::Mutex<Option<PathBuf>>> = std::sync::OnceLock::new();
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(path) = cache.as_ref() {
        return Ok(path.clone());
    }

    let status = std::process::Command::new(env!("CARGO"))
        .args(["build", "--quiet", "-p", "aa-api", "--bin", "aa-api-server"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .context("invoking cargo to build aa-api-server")?;
    anyhow::ensure!(status.success(), "`cargo build -p aa-api --bin aa-api-server` failed");

    let target_dir = super::managed_process::cargo_target_dir();
    let built = target_dir.join("debug").join("aa-api-server");
    anyhow::ensure!(
        built.is_file(),
        "no aa-api-server artefact at {} even after building it. Skipping instead would leave the \
         behaviour unmeasured.",
        built.display(),
    );
    *cache = Some(built.clone());
    Ok(built)
}
