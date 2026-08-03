//! `aasm integrations repair` when there is nothing to repair (AAASM-5455).
//!
//! # The defect these tests pin
//!
//! With no integration receipt, `repair` printed a report whose every
//! distinguishing block was empty, said nothing on stderr, and exited `0` — so
//! `aasm integrations repair <tool> && echo repaired` announced a repair of a
//! tool that had never been installed. The service's own position on that state
//! is the opposite: the Repair verb refuses it outright. The CLI never saw the
//! refusal because it never sent the verb — it returned success from its own
//! "nothing drifted" branch first, and a tool with no receipt has no drift.
//!
//! So the tests below assert *both* sides, because a regression in either one
//! reintroduces the silence:
//!
//! - [`the_service_refuses_the_repair_verb_without_a_receipt`] pins the
//!   service's refusal. If the service ever starts returning success for this
//!   state, the CLI's message becomes a polite fiction and this fails.
//! - [`repair_without_an_installation_states_the_no_op_on_stdout_and_stderr`]
//!   pins the CLI's statement of it. If the short-circuit ever goes back to
//!   returning a bare success, this fails.
//!
//! # Nothing here touches the developer's real configuration
//!
//! Every test redirects `AA_DEVINT_SOCKET`, `AA_DEVINT_TOKEN_FILE`,
//! `AASM_STATE_DIR` and `HOME` into its own `TempDir`, and the fixture's
//! settings file lives there too.

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use aa_core::dev_tool::DevToolKind;
use aa_core::integration::ReceiptStore;
use aa_runtime::devint::fixture::{FixtureContent, FixtureIntegration};
use aa_runtime::devint::{
    DevIntServer, DevIntServerConfig, DevIntServices, EngineLifecycle, RegisteredIntegration, TokenStore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// A running DI-API server plus every path the CLI under test will use.
///
/// Deliberately a local copy rather than a shared module: `integrations_command.rs`
/// owns its own harness and these tests must not constrain it.
struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    token_file: PathBuf,
    settings: PathBuf,
    store_root: PathBuf,
    shutdown: CancellationToken,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&run).expect("run dir");
        let socket = run.join("devint.sock");
        let token_file = run.join("devint.token");
        let settings = dir.path().join("settings.json");
        let store_root = dir.path().join("state/integrations");

        // The enrolment helper resolves its path from the environment, so the
        // *test* process points it at the temp file before issuing the token.
        std::env::set_var("AA_DEVINT_TOKEN_FILE", &token_file);
        std::env::set_var("AA_DEVINT_SOCKET", &socket);

        let fixture = FixtureIntegration::new(DevToolKind::ClaudeCode, &settings);
        let content = Arc::new(FixtureContent::new(fixture.rendered()));
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![RegisteredIntegration::new(DevToolKind::ClaudeCode, Arc::new(fixture)).with_content(content)],
            ReceiptStore::at(&store_root),
        ));

        let tokens = TokenStore::new();
        aa_runtime::devint::enrol_local_client(&tokens, "aasm", aa_core::integration::now_unix_secs()).expect("enrol");

        let services = DevIntServices {
            lifecycle,
            tokens,
            audit: Arc::new(aa_runtime::devint::audit::TracingAuditSink),
        };
        let shutdown = CancellationToken::new();
        let server_token = shutdown.clone();
        let server_config = DevIntServerConfig {
            socket_path: socket.clone(),
            max_connections: 8,
        };
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let server = DevIntServer::bind(server_config).expect("bind");
                let tracker = TaskTracker::new();
                server.run(tracker.clone(), server_token, services).await;
                tracker.close();
                tracker.wait().await;
            });
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !socket.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(socket.exists(), "the test server never bound its socket");

        Self {
            dir,
            socket,
            token_file,
            settings,
            store_root,
            shutdown,
            server: Some(handle),
        }
    }

    /// Run the shipped `aasm` binary as a subprocess against this harness.
    fn aasm(&self, args: &[&str]) -> Output {
        let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
        cmd.arg("integrations")
            .args(args)
            .arg("--no-autostart")
            .env("AA_DEVINT_SOCKET", &self.socket)
            .env("AA_DEVINT_TOKEN_FILE", &self.token_file)
            .env("AASM_STATE_DIR", self.dir.path().join("state"))
            .env("HOME", self.dir.path())
            .env("AASM_API_KEY", "");
        cmd.output().expect("run aasm")
    }

    fn settings_contents(&self) -> Option<String> {
        std::fs::read_to_string(&self.settings).ok()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("the process was not signalled")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn combined(output: &Output) -> String {
    format!("--- stdout ---\n{}\n--- stderr ---\n{}", stdout(output), stderr(output))
}

mod exit {
    pub const SUCCESS: i32 = 0;
    pub const DRIFTED: i32 = 5;
}

/// The sentence the service uses to refuse a repair it has no receipt for.
const SERVICE_REFUSAL: &str = "no integration receipt records";

// ── the service's position ───────────────────────────────────────────────────

/// The service refuses the Repair verb outright when no receipt accounts for
/// the tool. This is the falsification half of the pair: if the service is ever
/// changed to answer this state with an unconditional success, the CLI's
/// "nothing to repair" message stops being a report of a real refusal and
/// becomes a story the CLI made up — and this test fails first.
#[test]
fn the_service_refuses_the_repair_verb_without_a_receipt() {
    let h = Harness::start();
    let token = std::fs::read_to_string(&h.token_file).expect("token file");
    let socket = h.socket.clone();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let mut client =
            aa_runtime::devint::DevIntClient::connect(&socket, "aasm-test", "0.0.0", Some(token.trim().to_string()))
                .await
                .expect("connect");

        let refusal = client
            .repair("claude-code")
            .await
            .expect_err("the service accepted a repair for a tool it holds no receipt for");
        let rendered = format!("{refusal:?}");
        assert!(
            rendered.contains(SERVICE_REFUSAL),
            "the service refused, but not for the reason this command reports to the user: {rendered}"
        );

        // …and the verb the CLI actually sends does *not* refuse, which is the
        // asymmetry that let the no-op pass as a success in the first place.
        let status = client.status("claude-code").await.expect("status");
        assert_eq!(status.phase, "detected_not_integrated", "{status:?}");
        assert!(
            status.drift_mismatched.is_empty(),
            "a tool with no receipt reported drift, so the fix's premise no longer holds: {status:?}"
        );
    });
}

// ── the CLI's statement of it ────────────────────────────────────────────────

/// The bug, inverted. Asserts the exit code **and both streams**: a test that
/// only pinned the exit code would have passed against the defect, because the
/// defect's exit code was already `0` and stayed `0`.
#[test]
fn repair_without_an_installation_states_the_no_op_on_stdout_and_stderr() {
    let h = Harness::start();
    let output = h.aasm(&["repair", "claude-code", "--yes"]);

    // Deliberate, and documented in `repair.rs`: a no-op is a success, the same
    // way a second `remove` is. The distinction lives in the output.
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));

    let err = stderr(&output);
    assert!(
        err.contains("no Agent Assembly integration to repair"),
        "stderr said nothing about the no-op: {}",
        combined(&output)
    );
    assert!(
        err.contains("claude-code") && err.contains("detected_not_integrated"),
        "the stderr notice named neither the tool nor the phase it decided from: {err}"
    );

    let out = stdout(&output);
    assert!(
        out.contains("nothing to repair"),
        "the report's always-printed header did not carry the outcome: {out}"
    );
    assert!(
        out.contains("Nothing was repaired:"),
        "the report carried no unconditional statement of the no-op: {out}"
    );
    // The other no-op — an installed tool whose state matches its receipt —
    // must not be borrowed to describe this one. There is no receipt here, so
    // claiming anything matches one is a false statement about the host, and
    // it is what this command says if the phase branch is removed and the
    // `drifted.is_empty()` branch catches the case instead.
    assert!(
        !out.contains("matches its receipt"),
        "a tool with no receipt was described as matching one: {out}"
    );

    // The word the ticket observed was absent from the whole run.
    assert!(
        combined(&output).contains("receipt") || out.contains("no Agent Assembly integration"),
        "nothing in the output explains that there is no installation: {}",
        combined(&output)
    );

    // A stated no-op must also be a real one.
    assert!(
        h.settings_contents().is_none(),
        "repair wrote the tool's settings file for a tool that was never installed"
    );
    assert!(
        !h.store_root.exists(),
        "repair created a receipt store for a tool that was never installed"
    );
}

/// `--output json` is the scripted surface, and the reason has to survive into
/// it — an operator branching on the report must not have to parse English.
#[test]
fn repair_without_an_installation_reports_the_reason_in_json() {
    let h = Harness::start();
    let output = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);

    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("the report was not valid JSON");

    let reason = report
        .get("nothing_to_repair")
        .and_then(|v| v.as_str())
        .expect("the JSON report carried no nothing_to_repair reason");
    assert!(
        reason.contains("no Agent Assembly integration to repair"),
        "the machine-readable reason does not state the no-op: {reason}"
    );
    assert_eq!(
        report.get("repaired").and_then(|v| v.as_array()).map(Vec::len),
        Some(0),
        "a no-op claimed to have repaired something: {report}"
    );
}

/// The dry run has the same hole and the same fix: previewing a repair of a
/// tool that was never installed must not render as an empty, clean preview.
#[test]
fn repair_dry_run_without_an_installation_states_the_no_op() {
    let h = Harness::start();
    let output = h.aasm(&["repair", "claude-code", "--dry-run"]);

    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    assert!(
        stderr(&output).contains("no Agent Assembly integration to repair"),
        "{}",
        combined(&output)
    );
    assert!(stdout(&output).contains("nothing to repair"), "{}", stdout(&output));
}

// ── falsification: success is not unconditional ──────────────────────────────

/// The guard against the other failure mode. A `repair` that reported the same
/// thing regardless of state would satisfy every assertion above; this test
/// runs the *real* repair path in the same process-shaped way and requires the
/// two outcomes to be distinguishable in both directions:
///
/// - the real repair must say it restored something, and must **not** carry the
///   no-op marker;
/// - the no-op must carry the marker, and must **not** claim a restoration.
///
/// Collapsing the two — by dropping the phase branch, by making
/// `nothing_to_repair` unconditional, or by rendering the header the same way
/// either side — fails here.
#[test]
fn a_real_repair_and_a_no_op_repair_are_not_the_same_output() {
    let h = Harness::start();
    std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");

    // Before anything is installed: the no-op.
    let no_op = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(code(&no_op), exit::SUCCESS, "{}", combined(&no_op));

    // Install, then tamper with a key AASM owns so there is real drift.
    assert_eq!(
        code(&h.aasm(&["install", "claude-code", "--yes"])),
        exit::SUCCESS,
        "install failed, so the real-repair half of this test proves nothing"
    );
    std::fs::write(&h.settings, r#"{"aasmManaged":false,"theme":"gruvbox"}"#).expect("tamper");
    assert_eq!(
        code(&h.aasm(&["status", "claude-code"])),
        exit::DRIFTED,
        "the tampering produced no drift, so the real-repair half proves nothing"
    );

    let real = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(code(&real), exit::SUCCESS, "{}", combined(&real));

    // The real repair actually restored the managed key.
    assert!(
        h.settings_contents()
            .expect("settings")
            .contains(r#""aasmManaged":true"#),
        "the real repair did not restore anything, so it is not a control"
    );

    // Now the two must be tellable apart, in both directions.
    assert!(
        stdout(&real).contains("Restored"),
        "the real repair did not report a restoration: {}",
        stdout(&real)
    );
    assert!(
        !stdout(&real).contains("nothing to repair"),
        "a repair that restored a managed key was marked as a no-op: {}",
        stdout(&real)
    );
    assert!(
        stdout(&no_op).contains("nothing to repair"),
        "the no-op was not marked: {}",
        stdout(&no_op)
    );
    assert!(
        !stdout(&no_op).contains("Restored"),
        "a repair of a tool that was never installed claimed a restoration: {}",
        stdout(&no_op)
    );
    assert!(
        !stderr(&real).contains("no Agent Assembly integration to repair"),
        "a real repair emitted the no-op notice: {}",
        stderr(&real)
    );
}

/// The third state, kept distinct from the other two on purpose: installed,
/// clean, nothing drifted. It repairs nothing and exits `0` like the
/// uninstalled case, but for a different reason — and says so, rather than
/// borrowing the uninstalled case's wording.
#[test]
fn repair_of_a_clean_installation_states_its_own_reason() {
    let h = Harness::start();
    std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let output = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));

    let out = stdout(&output);
    assert!(out.contains("nothing to repair"), "{out}");
    assert!(
        out.contains("already matches its receipt"),
        "a clean installation borrowed the uninstalled case's reason: {out}"
    );
    assert!(
        !out.contains("no Agent Assembly integration to repair"),
        "an installed tool was described as having no integration: {out}"
    );
    // An installed tool is installed: the uninstalled notice must not appear.
    assert!(
        !stderr(&output).contains("no Agent Assembly integration to repair"),
        "{}",
        stderr(&output)
    );
}
