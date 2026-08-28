//! `aasm integrations remove` when there is nothing to remove (AAASM-5629).
//!
//! # The contract these tests pin
//!
//! A removal report identifies the plan it is a report *of*. Every report that
//! has one must carry it; a report that has none must say so, rather than
//! carrying an empty id that a reader — human or script — has to guess about.
//! The defect was the second half: with no integration installed the CLI
//! printed
//!
//! ```text
//! claude-code — removal (plan )
//! ```
//!
//! and `--output json` carried `"plan_id": ""`.
//!
//! # Why that is a plan-identity defect and not a rendering one
//!
//! The service never authors a plan with a blank id. `EngineLifecycle::remove`
//! loads the integration receipt *before* asking the adapter to author the
//! reversal, and with no receipt it refuses outright — so there is no removal
//! plan for an uninstalled tool, not a nameless one. The empty string was
//! invented by the CLI's own short-circuit, which decides from the lifecycle
//! phase and never sends the `Remove` verb at all. The report type said
//! "a removal always has a plan id" and the no-op path had to lie to satisfy
//! it.
//!
//! So the tests below assert both ends of that, because a regression in either
//! reintroduces the ambiguity:
//!
//! - [`the_service_refuses_the_remove_verb_without_a_receipt`] pins the
//!   service's position. If it ever starts authoring a plan for a tool it holds
//!   no receipt for, the no-op *should* carry an id and this fails first.
//! - [`every_removal_report_agrees_with_itself_about_its_plan_identity`] pins
//!   the report's: across all three shapes a removal can take, the machine
//!   field is either a real id or an explicit absence — never `""` — and the
//!   human first line says the same thing the JSON does.
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
    DevIntServer, DevIntServerConfig, DevIntServices, EngineLifecycle, RegisteredIntegration, TargetRequest, TokenStore,
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

        let services = DevIntServices::new(lifecycle, tokens, Arc::new(aa_runtime::devint::audit::TracingAuditSink));
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
            // AAASM-5957: the fixture's settings file lives at this harness's
            // root directly, so the caller-supplied configuration home is
            // pointed there rather than left to the `$HOME/.claude` default —
            // otherwise it would name a home the receipt never recorded.
            .env("CLAUDE_CONFIG_DIR", self.dir.path())
            .env("AASM_API_KEY", "");
        cmd.output().expect("run aasm")
    }

    fn settings_contents(&self) -> Option<String> {
        std::fs::read_to_string(&self.settings).ok()
    }

    /// Put a real integration in place, so the "has a plan" half of the
    /// contract is exercised against a real one rather than a stub.
    fn install(&self) {
        std::fs::write(&self.settings, r#"{"theme":"solarized"}"#).expect("seed");
        assert_eq!(
            code(&self.aasm(&["install", "claude-code", "--yes"])),
            exit::SUCCESS,
            "install failed, so the has-a-plan half of these tests proves nothing"
        );
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
}

/// The sentence the service uses to refuse a removal it has no receipt for.
const SERVICE_REFUSAL: &str = "no integration receipt records";

/// The plan identity a removal report claims, read from `--output json`.
///
/// `Ok(Some(id))` is a plan; `Ok(None)` is an explicit, machine-readable
/// absence. Anything else — a missing field, a non-string, or the empty string
/// — is the defect: a report that neither names a plan nor admits it has none.
fn plan_identity(report: &serde_json::Value) -> Result<Option<String>, String> {
    match report.get("plan_id") {
        None => Err("the report has no `plan_id` field at all".to_string()),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(id)) if !id.trim().is_empty() => Ok(Some(id.clone())),
        Some(serde_json::Value::String(_)) => Err(
            "`plan_id` is the empty string: the report neither names a plan nor states that it has none, \
             so every consumer has to guess which it meant"
                .to_string(),
        ),
        Some(other) => Err(format!("`plan_id` is not a string or null: {other}")),
    }
}

/// The parenthetical on a removal report's always-printed first line.
///
/// That line is the only part of the human rendering a reader always sees, so
/// it is where the plan identity has to agree with the machine field.
fn header_parenthetical(out: &str) -> String {
    let first = out.lines().next().unwrap_or_default();
    let open = first
        .rfind('(')
        .unwrap_or_else(|| panic!("no parenthetical on the header line: {first:?}"));
    let close = first[open..]
        .find(')')
        .unwrap_or_else(|| panic!("unterminated parenthetical on the header line: {first:?}"));
    first[open + 1..open + close].to_string()
}

/// Assert the one contract, for one run: the machine field is well formed, and
/// the human header says the same thing it does.
fn assert_plan_identity_is_coherent(label: &str, human: &Output, json: &Output) {
    let report: serde_json::Value =
        serde_json::from_str(&stdout(json)).unwrap_or_else(|e| panic!("{label}: the report was not valid JSON: {e}"));
    let identity = plan_identity(&report).unwrap_or_else(|e| {
        panic!(
            "{label}: {e}\n{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        )
    });

    let parenthetical = header_parenthetical(&stdout(human));
    match identity {
        Some(id) => assert_eq!(
            parenthetical,
            format!("plan {id}"),
            "{label}: the human header does not name the plan the JSON reports\n{}",
            combined(human)
        ),
        None => {
            assert!(
                !parenthetical.trim().is_empty(),
                "{label}: the JSON says there is no plan and the human header says nothing at all\n{}",
                combined(human)
            );
            assert!(
                !parenthetical.starts_with("plan"),
                "{label}: the JSON says there is no plan but the human header still claims one: {parenthetical:?}\n{}",
                combined(human)
            );
        }
    }
}

// ── the service's position ───────────────────────────────────────────────────

/// The service refuses the Remove verb outright when no receipt accounts for
/// the tool — it does not author a plan with a blank id.
///
/// This is the falsification half. If the service is ever changed to author a
/// reversal for a tool it holds no receipt for, then the no-op *does* have a
/// plan and should carry its id, and this test fails before the report-shape
/// tests below start looking wrong.
#[test]
fn the_service_refuses_the_remove_verb_without_a_receipt() {
    let h = Harness::start();
    let token = std::fs::read_to_string(&h.token_file).expect("token file");
    let socket = h.socket.clone();
    let home = h.dir.path().to_string_lossy().into_owned();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let mut client =
            aa_runtime::devint::DevIntClient::connect(&socket, "aasm-test", "0.0.0", Some(token.trim().to_string()))
                .await
                .expect("connect");

        // Names the configuration home the fixture actually set `HOME` to, so
        // this reaches the no-receipt refusal under test rather than the
        // AAASM-5957 unstated-configuration-home refusal.
        let target = TargetRequest {
            user_config_home: &home,
            ..TargetRequest::default()
        };

        // The authoring half of the verb — no plan id, so it mutates nothing.
        // Even that is refused, which is what makes the uninstalled case
        // plan-*less* rather than holding a plan nobody named.
        let refusal = client
            .remove("claude-code", "", target)
            .await
            .expect_err("the service authored a removal plan for a tool it holds no receipt for");
        let rendered = format!("{refusal:?}");
        assert!(
            rendered.contains(SERVICE_REFUSAL),
            "the service refused, but not because there is no receipt: {rendered}"
        );

        // …and the verb the CLI actually sends first does not refuse, which is
        // why the CLI can short-circuit before ever seeing the refusal above.
        let status = client.status("claude-code", target).await.expect("status");
        assert_eq!(status.phase, "detected_not_integrated", "{status:?}");
    });
}

// ── the report's position ────────────────────────────────────────────────────

/// The contract, over every shape a removal report can take.
///
/// One test on purpose: the point is not that any single run looks right, it
/// is that the *same* rule holds whether a plan exists or not. A report either
/// names its plan in both surfaces or states in both that it has none.
#[test]
fn every_removal_report_agrees_with_itself_about_its_plan_identity() {
    // 1. Nothing installed: there is no plan, because the service will not
    //    author one (see the test above).
    let h = Harness::start();
    assert_plan_identity_is_coherent(
        "no installation",
        &h.aasm(&["remove", "claude-code", "--yes"]),
        &h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]),
    );

    // 2. Installed, previewed: the service authored a plan, so it has an id.
    let preview_host = Harness::start();
    preview_host.install();
    assert_plan_identity_is_coherent(
        "dry-run preview",
        &preview_host.aasm(&["remove", "claude-code", "--dry-run"]),
        &preview_host.aasm(&["remove", "claude-code", "--dry-run", "--output", "json"]),
    );

    // 3. Installed, executed: the id the executing call referred to.
    let human_host = Harness::start();
    human_host.install();
    let human = human_host.aasm(&["remove", "claude-code", "--yes"]);
    let json_host = Harness::start();
    json_host.install();
    let json = json_host.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    assert_plan_identity_is_coherent("executed removal", &human, &json);
}

/// A removal that had a plan must name it — the control for the test below.
///
/// Without this, "always report no plan" would satisfy the no-op assertions,
/// and the plan identity would have been removed rather than made honest.
#[test]
fn a_real_removal_names_the_plan_it_carried_out() {
    let h = Harness::start();
    h.install();
    let output = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));

    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("the report was not valid JSON");
    let id = plan_identity(&report)
        .expect("a real removal reported a malformed plan identity")
        .expect("a real removal reported no plan at all, so the identity was dropped rather than fixed");
    assert!(
        !id.trim().is_empty(),
        "a real removal reported a blank plan identity: {id:?}"
    );
    assert!(
        !report["steps"].as_array().expect("steps").is_empty(),
        "the removal that is meant to be the control restored nothing: {report}"
    );
}

/// The no-op removal states that it has no plan, in both surfaces.
///
/// `null` rather than `""` is the machine-readable half: a script can test for
/// absence instead of comparing against a sentinel string it had to know about.
#[test]
fn a_removal_with_nothing_to_remove_reports_no_plan_at_all() {
    let h = Harness::start();
    let output = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));

    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("the report was not valid JSON");
    assert_eq!(
        plan_identity(&report).expect("the no-op reported a malformed plan identity"),
        None,
        "a removal that authored no plan reported one: {report}"
    );
    assert!(
        report["steps"].as_array().expect("steps").is_empty(),
        "a removal of a tool that was never installed listed restoration actions: {report}"
    );

    // The human half states the same fact on the always-printed first line,
    // and the stderr notice still explains why.
    let human = h.aasm(&["remove", "claude-code", "--yes"]);
    assert!(
        stdout(&human).contains("nothing to remove"),
        "the report's always-printed header did not carry the outcome: {}",
        combined(&human)
    );
    assert!(
        stderr(&human).contains("no Agent Assembly integration to remove"),
        "{}",
        combined(&human)
    );

    // A stated no-op must also be a real one.
    assert!(
        h.settings_contents().is_none(),
        "remove wrote the tool's settings file for a tool that was never installed"
    );
    assert!(
        !h.store_root.exists(),
        "remove created a receipt store for a tool that was never installed"
    );
}

/// `--dry-run` reaches the same short-circuit — the phase is decided before the
/// preview is asked for — so it has the same hole and needs the same answer.
#[test]
fn a_dry_run_with_nothing_to_remove_reports_no_plan_at_all() {
    let h = Harness::start();
    let json = h.aasm(&["remove", "claude-code", "--dry-run", "--output", "json"]);
    assert_eq!(code(&json), exit::SUCCESS, "{}", combined(&json));

    let report: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("the report was not valid JSON");
    assert_eq!(
        plan_identity(&report).expect("the no-op preview reported a malformed plan identity"),
        None,
        "a preview that authored no plan reported one: {report}"
    );

    assert_plan_identity_is_coherent(
        "no-installation dry run",
        &h.aasm(&["remove", "claude-code", "--dry-run"]),
        &json,
    );
}
