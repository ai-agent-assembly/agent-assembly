//! `aasm integrations` end to end, against a real DI-API server (AAASM-5280).
//!
//! # Why these tests run the real binary against a real socket
//!
//! The command family's whole claim is that it is a *client*: it holds no tool
//! knowledge, derives no protection state, and gets everything over one
//! boundary. A test that called the command functions with a mocked client
//! would pass just as happily if that stopped being true. So each test here
//! stands up an actual [`DevIntServer`] over an actual Unix socket, backed by
//! the same [`FixtureIntegration`] `aa-runtime`'s own tests use, and then runs
//! the compiled `aasm` binary as a subprocess against it.
//!
//! # Nothing here touches the developer's real configuration
//!
//! Every test redirects `AA_DEVINT_SOCKET`, `AA_DEVINT_TOKEN_FILE`,
//! `AASM_STATE_DIR` and `HOME` into its own `TempDir`, and the fixture's
//! settings file lives there too. No test reads or writes `~/.claude`, `~/.aa`
//! or `~/.aasm`.

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use aa_core::dev_tool::DevToolKind;
use aa_core::integration::ReceiptStore;
use aa_runtime::devint::fixture::{FixtureContent, FixtureIntegration, FixtureVerification, LEAK_SENTINEL};
use aa_runtime::devint::{
    DevIntServer, DevIntServerConfig, DevIntServices, EngineLifecycle, RegisteredIntegration, TokenStore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// A running DI-API server plus every path the CLI under test will use.
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
    /// Start a server whose single registered tool is `build`'s fixture.
    fn start(build: impl FnOnce(FixtureIntegration) -> FixtureIntegration) -> Self {
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

        let fixture = build(FixtureIntegration::new(DevToolKind::ClaudeCode, &settings));
        let content = Arc::new(FixtureContent::new(fixture.rendered()));
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![RegisteredIntegration::new(DevToolKind::ClaudeCode, Arc::new(fixture)).with_content(content)],
            ReceiptStore::at(&store_root),
        ));

        let tokens = TokenStore::new();
        // Issued at *now*: the token carries an absolute expiry, so a fixed epoch
        // would hand the CLI a credential that expired years ago.
        aa_runtime::devint::enrol_local_client(&tokens, "aasm", aa_core::integration::now_unix_secs()).expect("enrol");

        let services = DevIntServices::new(lifecycle, tokens, Arc::new(aa_runtime::devint::audit::TracingAuditSink));
        let shutdown = CancellationToken::new();
        let server_token = shutdown.clone();
        let server_config = DevIntServerConfig {
            socket_path: socket.clone(),
            max_connections: 8,
        };
        // `DevIntServer::bind` registers the listener with the tokio reactor,
        // so it has to happen inside the server's own runtime rather than on
        // the test thread.
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

        // The listener is bound before `run` is spawned, so the socket file is
        // already on disk; wait for it anyway rather than assume.
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

    /// Run `aasm integrations …` against this harness.
    fn aasm(&self, args: &[&str]) -> Output {
        let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
        cmd.arg("integrations")
            .args(args)
            // No autostart: the server is already up, and a test that started a
            // real runtime would leave a daemon behind and read the developer's
            // own home directory.
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
    format!("{}{}", stdout(output), stderr(output))
}

/// Exit codes, in one place so a test asserting one reads as a contract rather
/// than as a magic number.
mod exit {
    pub const SUCCESS: i32 = 0;
    pub const UNSUPPORTED: i32 = 3;
    pub const DRIFTED: i32 = 5;
    pub const VERIFICATION_FAILED: i32 = 6;
    pub const RUNTIME_UNAVAILABLE: i32 = 7;
    pub const ABORTED: i32 = 9;
}

// ── plan mutates nothing ─────────────────────────────────────────────────────

/// The plan verb's entire contract, asserted against the filesystem. "It did
/// not mutate" is a claim about the host, so the host is what is checked: no
/// settings file, no receipt, no store directory.
#[test]
fn plan_creates_no_file_no_artifact_and_no_store_directory() {
    let h = Harness::start(|f| f);
    let output = h.aasm(&["plan", "claude-code"]);

    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    assert!(
        stdout(&output).contains("Nothing has been changed"),
        "{}",
        stdout(&output)
    );
    assert!(h.settings_contents().is_none(), "plan wrote the tool's settings file");
    assert!(!h.store_root.exists(), "plan created the receipt store directory");
    assert!(
        !h.dir.path().join("state").join("integrations").exists(),
        "plan created a receipt"
    );
}

// ── install: idempotent, and it keeps what it did not write ──────────────────

#[test]
fn installing_twice_is_idempotent_and_preserves_unrelated_user_configuration() {
    let h = Harness::start(|f| f);
    std::fs::write(&h.settings, r#"{"theme":"solarized","editor":{"tabSize":2}}"#).expect("seed");

    let first = h.aasm(&["install", "claude-code", "--yes"]);
    assert_eq!(code(&first), exit::SUCCESS, "{}", combined(&first));
    let after_first = h.settings_contents().expect("settings written");
    assert!(
        after_first.contains("solarized"),
        "the user's own key was lost: {after_first}"
    );
    assert!(
        after_first.contains("tabSize"),
        "a nested user key was lost: {after_first}"
    );
    assert!(after_first.contains("aasmManaged"), "the managed keys were not written");

    let second = h.aasm(&["install", "claude-code", "--yes"]);
    assert_eq!(code(&second), exit::SUCCESS, "{}", combined(&second));
    assert_eq!(
        h.settings_contents().expect("settings"),
        after_first,
        "a repeated install changed the file"
    );
    // Idempotence is a property of the host, not of a line of output: the file
    // is byte-identical and the receipt still names one applied step.
    assert!(stdout(&second).contains("settings: applied"), "{}", stdout(&second));
}

/// A machine-readable run has no way to answer a prompt, so it must abort and
/// change nothing rather than treat silence as consent.
#[test]
fn a_non_interactive_install_without_yes_aborts_and_changes_nothing() {
    let h = Harness::start(|f| f);
    let output = h.aasm(&["install", "claude-code"]);
    assert_eq!(code(&output), exit::ABORTED, "{}", combined(&output));
    assert!(stderr(&output).contains("--yes"), "{}", stderr(&output));
    assert!(h.settings_contents().is_none(), "an aborted install wrote settings");
}

// ── verify: the anti-vacuous-pass guard ──────────────────────────────────────

/// **The** load-bearing test, and it is deliberately adversarial: the fixture
/// reports `Passed` while having exercised nothing at all. An implementation
/// that trusted the outcome token would exit 0 here. `verify` must fail anyway,
/// because a pass with no traffic behind it is a statement about a file.
#[test]
fn verify_fails_when_the_protected_path_was_not_exercised() {
    let h = Harness::start(|f| f.verifying(FixtureVerification::VacuousPass));
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let output = h.aasm(&["verify", "claude-code"]);
    assert_eq!(
        code(&output),
        exit::VERIFICATION_FAILED,
        "a verification that exercised nothing must not exit 0:\n{}",
        combined(&output)
    );
    let rendered = stdout(&output);
    assert!(
        rendered.contains("protected path exercised: no"),
        "the output did not say the path was not exercised:\n{rendered}"
    );
    assert!(
        rendered.contains("NOT a protection measurement"),
        "the output let a configuration check read as protection:\n{rendered}"
    );
}

#[test]
fn verify_succeeds_only_when_traffic_was_produced_and_adjudicated() {
    let h = Harness::start(|f| f.verifying(FixtureVerification::Exercised));
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let output = h.aasm(&["verify", "claude-code"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    assert!(stdout(&output).contains("protected path exercised: yes"));
}

/// An adapter with no protection test says so. `Unverifiable` is not a pass,
/// and must not exit 0.
#[test]
fn an_unverifiable_integration_fails_rather_than_passing_quietly() {
    let h = Harness::start(|f| f.verifying(FixtureVerification::Unverifiable));
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    let output = h.aasm(&["verify", "claude-code"]);
    assert_eq!(code(&output), exit::VERIFICATION_FAILED, "{}", combined(&output));
}

/// The machine-readable half of the same claim: a script must be able to branch
/// on the assertion without reading prose.
#[test]
fn verify_emits_machine_readable_assertions() {
    let h = Harness::start(|f| f.verifying(FixtureVerification::VacuousPass));
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    let output = h.aasm(&["verify", "claude-code", "--output", "json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");

    assert_eq!(json["protected_path_exercised"], serde_json::json!(false));
    let exercised = json["assertions"]
        .as_array()
        .expect("assertions")
        .iter()
        .find(|a| a["id"] == "protected_path_exercised")
        .expect("the exercised assertion must be present");
    assert_eq!(exercised["holds"], serde_json::json!(false));
}

// ── status: evidence, and the rung this host cannot reach ────────────────────

/// The rung is named on every read, and what is said about it is the
/// **adapter's** answer — product brief §7.3 for the naming, AAASM-5454 for the
/// answer. An adapter that declares the mechanism unsupported gets its own
/// sentence printed; nothing here substitutes a platform claim of the CLI's own.
#[test]
fn status_reports_an_unsupported_host_enforcement_with_the_adapters_own_reason() {
    let h = Harness::start(|f| f);
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let output = h.aasm(&["status", "claude-code"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    let rendered = stdout(&output);
    assert!(
        rendered.contains("host_enforced"),
        "the ladder hid a rung instead of naming it:\n{rendered}"
    );
    assert!(
        rendered.contains("unsupported by this integration"),
        "an unsupported rung was not marked as unsupported:\n{rendered}"
    );
    assert!(
        rendered.contains("host enforcement is not available on this platform"),
        "the adapter's own reason was replaced by wording of the CLI's own:\n{rendered}"
    );
    assert!(
        rendered.contains("Exercised evidence") && rendered.contains("Read-back evidence"),
        "exercised and read-back evidence were not kept apart:\n{rendered}"
    );
    assert!(rendered.contains("last verification"), "{rendered}");
    assert!(
        rendered.contains("Runtime:"),
        "status did not report runtime connectivity"
    );
}

/// The defect this ticket was filed for, in the shape a macOS user meets it:
/// the adapter declares host enforcement **supported**, nothing has reached it
/// yet, and `status` used to answer "unavailable on this platform" — a claim
/// about the host that nobody established and that is false on the only
/// platform where the mechanism works.
#[test]
fn status_reports_a_supported_host_enforcement_as_reachable_never_as_unavailable() {
    let h = Harness::start(|f| f.supporting_host_enforcement());
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let output = h.aasm(&["status", "claude-code"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    let rendered = stdout(&output);
    assert!(
        rendered.contains("host_enforced"),
        "the ladder hid the rung entirely:\n{rendered}"
    );
    assert!(
        !rendered.contains("unavailable on this platform"),
        "a supported mechanism was reported as impossible on this host:\n{rendered}"
    );
    assert!(
        rendered.contains("--install-managed-settings"),
        "a reachable rung did not name the command that reaches it:\n{rendered}"
    );
    // Reachable is not reached. The rung must not read as protection that
    // exists — nothing has attested an endpoint-managed policy here.
    assert_eq!(
        ladder_mark(&rendered, "host_enforced"),
        "not active",
        "an available rung was rendered as though it had been measured:\n{rendered}"
    );
}

/// The mark `status` printed beside one ladder rung.
///
/// Read off the rendered table rather than the JSON, because the mark is the
/// thing a human actually reads and the thing AAASM-5454 got wrong.
fn ladder_mark(rendered: &str, level: &str) -> String {
    rendered
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(level))
        .unwrap_or_else(|| panic!("the ladder never named {level}:\n{rendered}"))
        .trim()
        .to_string()
}

#[test]
fn status_separates_exercised_evidence_from_read_back_in_json() {
    let h = Harness::start(|f| f);
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    assert_eq!(code(&h.aasm(&["verify", "claude-code"])), exit::SUCCESS);

    let output = h.aasm(&["status", "claude-code", "--output", "json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert!(!json["exercised_evidence"].as_array().expect("array").is_empty());
    assert!(json["read_back_evidence"].is_array());
    assert!(json["observed_at_unix_secs"].as_u64().is_some());
    let host = host_level(&json);
    assert_eq!(host["available"], serde_json::json!(false));
    assert_eq!(
        host["availability"],
        serde_json::json!("unsupported"),
        "an adapter that declared a refusal must not read as one that declared nothing"
    );
}

/// The `host_enforced` rung of a JSON status.
fn host_level(json: &serde_json::Value) -> &serde_json::Value {
    json["levels"]
        .as_array()
        .expect("levels")
        .iter()
        .find(|l| l["level"] == "host_enforced")
        .expect("host_enforced must be listed")
}

/// AAASM-5454's headline symptom: two surfaces of the same binary, on the same
/// host, in the same minute, contradicting each other about whether the rung is
/// reachable — and the discouraging one being the false one.
///
/// Both directions are asserted, because agreement that only holds when the
/// answer is "no" is what the bug already had.
#[test]
fn plan_and_status_agree_on_whether_host_enforcement_is_reachable() {
    for supported in [true, false] {
        let h = Harness::start(|f| if supported { f.supporting_host_enforcement() } else { f });
        assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

        let plan: serde_json::Value =
            serde_json::from_str(&stdout(&h.aasm(&["plan", "claude-code", "--output", "json"]))).expect("plan JSON");
        let status: serde_json::Value =
            serde_json::from_str(&stdout(&h.aasm(&["status", "claude-code", "--output", "json"])))
                .expect("status JSON");

        let plan_says_reachable = !plan["unsupported"]
            .as_array()
            .expect("unsupported")
            .iter()
            .any(|u| u["capability"] == "host_enforcement");
        let status_says_reachable = host_level(&status)["available"] == serde_json::json!(true);

        assert_eq!(
            plan_says_reachable, supported,
            "the plan disagreed with the adapter's declaration (supported={supported})"
        );
        assert_eq!(
            status_says_reachable, plan_says_reachable,
            "plan and status disagree about host enforcement (supported={supported}): \
             plan reachable={plan_says_reachable}, status reachable={status_says_reachable}"
        );
    }
}

/// Availability is a statement about a path. It must never carry an implication
/// that something was installed, exercised or attested — the three states stay
/// three, and none of them is `achieved`.
#[test]
fn a_reachable_rung_is_not_reported_as_a_measured_one() {
    let h = Harness::start(|f| f.supporting_host_enforcement());
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    let status: serde_json::Value =
        serde_json::from_str(&stdout(&h.aasm(&["status", "claude-code", "--output", "json"]))).expect("status JSON");
    let host = host_level(&status);
    assert_eq!(host["available"], serde_json::json!(true));
    assert_eq!(host["availability"], serde_json::json!("available"));
    assert_eq!(
        host["achieved"],
        serde_json::json!(false),
        "a reachable rung was reported as reached"
    );
    assert_ne!(
        status["achieved_level"],
        serde_json::json!("host_enforced"),
        "the ladder claimed a level no evidence supports"
    );
}

// ── drift and repair ─────────────────────────────────────────────────────────

#[test]
fn tampering_with_a_managed_key_drifts_and_repair_restores_only_what_aasm_owns() {
    let h = Harness::start(|f| f);
    std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    std::fs::write(&h.settings, r#"{"aasmManaged":false,"theme":"gruvbox"}"#).expect("tamper");
    let drifted = h.aasm(&["status", "claude-code"]);
    assert_eq!(code(&drifted), exit::DRIFTED, "{}", combined(&drifted));
    assert!(stdout(&drifted).contains("repair"), "{}", stdout(&drifted));

    let preview = h.aasm(&["repair", "claude-code", "--dry-run"]);
    assert_eq!(code(&preview), exit::DRIFTED, "{}", combined(&preview));
    assert!(
        stdout(&preview).contains("Nothing has been changed"),
        "{}",
        stdout(&preview)
    );
    assert!(
        h.settings_contents().expect("settings").contains("gruvbox"),
        "the dry run changed the file"
    );

    let repaired = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(code(&repaired), exit::SUCCESS, "{}", combined(&repaired));
    let after = h.settings_contents().expect("settings");
    assert!(
        after.contains("gruvbox"),
        "repair discarded the user's own edit: {after}"
    );
    assert!(
        after.contains(r#""aasmManaged":true"#),
        "repair did not restore the managed key: {after}"
    );
}

// ── remove ───────────────────────────────────────────────────────────────────

#[test]
fn remove_previews_then_restores_the_users_own_configuration() {
    let h = Harness::start(|f| f);
    std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    let installed = h.settings_contents().expect("settings");
    assert!(installed.contains("aasmManaged"));

    let preview = h.aasm(&["remove", "claude-code", "--dry-run"]);
    assert_eq!(code(&preview), exit::SUCCESS, "{}", combined(&preview));
    assert!(stdout(&preview).contains("Restoration actions"), "{}", stdout(&preview));
    assert_eq!(
        h.settings_contents().expect("settings"),
        installed,
        "the removal preview changed the file"
    );

    let removed = h.aasm(&["remove", "claude-code", "--yes"]);
    assert_eq!(code(&removed), exit::SUCCESS, "{}", combined(&removed));
    let after = h.settings_contents().expect("settings");
    assert!(after.contains("solarized"), "removal lost the user's own key: {after}");
    assert!(
        !after.contains("aasmManaged"),
        "removal left AASM's keys behind: {after}"
    );
}

/// Removing twice is a success. A teardown script that runs in a loop should
/// not have to special-case the run where there is nothing left to do.
#[test]
fn removing_twice_is_idempotent() {
    let h = Harness::start(|f| f);
    std::fs::write(&h.settings, r#"{"theme":"solarized"}"#).expect("seed");
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    assert_eq!(code(&h.aasm(&["remove", "claude-code", "--yes"])), exit::SUCCESS);

    let after_first = h.settings_contents().expect("settings");
    let second = h.aasm(&["remove", "claude-code", "--yes"]);
    assert_eq!(code(&second), exit::SUCCESS, "{}", combined(&second));
    assert!(
        stderr(&second).contains("no Agent Assembly integration to remove"),
        "{}",
        stderr(&second)
    );
    assert_eq!(
        h.settings_contents().expect("settings"),
        after_first,
        "the second removal changed the file"
    );
}

// ── exit codes ───────────────────────────────────────────────────────────────

/// Each outcome a caller might branch on must be reachable and distinct. If
/// two of these ever collapsed onto one code, a wrapper script would silently
/// start taking the wrong branch.
#[test]
fn each_outcome_produces_its_own_exit_code() {
    let h = Harness::start(|f| f.verifying(FixtureVerification::ReadBackOnly));

    let unknown = h.aasm(&["status", "not-a-real-tool"]);
    assert_eq!(code(&unknown), exit::UNSUPPORTED, "{}", combined(&unknown));
    assert!(stderr(&unknown).contains("known tools:"), "{}", stderr(&unknown));

    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);
    assert_eq!(code(&h.aasm(&["verify", "claude-code"])), exit::VERIFICATION_FAILED);
    assert_eq!(code(&h.aasm(&["install", "claude-code"])), exit::ABORTED);

    std::fs::write(&h.settings, r#"{"aasmManaged":false}"#).expect("tamper");
    assert_eq!(code(&h.aasm(&["status", "claude-code"])), exit::DRIFTED);
}

/// A stopped runtime is its own outcome, and `--no-autostart` is what makes it
/// observable instead of being papered over by a bootstrap.
#[test]
fn a_stopped_runtime_exits_runtime_unavailable_and_says_what_to_do() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    let output = cmd
        .args(["integrations", "list", "--no-autostart"])
        .env("AA_DEVINT_SOCKET", dir.path().join("absent.sock"))
        .env("AA_DEVINT_TOKEN_FILE", dir.path().join("absent.token"))
        .env("HOME", dir.path())
        .output()
        .expect("run aasm");

    assert_eq!(code(&output), exit::RUNTIME_UNAVAILABLE, "{}", combined(&output));
    let message = stderr(&output);
    assert!(message.contains("not running"), "{message}");
    assert!(message.contains("→"), "the error carried no remediation: {message}");
}

/// An unenrolled client is refused with something it can act on, and the
/// message never quotes a token — there is none to quote, which is the point.
#[test]
fn a_missing_enrolment_is_actionable_and_quotes_no_secret() {
    let h = Harness::start(|f| f);
    std::fs::remove_file(&h.token_file).expect("remove the token");
    let output = h.aasm(&["list"]);
    assert_ne!(code(&output), exit::SUCCESS);
    let message = stderr(&output);
    assert!(message.contains("not enrolled"), "{message}");
    assert!(message.contains("restart"), "{message}");
}

// ── output constraints ───────────────────────────────────────────────────────

/// The poisoned-fixture guard. The fixture renders a settings body containing
/// `LEAK_SENTINEL`; that body is real, is written to disk, and is what the
/// receipt fingerprints. No CLI output may contain it — not the report, not the
/// human table, not an error.
#[test]
fn no_command_output_carries_a_secret_from_a_poisoned_fixture() {
    let h = Harness::start(|f| f.poisoned());

    let mut seen_anything = false;
    for args in [
        vec!["list"],
        vec!["list", "--capabilities"],
        vec!["plan", "claude-code"],
        vec!["install", "claude-code", "--yes"],
        vec!["status", "claude-code"],
        vec!["verify", "claude-code"],
        vec!["repair", "claude-code", "--yes"],
        vec!["remove", "claude-code", "--dry-run"],
    ] {
        for format in ["table", "json", "yaml"] {
            let mut full = args.clone();
            full.extend_from_slice(&["--output", format]);
            let output = h.aasm(&full);
            let text = combined(&output);
            assert!(
                !text.contains(LEAK_SENTINEL),
                "`aasm integrations {}` leaked the settings body:\n{text}",
                full.join(" ")
            );
            seen_anything = true;
        }
    }
    assert!(seen_anything);

    // …and the sentinel really is in the settings the fixture wrote, so the
    // assertions above were looking for something that exists.
    let written = h.settings_contents().expect("the install wrote settings");
    assert!(
        written.contains(LEAK_SENTINEL),
        "the poisoned fixture never wrote its secret, so the guard proved nothing"
    );
}

/// Every command's machine-readable output must actually parse, in both
/// formats — a "stable JSON output" that a consumer cannot load is not stable.
#[test]
fn machine_readable_output_parses_for_every_command() {
    let h = Harness::start(|f| f);
    assert_eq!(code(&h.aasm(&["install", "claude-code", "--yes"])), exit::SUCCESS);

    for args in [
        vec!["list"],
        vec!["plan", "claude-code"],
        vec!["status", "claude-code"],
        vec!["verify", "claude-code"],
        vec!["repair", "claude-code", "--dry-run"],
        vec!["remove", "claude-code", "--dry-run"],
    ] {
        let mut json_args = args.clone();
        json_args.extend_from_slice(&["--output", "json"]);
        let output = h.aasm(&json_args);
        serde_json::from_str::<serde_json::Value>(&stdout(&output))
            .unwrap_or_else(|e| panic!("`{}` did not emit valid JSON: {e}\n{}", args.join(" "), stdout(&output)));

        let mut yaml_args = args.clone();
        yaml_args.extend_from_slice(&["--output", "yaml"]);
        let output = h.aasm(&yaml_args);
        serde_yaml::from_str::<serde_yaml::Value>(&stdout(&output))
            .unwrap_or_else(|e| panic!("`{}` did not emit valid YAML: {e}", args.join(" ")));
    }
}

/// Auto-start notices belong on stderr so a piped JSON run stays parseable.
#[test]
fn notices_and_prompts_never_contaminate_the_report_stream() {
    let h = Harness::start(|f| f);
    let output = h.aasm(&["install", "claude-code", "--output", "json"]);
    // The install aborts for want of a confirmation, and the *review* copy of
    // the plan goes to stderr — stdout must carry nothing but a report, and in
    // this case there is no report to carry.
    assert_eq!(code(&output), exit::ABORTED);
    assert!(
        stdout(&output).trim().is_empty(),
        "stdout carried a prompt or a notice:\n{}",
        stdout(&output)
    );
    assert!(stderr(&output).contains("Material changes"), "{}", stderr(&output));
}

// ── help ─────────────────────────────────────────────────────────────────────

#[test]
fn the_help_documents_every_subcommand_and_the_exit_codes() {
    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    let output = cmd.args(["integrations", "--help"]).output().expect("run");
    let help = stdout(&output);
    for verb in ["list", "plan", "install", "status", "verify", "repair", "remove"] {
        assert!(help.contains(verb), "{verb} is missing from --help:\n{help}");
    }

    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    let long = stdout(&cmd.args(["integrations", "help"]).output().expect("run"));
    for token in [
        "EXIT CODES",
        "verification_failed",
        "drifted",
        "unsupported",
        "incompatible",
    ] {
        assert!(long.contains(token), "{token} is missing from the long help:\n{long}");
    }
}

#[test]
fn every_subcommand_has_its_own_help() {
    for verb in ["list", "plan", "install", "status", "verify", "repair", "remove"] {
        let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
        let output = cmd.args(["integrations", verb, "--help"]).output().expect("run");
        assert!(output.status.success(), "`aasm integrations {verb} --help` failed");
        assert!(!stdout(&output).is_empty(), "{verb} has no help text");
    }
}

/// A sanity check on the harness itself: the settings path the fixture writes
/// is inside the temp directory, so no test can reach the developer's own
/// configuration even if it tried.
#[test]
fn the_harness_never_points_at_a_real_home_directory() {
    let h = Harness::start(|f| f);
    assert!(
        h.settings.starts_with(h.dir.path()),
        "the fixture's settings path escaped the temp directory"
    );
    assert!(Path::new(&h.socket).starts_with(h.dir.path()));
    assert!(Path::new(&h.token_file).starts_with(h.dir.path()));
}
