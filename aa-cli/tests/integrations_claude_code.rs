//! `aasm integrations … claude-code` driven end to end against the **native**
//! Claude Code integration over a real DI-API socket (AAASM-5281).
//!
//! # Why this exists next to `integrations_command.rs`
//!
//! That suite drives the CLI against `FixtureIntegration` — a stand-in wearing
//! the `ClaudeCode` label — which is right for pinning the command surface and
//! wrong for pinning the *tool*. Nothing there would notice if the real adapter
//! stopped materialising its trust material, stopped naming its scope, or
//! started writing to a file the receipt does not describe.
//!
//! This suite registers the same `claude_code_registration` the runtime does,
//! runs the compiled `aasm` binary against it, and asserts on what lands on
//! disk.
//!
//! # Safety
//!
//! Every root — `HOME`, `CLAUDE_CONFIG_DIR`, `AASM_STATE_DIR`, `AA_CA_DIR` — is
//! redirected into one temp directory **before** the integration is constructed,
//! in the test process and in the CLI's environment. Nothing reads or writes the
//! developer's real `~/.claude` or `~/.aa`, and no keychain operation is
//! performed. `nextest` runs each test in its own process, which is what makes
//! the process-wide redirection safe.
//!
//! # Skipping
//!
//! Detection runs against the real `claude` binary, so on a host without one
//! (Linux CI) every test prints `SKIP:` and returns. A skip is visible in the
//! output rather than looking like a pass.
//!
//! **This suite is the extreme case** (AAASM-5465): *every* test here is gated,
//! so on Linux CI the binary reports "5 passed" having asserted nothing at all.
//! Each skip is therefore also recorded in the shared evidence ledger, and
//! `.ci/test-evidence-summary.sh` nets those records against the runner's pass
//! count so a lane with zero substantive cases cannot read as a lane that
//! measured five.

use std::process::Output;
use std::sync::Arc;

use aa_core::integration::ReceiptStore;
use aa_runtime::devint::adapters::claude_code_integration;
use aa_runtime::devint::{DevIntServer, DevIntServerConfig, DevIntServices, EngineLifecycle, TokenStore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The evidence ledger, shared verbatim with the `aa-integration-tests` suites
/// that decline for the same reason (AAASM-5465).
///
/// Included by path rather than copied: one CI summary reads every suite's
/// records, and two implementations of "what a decline looks like" would drift
/// until the summary quietly stopped seeing one of them. The module deliberately
/// has no dependencies, so including it here costs `aa-cli` no dev-dependency.
///
/// Reaching outside the package directory is safe for the published tarball
/// because `.ci/strip-for-publish.sh` deletes this whole file before
/// `cargo workspaces publish` runs — the include can never become a dangling
/// path in a crates.io release.
#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

/// Locate the real `claude` binary, or declare the skip against `scenario`.
///
/// `scenario` is the test's own name: the ledger keys one record per scenario,
/// and a suite where every case declines has to be able to say *which* five.
fn require_claude(scenario: &str) -> bool {
    let found = std::process::Command::new("which")
        .arg("claude")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !found {
        let reason = "no `claude` binary on PATH (expected on Linux CI)";
        println!("SKIP [{scenario}]: {reason}");
        evidence::record(scenario, evidence::Measurement::ToolAbsent, reason);
    }
    found
}

struct Harness {
    dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    token_file: std::path::PathBuf,
    shutdown: CancellationToken,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Harness {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let run = dir.path().join("run");
        let claude_home = dir.path().join(".claude");
        let ca_dir = dir.path().join("aa").join("ca");
        std::fs::create_dir_all(&run).expect("run dir");
        std::fs::create_dir_all(&claude_home).expect("claude config dir");
        std::fs::create_dir_all(&ca_dir).expect("ca dir");
        // A CA the proxy would have written. Its contents are never validated
        // here — the assertions are that it is copied, pointed at and removed.
        std::fs::write(
            ca_dir.join("ca-cert.pem"),
            "-----BEGIN CERTIFICATE-----\nAAASM5281SMOKECA\n-----END CERTIFICATE-----\n",
        )
        .expect("ca pem");

        let socket = run.join("devint.sock");
        let token_file = run.join("devint.token");

        // Redirect every root the integration resolves from the environment
        // *before* constructing it — this is what keeps the smoke run off the
        // developer's live configuration.
        std::env::set_var("AA_DEVINT_TOKEN_FILE", &token_file);
        std::env::set_var("AA_DEVINT_SOCKET", &socket);
        std::env::set_var("HOME", dir.path());
        std::env::set_var("CLAUDE_CONFIG_DIR", &claude_home);
        std::env::set_var("AASM_STATE_DIR", dir.path().join("state"));
        std::env::set_var("AA_CA_DIR", &ca_dir);
        // AAASM-5298: the endpoint-managed surface is redirected into the temp
        // directory too. `MacOsAdminAuthority` refuses to elevate for anything
        // but the canonical `/Library/Application Support/ClaudeCode` path, so
        // this redirection cannot point an authorized write anywhere — it makes
        // the write unprivileged, and keeps the smoke run off the real path.
        std::env::set_var("AASM_CLAUDE_MANAGED_ROOT", dir.path().join("ClaudeCode"));

        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![claude_code_integration()],
            ReceiptStore::at(dir.path().join("state").join("integrations")),
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
            shutdown,
            server: Some(handle),
        }
    }

    fn aasm(&self, args: &[&str]) -> Output {
        let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
        cmd.arg("integrations")
            .args(args)
            .arg("--no-autostart")
            .env("AA_DEVINT_SOCKET", &self.socket)
            .env("AA_DEVINT_TOKEN_FILE", &self.token_file)
            .env("AASM_STATE_DIR", self.dir.path().join("state"))
            .env("HOME", self.dir.path())
            .env("CLAUDE_CONFIG_DIR", self.dir.path().join(".claude"))
            .env("AA_CA_DIR", self.dir.path().join("aa").join("ca"))
            .env("AASM_API_KEY", "");
        cmd.output().expect("run aasm")
    }

    fn settings(&self) -> Option<serde_json::Value> {
        let raw = std::fs::read_to_string(self.dir.path().join(".claude").join("settings.json")).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn ca_pem(&self) -> std::path::PathBuf {
        self.dir
            .path()
            .join("state")
            .join("integrations")
            .join("claude-code")
            .join("user")
            .join("aasm-proxy-ca.pem")
    }

    fn injected(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(
            self.dir
                .path()
                .join("state")
                .join("integrations")
                .join("claude-code")
                .join("user")
                .join("launch-env")
                .join(name),
        )
        .ok()
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

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The whole user journey, through the compiled binary.
#[test]
fn the_command_family_drives_the_native_claude_code_integration() {
    if !require_claude("the_command_family_drives_the_native_claude_code_integration") {
        return;
    }
    let h = Harness::start();

    // The user already has configuration of their own.
    std::fs::write(
        h.dir.path().join(".claude").join("settings.json"),
        r#"{"theme":"gruvbox"}"#,
    )
    .expect("seed settings");

    let list = h.aasm(&["list"]);
    assert!(list.status.success(), "{}", stderr(&list));
    assert!(stdout(&list).contains("claude-code"), "{}", stdout(&list));

    let plan = h.aasm(&["plan", "claude-code", "--scope", "user"]);
    assert!(plan.status.success(), "{}", stderr(&plan));
    let planned = stdout(&plan);
    for expected in [
        "write_managed_settings",
        "materialise_trust_material",
        "inject_launch_environment",
        "NODE_EXTRA_CA_CERTS",
        "configure_proxy",
        "manage_artifact",
        "run_protection_test",
        // The measured bypass, stated where a user approves the plan.
        "is not protected",
    ] {
        assert!(planned.contains(expected), "plan is missing {expected}:\n{planned}");
    }
    assert!(!h.ca_pem().exists(), "a plan must not put anything on disk:\n{planned}");

    let install = h.aasm(&["install", "claude-code", "--scope", "user", "--yes"]);
    println!(
        "--- aasm integrations install claude-code --scope user ---\n{}",
        stdout(&install)
    );
    assert!(install.status.success(), "{}", stderr(&install));
    // The ratified outcome, end to end: engine → DI-API v5 → CLI. A first
    // install writes the settings file, so `changed` is the only honest answer
    // (AAASM-5674).
    assert!(
        stdout(&install).contains("Applied as receipt") && stdout(&install).contains("changed"),
        "the install did not state its change outcome:\n{}",
        stdout(&install)
    );
    assert!(h.ca_pem().is_file(), "the proxy CA must be materialised");
    assert_eq!(
        h.injected("NODE_EXTRA_CA_CERTS").as_deref(),
        Some(h.ca_pem().display().to_string().as_str()),
        "condition C1: the governed launch must carry the CA variable"
    );
    assert!(h.injected("HTTPS_PROXY").is_some());
    let settings = h.settings().expect("settings survive");
    assert_eq!(settings["theme"], serde_json::json!("gruvbox"));
    assert_eq!(settings["permissions"]["defaultMode"], serde_json::json!("default"));
    let settings_after_install = settings.clone();

    // …and the second install reaches the same end state without touching it.
    // Both exit 0, so the outcome is the only thing that tells them apart —
    // which is the whole of the AAASM-5499 contract, now covering `install`.
    let reinstall = h.aasm(&["install", "claude-code", "--scope", "user", "--yes", "--output", "json"]);
    assert!(reinstall.status.success(), "{}", stderr(&reinstall));
    let report: serde_json::Value = serde_json::from_str(&stdout(&reinstall)).expect("json report");
    println!("--- aasm integrations install (repeat) ---\n{report:#}");
    assert_eq!(
        report["outcome"],
        serde_json::json!("unchanged"),
        "a repeated install must report the no-op it performed"
    );
    assert_eq!(report["outcome_unknown"], serde_json::Value::Null);
    assert_eq!(
        h.settings().expect("settings survive"),
        settings_after_install,
        "the repeated install reported `unchanged` while changing the settings"
    );

    let status = h.aasm(&["status", "claude-code"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let rendered = stdout(&status);
    // Printed so a run with `--success-output immediate` is a readable record of
    // the operator journey, not just a green tick.
    println!("--- aasm integrations status claude-code ---\n{rendered}");
    assert!(rendered.contains("claude-code"), "{rendered}");
    assert!(
        rendered.contains("Host Enforced") || rendered.contains("host_enforced"),
        "the unreachable rung must be reported, not omitted:\n{rendered}"
    );

    // Verification cannot pass without an adjudicating probe, and the CLI's exit
    // code says so rather than reporting a protection that was never measured.
    let verify = h.aasm(&["verify", "claude-code"]);
    println!("--- aasm integrations verify claude-code ---\n{}", stdout(&verify));
    assert_eq!(
        verify.status.code(),
        Some(6),
        "verify must exit verification_failed when the protected path was not exercised:\n{}",
        stdout(&verify)
    );

    // Drift and repair.
    let mut doc = h.settings().expect("settings");
    doc["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    std::fs::write(
        h.dir.path().join(".claude").join("settings.json"),
        serde_json::to_string_pretty(&doc).expect("json"),
    )
    .expect("tamper");

    let drifted = h.aasm(&["status", "claude-code"]);
    assert_eq!(drifted.status.code(), Some(5), "{}", stdout(&drifted));

    let repair = h.aasm(&["repair", "claude-code", "--yes"]);
    assert!(repair.status.success(), "{}", stderr(&repair));
    let repaired = h.settings().expect("settings");
    assert_eq!(repaired["permissions"]["defaultMode"], serde_json::json!("default"));
    assert_eq!(repaired["theme"], serde_json::json!("gruvbox"));

    // The removal preview must read as what removal does. A settings step's
    // reversal is "restore these keys", not "delete this file", and rendering it
    // as an artifact removal would tell the user their configuration is about to
    // be deleted.
    let preview = h.aasm(&["remove", "claude-code"]);
    let previewed = stdout(&preview);
    assert!(
        previewed.contains("restore the four Agent Assembly-owned keys"),
        "{previewed}"
    );
    assert!(
        !previewed.contains("run-protection-test") && !previewed.contains("run_protection_test"),
        "a probe mutated nothing and must not appear in a removal preview:\n{previewed}"
    );

    // Removal restores what was there before.
    let remove = h.aasm(&["remove", "claude-code", "--yes"]);
    println!("--- aasm integrations remove claude-code ---\n{}", stdout(&remove));
    assert!(remove.status.success(), "{}", stderr(&remove));
    assert!(!h.ca_pem().exists(), "the copied CA must be gone");
    assert!(h.injected("NODE_EXTRA_CA_CERTS").is_none());
    let restored = h.settings().expect("settings");
    assert_eq!(restored["theme"], serde_json::json!("gruvbox"));
    assert!(restored.get("permissions").is_none(), "{restored}");
}

/// AAASM-5454, against the **real** adapter: `plan` and `status` must not
/// contradict each other about whether `Host Enforced` can be reached here.
///
/// The bug was reported from exactly this pair, one after the other on one
/// macOS host: `plan --install-managed-settings` answered
/// `planned level: host_enforced` while `status` answered
/// `unavailable on this platform`. The two surfaces read the same adapter
/// declaration, so the assertion is agreement rather than a fixed verdict —
/// which is also what keeps it honest on a Linux host that happens to have the
/// tool installed, where the adapter genuinely answers unsupported.
#[test]
fn status_and_plan_agree_with_the_real_adapter_about_host_enforcement() {
    if !require_claude("status_and_plan_agree_with_the_real_adapter_about_host_enforcement") {
        return;
    }
    let h = Harness::start();
    assert!(h
        .aasm(&["install", "claude-code", "--scope", "user", "--yes"])
        .status
        .success());

    let status: serde_json::Value =
        serde_json::from_str(&stdout(&h.aasm(&["status", "claude-code", "--output", "json"]))).expect("status JSON");
    let host = status["levels"]
        .as_array()
        .expect("levels")
        .iter()
        .find(|l| l["level"] == "host_enforced")
        .expect("the rung must be named, never omitted");
    let reachable = host["available"] == serde_json::json!(true);

    let plan = h.aasm(&["plan", "claude-code", "--install-managed-settings"]);
    let planned = format!("{}{}", stdout(&plan), stderr(&plan));
    let plan_says_reachable = planned.contains("planned level:   host_enforced");
    assert_eq!(
        reachable, plan_says_reachable,
        "plan and status disagree about host enforcement.\n--- status ---\n{status:#}\n--- plan ---\n{planned}"
    );

    let rendered = stdout(&h.aasm(&["status", "claude-code"]));
    if reachable {
        assert!(
            !rendered.contains("unavailable on this platform"),
            "a mechanism this adapter supports was reported as impossible here:\n{rendered}"
        );
        assert!(
            rendered.contains("--install-managed-settings"),
            "a reachable rung did not name the command that reaches it:\n{rendered}"
        );
        assert_eq!(
            host["achieved"],
            serde_json::json!(false),
            "nothing attested an endpoint-managed policy, so the rung is not reached"
        );
    }

    // macOS is the platform the mechanism exists for, and the one the defect
    // told it was impossible. `MacOsAdminAuthority::availability` answers
    // `Unavailable` only off macOS; a non-terminal stdin is `NonInteractive`,
    // which is a runtime condition and not a missing capability.
    if cfg!(target_os = "macos") {
        assert!(
            reachable,
            "macOS must report host enforcement as reachable:\n{status:#}"
        );
    }
}

/// `--scope managed` alone is not the explicit opt-in the privileged write needs.
#[test]
fn a_managed_scope_install_is_refused_and_names_the_flag_that_opts_in() {
    if !require_claude("a_managed_scope_install_is_refused_and_names_the_flag_that_opts_in") {
        return;
    }
    let h = Harness::start();
    let out = h.aasm(&["plan", "claude-code", "--scope", "managed"]);
    assert!(!out.status.success());
    let message = stderr(&out);
    assert!(message.contains("explicit opt-in"), "{message}");
    assert!(message.contains("--install-managed-settings"), "{message}");
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "a refused plan must write nothing"
    );
}

/// The plan discloses everything before anything is authorized — and a plan
/// still changes nothing.
#[test]
fn the_managed_install_plan_discloses_path_content_diff_backup_and_rollback() {
    if !require_claude("the_managed_install_plan_discloses_path_content_diff_backup_and_rollback") {
        return;
    }
    let h = Harness::start();
    let out = h.aasm(&["plan", "claude-code", "--install-managed-settings"]);
    let rendered = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- aasm integrations plan --install-managed-settings ---\n{rendered}");
    assert!(out.status.success(), "{rendered}");

    assert!(rendered.contains("settings scope:  managed"), "{rendered}");
    assert!(rendered.contains("CONSENT REQUIRED"), "{rendered}");
    assert!(rendered.contains("administrator authorization"), "{rendered}");
    assert!(rendered.contains("managed-settings.json"), "{rendered}");
    assert!(rendered.contains("disableBypassPermissionsMode"), "{rendered}");
    assert!(
        rendered.contains("the exact content that will be written"),
        "{rendered}"
    );
    assert!(rendered.contains("integrations remove claude-code"), "{rendered}");
    assert!(rendered.contains("Nothing has been changed"), "{rendered}");
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "a plan must write nothing"
    );
}

/// A non-interactive run fails immediately rather than blocking on a credential
/// prompt nobody can answer — and reports it as Unavailable, not as a success.
#[test]
fn a_non_interactive_managed_install_fails_safely_instead_of_waiting() {
    if !require_claude("a_non_interactive_managed_install_fails_safely_instead_of_waiting") {
        return;
    }
    let h = Harness::start();
    let out = h.aasm(&["install", "claude-code", "--install-managed-settings", "--yes"]);
    let message = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- aasm integrations install --install-managed-settings --yes ---\n{message}");
    assert!(!out.status.success(), "{message}");
    assert!(
        message.contains("Unavailable") || message.contains("Permission Required"),
        "a refusal must stay a refusal, in those words: {message}"
    );
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "nothing may be written when authorization could not be obtained"
    );
}

/// And without `--yes`, a non-interactive run does not even reach the service.
#[test]
fn a_managed_install_without_confirmation_changes_nothing() {
    if !require_claude("a_managed_install_without_confirmation_changes_nothing") {
        return;
    }
    let h = Harness::start();
    let out = h.aasm(&["install", "claude-code", "--install-managed-settings"]);
    let message = format!("{}{}", stdout(&out), stderr(&out));
    assert!(!out.status.success(), "{message}");
    assert!(message.contains("nothing was changed"), "{message}");
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "{message}"
    );
}
