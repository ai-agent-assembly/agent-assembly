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
//! so on Linux CI the binary reports every test as passed having asserted
//! nothing at all.
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

    /// Stop the service and start a fresh one over the same socket, the same
    /// receipt store and the same roots — a daemon restart, with nothing else
    /// changed.
    ///
    /// The new service is constructed while this process's working directory is
    /// `boot_cwd`, which is how a restart in a real deployment picks up a new
    /// directory: whatever launched it. A caller's project binding must not move
    /// when that happens (AAASM-5913).
    fn restart_service_from(&mut self, boot_cwd: &std::path::Path) {
        self.shutdown.cancel();
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket);

        let prior = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(boot_cwd).expect("chdir to the new boot directory");
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![claude_code_integration()],
            ReceiptStore::at(self.dir.path().join("state").join("integrations")),
        ));
        std::env::set_current_dir(prior).expect("restore cwd");

        let tokens = TokenStore::new();
        aa_runtime::devint::enrol_local_client(&tokens, "aasm", aa_core::integration::now_unix_secs()).expect("enrol");
        let services = DevIntServices::new(lifecycle, tokens, Arc::new(aa_runtime::devint::audit::TracingAuditSink));

        let shutdown = CancellationToken::new();
        let server_token = shutdown.clone();
        let server_config = DevIntServerConfig {
            socket_path: self.socket.clone(),
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
        while !self.socket.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(self.socket.exists(), "the restarted server never bound its socket");
        self.shutdown = shutdown;
        self.server = Some(handle);
    }

    /// Run `aasm` from `cwd`, against this harness's already-running service.
    ///
    /// # Why the working directory has to be the *only* difference (AAASM-5913)
    ///
    /// A test that autostarts a fresh service and then plans from that same
    /// directory passes against the defective code: `ProcessSpawner::command()`
    /// sets no working directory, so the autostarted daemon inherits the caller's,
    /// and reading the daemon's directory happens to give the right answer. The
    /// defect only shows when a *second* caller, in a *different* directory,
    /// reaches an *already-running* service — which is what this does and what
    /// `Harness` exists to arrange.
    fn aasm_in(&self, cwd: &std::path::Path, args: &[&str]) -> Output {
        let mut cmd = self.command(args);
        cmd.current_dir(cwd);
        cmd.output().expect("run aasm")
    }

    fn aasm(&self, args: &[&str]) -> Output {
        self.command(args).output().expect("run aasm")
    }

    fn command(&self, args: &[&str]) -> assert_cmd::Command {
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
        cmd
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

/// Sets this process's working directory and puts the previous one back on drop.
///
/// `nextest` gives each test its own process, so a leaked working directory costs
/// nothing there. Under plain `cargo test` all of these tests share one process,
/// and a test that leaves the directory inside a temp directory it then deletes
/// makes every *later* test's `aasm` child unable to resolve a directory at all —
/// which surfaces as "Claude Code is not installed on this host" in a test that
/// has nothing to do with directories.
struct Cwd(std::path::PathBuf);

impl Cwd {
    fn set(to: &std::path::Path) -> Self {
        let previous = std::env::current_dir().expect("the current directory must be readable");
        std::env::set_current_dir(to).unwrap_or_else(|e| panic!("chdir to {}: {e}", to.display()));
        Self(previous)
    }
}

impl Drop for Cwd {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
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

/// AAASM-5906/5907, Isolation test F: a `--scope project` install must leave
/// no trace at User scope (would-be machine-wide `$HOME/.claude/settings.json`)
/// or Managed scope — the whole point of the scope existing.
///
/// The project root reaches the service in the `plan` request the `aasm` child
/// process sends, resolved from *that child's* own directory (AAASM-5913). This
/// test leaves the child in this process's directory, so it is the weak,
/// same-directory arrangement — it says nothing about *which* project is chosen
/// and would pass against the defective code. The tests further down make that
/// choice observable; this one is only about scope containment.
///
/// The positive control is the same install run at `--scope user` in the same
/// test, on the same harness: it proves this assertion machinery can actually
/// see a settings file that *was* written, not merely that nothing exists on a
/// harness that never writes anything (the grep-for-absence trap this repo's
/// own review conventions warn against).
#[test]
fn project_scope_install_stays_out_of_home_and_managed_scope() {
    if !require_claude("project_scope_install_stays_out_of_home_and_managed_scope") {
        return;
    }
    let project = tempfile::tempdir().expect("project tempdir");
    let _cwd = Cwd::set(project.path());

    let h = Harness::start();
    let install = h.aasm(&["install", "claude-code", "--scope", "project", "--yes"]);
    assert!(install.status.success(), "{}", stderr(&install));

    assert!(
        project.path().join(".claude").join("settings.json").is_file(),
        "the project-scope install must write into the project root:\n{}",
        stdout(&install)
    );
    assert!(
        !h.dir.path().join(".claude").join("settings.json").exists(),
        "a project-scope install must not also write $HOME/.claude/settings.json — that write would \
         make every unrelated Claude Code session on this machine see AASM's managed keys"
    );
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "a project-scope install must never touch the managed-settings surface"
    );

    // Positive control: the *same* install, at the machine-wide default scope,
    // on a fresh harness (installs are not idempotent-across-scope on one
    // receipt store in a way this test needs to reason about) — proves the
    // "$HOME/.claude/settings.json exists" check above is capable of failing.
    let h_user = Harness::start();
    let user_install = h_user.aasm(&["install", "claude-code", "--scope", "user", "--yes"]);
    assert!(user_install.status.success(), "{}", stderr(&user_install));
    assert!(
        h_user.dir.path().join(".claude").join("settings.json").is_file(),
        "control failed: a --scope user install must write $HOME/.claude/settings.json, or the \
         negative assertions above are not proving anything"
    );
}

// ---------------------------------------------------------------------------
// AAASM-5913: which project a `--scope project` lifecycle call is about
//
// # The defect, and why it is severe
//
// A project-scope `settings.json` is a **checked-in, shared** file. The service
// that executed these calls resolved "the project" from `std::env::current_dir()`
// at construction time — its own, as a long-lived daemon shared by every client
// on the host. So `aasm integrations install --scope project` run from project B
// merged Agent Assembly's managed keys into project A's version-controlled
// settings file, in a repository the user never named, and the binding changed
// every time the daemon was restarted.
//
// # Why these tests are shaped the way they are
//
// A test that autostarts a fresh service and then plans from that same directory
// **passes against the defective code**: `ProcessSpawner::command()` sets no
// working directory, so an autostarted daemon inherits the caller's and reading
// the daemon's directory accidentally gives the right answer. Every test below
// therefore arranges the one situation that separates the two implementations —
// a second caller, in a different directory, against an *already-running*
// service — by setting this process's directory to project A *before*
// `Harness::start()` constructs the engine, and then invoking `aasm` from project
// B with [`Harness::aasm_in`].
//
// Each test also carries a positive control, because every central claim here is
// an *absence* ("nothing was written in A") and an absence proves nothing on a
// harness that writes nothing at all.
// ---------------------------------------------------------------------------

/// A project root with a `.claude` directory already in it, as a real checkout
/// that has used Claude Code would have.
///
/// The root is kept in canonical form. `tempfile` hands back `/var/folders/…` on
/// macOS while the `aasm` child process reports its own directory as the resolved
/// `/private/var/folders/…`, and these tests compare the two.
struct Project {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
}

impl Project {
    fn new(label: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix(&format!("aasm-5913-{label}-"))
            .tempdir()
            .expect("project tempdir");
        std::fs::create_dir_all(dir.path().join(".claude")).expect("project .claude");
        let root = dir.path().canonicalize().expect("canonical project root");
        Self { _dir: dir, root }
    }

    fn path(&self) -> &std::path::Path {
        &self.root
    }
}

fn project(label: &str) -> Project {
    Project::new(label)
}

fn project_settings(root: &std::path::Path) -> Option<serde_json::Value> {
    let raw = std::fs::read_to_string(root.join(".claude").join("settings.json")).ok()?;
    serde_json::from_str(&raw).ok()
}

/// The settings file a plan says it will write, read off the plan itself.
fn planned_settings_path(out: &Output) -> String {
    let report: serde_json::Value = serde_json::from_str(&stdout(out)).expect("json plan report");
    let steps = report["steps"].as_array().expect("plan steps");
    let step = steps
        .iter()
        .find(|s| s["action_kind"] == serde_json::json!("write_managed_settings"))
        .unwrap_or_else(|| panic!("no settings step in the plan:\n{report:#}"));
    step["artifact_paths"][0]
        .as_str()
        .unwrap_or_else(|| panic!("the settings step names no path:\n{report:#}"))
        .to_string()
}

/// Matrix case 1, 2 and 3. The service boots in project A; the caller is in
/// project B. B is written, A is not, and the machine-wide user surface is not.
#[test]
fn a_project_scope_install_reaches_the_callers_project_and_not_the_services() {
    if !require_claude("a_project_scope_install_reaches_the_callers_project_and_not_the_services") {
        return;
    }
    let a = project("service-boot-project-a");
    let b = project("caller-project-b");

    // The service's directory. Pre-fix this is the project every project-scope
    // call resolved to, whoever asked.
    let _cwd = Cwd::set(a.path());
    let h = Harness::start();

    // The caller's directory. Nothing else about this invocation differs.
    let install = h.aasm_in(b.path(), &["install", "claude-code", "--scope", "project", "--yes"]);
    println!(
        "--- aasm integrations install --scope project (caller in B) ---\n{}{}",
        stdout(&install),
        stderr(&install)
    );
    assert!(install.status.success(), "{}", stderr(&install));

    // 1. B — the caller's project — is the one that changed.
    let written = project_settings(b.path())
        .unwrap_or_else(|| panic!("the caller's own project was not written:\n{}", stdout(&install)));
    assert_eq!(
        written["permissions"]["defaultMode"],
        serde_json::json!("default"),
        "the caller's project settings do not carry the managed keys: {written}"
    );

    // 2. A — the service's directory — is untouched. This is the checked-in file
    //    in a repository the user never named.
    assert_eq!(
        project_settings(a.path()),
        None,
        "the project the *service* was started in was written; that file is checked in, and its \
         repository was never named by this caller"
    );

    // 3. Neither is the machine-wide user surface, nor the administrator one.
    assert!(
        !h.dir.path().join(".claude").join("settings.json").exists(),
        "a project-scope install must not also write $HOME/.claude/settings.json"
    );
    assert!(
        !h.dir.path().join("ClaudeCode").join("managed-settings.json").exists(),
        "a project-scope install must never touch the managed-settings surface"
    );

    // Positive control for all three absences: the same harness, at user scope,
    // does write $HOME/.claude/settings.json — so these assertions are capable of
    // failing.
    let user = h.aasm_in(b.path(), &["install", "claude-code", "--scope", "user", "--yes"]);
    assert!(user.status.success(), "{}", stderr(&user));
    assert!(
        h.dir.path().join(".claude").join("settings.json").is_file(),
        "control failed: a --scope user install must write $HOME/.claude/settings.json, so the \
         absence assertions above are not proving anything"
    );
    assert_eq!(
        project_settings(a.path()),
        None,
        "not even a user-scope install may write the service's project"
    );
}

/// Matrix case 6. Two callers, in two projects, against one service. Each plan
/// names its own project and neither names the other's or the service's.
#[test]
fn two_project_roots_against_one_service_do_not_cross_contaminate() {
    if !require_claude("two_project_roots_against_one_service_do_not_cross_contaminate") {
        return;
    }
    let a = project("service-boot-project-a");
    let b = project("caller-project-b");
    let c = project("caller-project-c");

    let _cwd = Cwd::set(a.path());
    let h = Harness::start();

    let plan_args = ["plan", "claude-code", "--scope", "project", "--output", "json"];
    let from_b = h.aasm_in(b.path(), &plan_args);
    assert!(from_b.status.success(), "{}", stderr(&from_b));
    let from_c = h.aasm_in(c.path(), &plan_args);
    assert!(from_c.status.success(), "{}", stderr(&from_c));

    let path_b = planned_settings_path(&from_b);
    let path_c = planned_settings_path(&from_c);
    println!("--- planned settings paths ---\nB: {path_b}\nC: {path_c}");

    assert!(
        path_b.starts_with(&b.path().display().to_string()),
        "the plan authored for the caller in B names {path_b}"
    );
    assert!(
        path_c.starts_with(&c.path().display().to_string()),
        "the plan authored for the caller in C names {path_c}"
    );
    assert_ne!(
        path_b, path_c,
        "two callers in two projects were handed the same destination"
    );

    // Interleaving them proves the service holds no per-project state that the
    // second call could inherit: B, then C, then B again.
    let again = h.aasm_in(b.path(), &plan_args);
    assert!(again.status.success(), "{}", stderr(&again));
    assert_eq!(
        planned_settings_path(&again),
        path_b,
        "a caller's destination changed because another caller had asked in between"
    );

    // And the writes land the same way the plans said they would.
    for (label, root) in [("B", b.path()), ("C", c.path())] {
        let out = h.aasm_in(root, &["install", "claude-code", "--scope", "project", "--yes"]);
        assert!(out.status.success(), "install from {label}: {}", stderr(&out));
        assert!(
            project_settings(root).is_some(),
            "the install from {label} did not write {label}"
        );
    }
    assert_eq!(
        project_settings(a.path()),
        None,
        "two project-scope installs, neither of them in A, wrote A"
    );

    // The read path, on the state those two installs leave behind. There is
    // exactly one project-scope receipt slot per tool per host, so C's install
    // took the slot B's had — this host can hold two project *installs* but only
    // one project *receipt*, which is a capacity limitation and not this fix.
    //
    // What this fix owns is which of the two answers get. C, whose receipt is the
    // stored one, is answered. B is **refused**, and that is the point: with the
    // caller's project unstated, B was told the protection C had installed was
    // its own, and `repair`/`remove` from B would have acted on C's files. A
    // refusal is the honest answer available to a host that can only remember
    // one, and it is the answer that does not write to the wrong repository.
    let c_status = h.aasm_in(c.path(), &["status", "claude-code"]);
    assert!(
        c_status.status.success(),
        "the project whose receipt is stored must be answered:\n{}",
        stderr(&c_status)
    );
    let b_status = h.aasm_in(b.path(), &["status", "claude-code"]);
    assert!(
        !b_status.status.success(),
        "B was told C's project-scope install was its own:\n{}",
        stdout(&b_status)
    );
}

/// Matrix cases 4, 5 and 7, on the **read** path: `status`, `verify`, `repair`
/// and `remove`.
///
/// The install writes B while the service is booted in A. The service is then
/// restarted in C, so the process that answers every read below is not the one
/// that authored the install and holds no memory of it. From then on the only
/// thing that varies is the directory the *caller* is in:
///
/// | caller | expected |
/// |---|---|
/// | B — the project that was installed | answers about B, drift included |
/// | D — an unrelated project | refuses, and writes nothing |
///
/// That pair is each other's control. Same service, same receipt, same verb,
/// same moment; one answers and one refuses, which is only possible if the
/// caller's own project is what decides. Pre-fix both came from the daemon's
/// working directory, so both would have answered about B — and `repair` and
/// `remove`, run by a developer standing in D, would have written to and
/// deleted from a *different* repository's checked-in configuration.
#[test]
fn a_restarted_service_answers_the_callers_project_and_refuses_a_strangers() {
    if !require_claude("a_restarted_service_answers_the_callers_project_and_refuses_a_strangers") {
        return;
    }
    let a = project("service-boot-project-a");
    let b = project("caller-project-b");
    let c = project("service-reboot-project-c");
    let d = project("unrelated-project-d");

    let _cwd = Cwd::set(a.path());
    let mut h = Harness::start();

    let install = h.aasm_in(b.path(), &["install", "claude-code", "--scope", "project", "--yes"]);
    assert!(install.status.success(), "{}", stderr(&install));
    let installed = project_settings(b.path()).expect("B was written");

    // The daemon goes away and comes back somewhere else entirely — the ordinary
    // consequence of a machine reboot or an `aasm daemon restart`. Nothing about
    // which project B's install is for may move with it.
    h.restart_service_from(c.path());

    let mut drifted = installed.clone();
    drifted["permissions"]["defaultMode"] = serde_json::json!("bypassPermissions");
    let tamper = || {
        std::fs::write(
            b.path().join(".claude").join("settings.json"),
            serde_json::to_string_pretty(&drifted).expect("json"),
        )
        .expect("tamper with B");
    };
    tamper();

    // The caller in B reaches B, across the restart, and sees the drift in it.
    let from_b = h.aasm_in(b.path(), &["status", "claude-code"]);
    assert_eq!(
        from_b.status.code(),
        Some(5),
        "the restarted service must still be reading B's file for a caller in B, and so must see \
         the drift:\n{}{}",
        stdout(&from_b),
        stderr(&from_b)
    );

    // The caller in D is somewhere else, and is told so rather than told about B.
    // Reporting B here is the disclosure half of the defect: it tells a developer
    // that the repository they are standing in is protected when it is not.
    let from_d = h.aasm_in(d.path(), &["status", "claude-code"]);
    println!(
        "--- aasm integrations status (caller in D, install is B's) ---\n{}{}",
        stdout(&from_d),
        stderr(&from_d)
    );
    assert!(
        !from_d.status.success(),
        "a caller in an unrelated project was answered about somebody else's:\n{}",
        stdout(&from_d)
    );
    let refusal = format!("{}{}", stdout(&from_d), stderr(&from_d));
    assert!(
        refusal.contains("belongs to another project"),
        "the refusal must say what is wrong:\n{refusal}"
    );
    assert!(
        !refusal.contains(&b.path().display().to_string()),
        "the refusal disclosed the other project's path, which this caller did not ask about and is \
         not owed:\n{refusal}"
    );

    // And the two mutating read-path verbs refuse *before* touching anything.
    // These are the assertions the severity rests on: B's file is checked in.
    for verb in ["repair", "remove"] {
        let out = h.aasm_in(d.path(), &[verb, "claude-code", "--yes"]);
        println!(
            "--- aasm integrations {verb} (caller in D) ---\n{}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            !out.status.success(),
            "`{verb}` run from an unrelated project acted on somebody else's:\n{}",
            stdout(&out)
        );
        assert_eq!(
            project_settings(b.path()).as_ref(),
            Some(&drifted),
            "`{verb}` from D changed B — the refusal was reported but not enforced"
        );
    }
    // A refusal that also deleted the file would satisfy the equality above by
    // way of `None == None`; assert the file itself is still there.
    assert!(
        b.path().join(".claude").join("settings.json").is_file(),
        "a refused `remove` deleted another project's settings file"
    );

    // `repair` from B, the project it is for, does the work.
    let repair = h.aasm_in(b.path(), &["repair", "claude-code", "--yes"]);
    println!("--- aasm integrations repair (caller in B) ---\n{}", stdout(&repair));
    assert!(repair.status.success(), "{}", stderr(&repair));
    assert_eq!(
        project_settings(b.path()).expect("B still exists"),
        installed,
        "the repair did not restore the project the install was for"
    );
    for (label, root) in [("A", a.path()), ("C", c.path()), ("D", d.path())] {
        assert_eq!(
            project_settings(root),
            None,
            "the repair wrote {label} — a project that is not the one the receipt names"
        );
    }
    assert!(
        !h.dir.path().join(".claude").join("settings.json").exists(),
        "the repair fell back to the machine-wide user surface"
    );

    // `verify` reads the same binding: from B it reaches a real file and reports
    // on it, and from D it refuses like the rest.
    let verify = h.aasm_in(b.path(), &["verify", "claude-code", "--output", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&verify)).expect("json verify report");
    println!("--- aasm integrations verify (caller in B) ---\n{report:#}");
    assert_ne!(
        report["outcome"],
        serde_json::json!("failed"),
        "verify reported the receipted artifacts as mismatched, which is what reading the wrong \
         project's file looks like:\n{report:#}"
    );
    assert!(
        !h.aasm_in(d.path(), &["verify", "claude-code"]).status.success(),
        "verify answered a caller in an unrelated project"
    );
}

/// Matrix case 7, stated on its own: the project a read verb is about comes from
/// the request, and a service that has *just* been asked about one project does
/// not carry it into the next caller's answer.
///
/// The interleaving is what makes this more than a repeat of the test above.
/// B is asked, then D, then B again: if anything about the first answer were
/// retained — a cached root, a last-seen project, a lazily-initialised field —
/// the third call is where it would show, and the second is where a stale one
/// would be handed to the wrong caller.
///
/// The `remove` at the end is the reason this matters beyond disclosure. A
/// project-scope receipt records the settings file it wrote; `remove` restores
/// and deletes exactly those paths. Getting the project wrong here is a write to
/// another repository's checked-in configuration, so `remove` is only allowed
/// from the project it is for — and after it, that project's own file is back to
/// what it was before the install.
#[test]
fn interleaved_callers_each_get_their_own_project_and_no_stale_one() {
    if !require_claude("interleaved_callers_each_get_their_own_project_and_no_stale_one") {
        return;
    }
    let a = project("service-boot-project-a");
    let b = project("caller-project-b");
    let d = project("unrelated-project-d");

    let _cwd = Cwd::set(a.path());
    let h = Harness::start();

    // B's project has configuration of its own, so removal has something to
    // restore *to* — an empty file proves nothing about what was preserved.
    std::fs::write(b.path().join(".claude").join("settings.json"), r#"{"theme":"gruvbox"}"#)
        .expect("seed B's settings");

    let install = h.aasm_in(b.path(), &["install", "claude-code", "--scope", "project", "--yes"]);
    assert!(install.status.success(), "{}", stderr(&install));

    let answered = |out: &Output| out.status.success();
    let first = h.aasm_in(b.path(), &["status", "claude-code"]);
    let stranger = h.aasm_in(d.path(), &["status", "claude-code"]);
    let again = h.aasm_in(b.path(), &["status", "claude-code"]);
    assert!(answered(&first), "B was refused its own project:\n{}", stderr(&first));
    assert!(
        !answered(&stranger),
        "D was answered about B's project:\n{}",
        stdout(&stranger)
    );
    assert!(
        answered(&again),
        "B's own project became unreachable because D had asked in between:\n{}",
        stderr(&again)
    );

    // The reverse direction: a refused caller must not leave its project behind
    // either. D asked last, and B is still the project that gets removed.
    let remove = h.aasm_in(b.path(), &["remove", "claude-code", "--yes"]);
    println!("--- aasm integrations remove (caller in B) ---\n{}", stdout(&remove));
    assert!(remove.status.success(), "{}", stderr(&remove));
    let restored = project_settings(b.path()).expect("B's own settings file survives removal");
    assert_eq!(
        restored["theme"],
        serde_json::json!("gruvbox"),
        "removal did not restore what B had before the install: {restored}"
    );
    assert!(
        restored.get("permissions").is_none(),
        "removal left AASM's managed keys in B: {restored}"
    );
    assert_eq!(
        project_settings(d.path()),
        None,
        "the removal wrote D — the project of the caller that was refused"
    );
    assert_eq!(
        project_settings(a.path()),
        None,
        "the removal wrote the service's project"
    );
}
