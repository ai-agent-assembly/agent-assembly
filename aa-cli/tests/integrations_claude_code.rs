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
//! performed. `nextest` runs each test in its own process, so the redirection
//! never observes another test there; under plain `cargo test`, where every test
//! in this file shares one process, `Harness` holds
//! [`aa_cli::env_guard::lock`] for its entire lifetime (AAASM-5989) so a second
//! `Harness` under construction on another thread blocks until the first is
//! dropped, instead of racing it for the same globals.
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
use aa_devtool_claude_code::managed_settings::testing::FakeAuthority;
use aa_devtool_claude_code::ClaudeCodeIntegration;
use aa_proto::assembly::devint::v1 as wire;
use aa_runtime::devint::adapters::claude_code_registration;
use aa_runtime::devint::codec::{self, DiFrame, DiResponseFrame};
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

/// The native Claude Code registration, with `recording` in the GUI authority
/// slot (AAASM-6491).
fn registration(recording: &Arc<FakeAuthority>) -> aa_runtime::devint::RegisteredIntegration {
    claude_code_registration(Arc::new(
        ClaudeCodeIntegration::new().with_managed_authority(recording.clone()),
    ))
}

/// Read a pty master until the slave side is gone (EOF or EIO) or `limit`
/// passes. The master is non-blocking-polled so the bound is real.
fn drain_pty(master: &mut std::fs::File, limit: std::time::Duration) {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let end = std::time::Instant::now() + limit;
    let mut buf = [0u8; 1024];
    while std::time::Instant::now() < end {
        let mut pfd = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is a valid pollfd for the call. (poll is fine on a pty
        // master; it is only the slave /dev/tty that macOS reports POLLNVAL for.)
        let ready = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ready < 0 {
            break;
        }
        if ready > 0 {
            match master.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    }
}

/// What a pseudo-terminal child is told, see [`Harness::aasm_scripted`].
struct PtyScript {
    stdin_on_tty: bool,
    early: String,
    password: String,
}

struct Harness {
    // Held for the whole struct lifetime, not just construction — see the
    // module doc's Safety section (AAASM-5989). Field order doesn't matter for
    // this (a `MutexGuard` unlocks on `Drop` regardless of declaration order,
    // and struct fields drop in declaration order only among fields declared
    // in the same struct, which affects nothing here), but it's declared first
    // as documentation: this is what makes every other field safe to mutate
    // globally.
    _env_guard: aa_cli::env_guard::EnvGuard,
    dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    token_file: std::path::PathBuf,
    shutdown: CancellationToken,
    server: Option<std::thread::JoinHandle<()>>,
    /// The GUI-slot authority the runtime's integration was registered with
    /// (AAASM-6491). It records every call and never elevates, so a test can
    /// prove the default flow did not reach it: terminal authorization goes
    /// through the CLI's `sudo` instead.
    recording: Arc<FakeAuthority>,
    /// The socket `aasm` is pointed at: the runtime's own, unless a test
    /// interposes a [`VersionProxy`].
    cli_socket: std::sync::Mutex<std::path::PathBuf>,
}

impl Harness {
    fn start() -> Self {
        let _env_guard = aa_cli::env_guard::lock();
        // The elevation seam is for the stub these tests install per command. An
        // ambient one would silently redirect every run, so it is a failure, not
        // a reason to skip.
        assert!(
            std::env::var_os("AASM_TEST_ELEVATION_HELPER").is_none(),
            "AASM_TEST_ELEVATION_HELPER must not be set in the environment these tests run in"
        );
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

        let recording = FakeAuthority::granting();
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![registration(&recording)],
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

        let cli_socket = std::sync::Mutex::new(socket.clone());
        Self {
            _env_guard,
            dir,
            socket,
            token_file,
            shutdown,
            server: Some(handle),
            recording,
            cli_socket,
        }
    }

    /// Point every later `aasm` run at `socket` instead of the runtime's own.
    fn point_cli_at(&self, socket: &std::path::Path) {
        *self.cli_socket.lock().expect("cli socket") = socket.to_path_buf();
    }

    /// Stop the service and start a fresh one over the same socket, the same
    /// receipt store and the same roots — a daemon restart, with nothing else
    /// changed.
    ///
    /// The new service is constructed while this process's working directory is
    /// `boot_cwd`, which is how a restart in a real deployment picks up a new
    /// directory: whatever launched it. A caller's project binding must not move
    /// when that happens (AAASM-5913).
    ///
    /// The `set_current_dir` calls below mutate this process's cwd, another
    /// process-global — safe here only because `self` is still holding
    /// `_env_guard` from construction (AAASM-5989), so no concurrent test can
    /// resolve a relative path against it mid-mutation.
    fn restart_service_from(&mut self, boot_cwd: &std::path::Path) {
        self.shutdown.cancel();
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket);

        let prior = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(boot_cwd).expect("chdir to the new boot directory");
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![registration(&self.recording)],
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
struct Cwd(
    std::path::PathBuf,
    #[allow(dead_code, reason = "held for its Drop, never read")] aa_cli::env_guard::EnvGuard,
);

impl Cwd {
    /// Holds [`aa_cli::env_guard::lock`] for its own lifetime, same as
    /// `Harness` (AAASM-5989) — every caller in this file constructs a
    /// `Harness` while still holding `_cwd`, and the guard is reentrant per
    /// thread precisely so that nesting is safe rather than a deadlock.
    fn set(to: &std::path::Path) -> Self {
        let guard = aa_cli::env_guard::lock();
        let previous = std::env::current_dir().expect("the current directory must be readable");
        std::env::set_current_dir(to).unwrap_or_else(|e| panic!("chdir to {}: {e}", to.display()));
        Self(previous, guard)
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

    // `permissions.defaultMode` is an AASM-owned key that changed externally
    // since AASM last set it — an ownership conflict (AAASM-6091), not
    // routine drift. Default repair refuses to reassert AASM's value over it
    // rather than silently clobbering whatever wrote it.
    let repair = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(repair.status.code(), Some(5), "{}", stderr(&repair));
    let repaired = h.settings().expect("settings");
    assert_eq!(
        repaired["permissions"]["defaultMode"],
        serde_json::json!("bypassPermissions"),
        "default repair must not clobber the externally-changed owned key"
    );
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

    // `repair` from B, the project it is for, reaches the right file — but
    // `permissions.defaultMode` is an AASM-owned key that changed externally
    // since AASM last set it, an ownership conflict (AAASM-6091), so default
    // repair refuses to reassert AASM's value rather than clobbering it.
    let repair = h.aasm_in(b.path(), &["repair", "claude-code", "--yes"]);
    println!("--- aasm integrations repair (caller in B) ---\n{}", stdout(&repair));
    assert_eq!(repair.status.code(), Some(5), "{}", stderr(&repair));
    assert_eq!(
        project_settings(b.path()).expect("B still exists"),
        drifted,
        "default repair must not clobber the externally-changed owned key"
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
    // on it, and from D it refuses like the rest. `outcome` is legitimately
    // "failed" here — the tampered `defaultMode` is an ownership conflict
    // default repair refused to clobber (AAASM-6091), so it is still drifted —
    // so the binding check is that the report is about B's own file, not that
    // it necessarily passed.
    let verify = h.aasm_in(b.path(), &["verify", "claude-code", "--output", "json"]);
    let report: serde_json::Value = serde_json::from_str(&stdout(&verify)).expect("json verify report");
    println!("--- aasm integrations verify (caller in B) ---\n{report:#}");
    let report_text = report.to_string();
    assert!(
        report_text.contains(&b.path().display().to_string()),
        "verify did not report on B's own file, which is what reading the wrong project's file \
         looks like:\n{report:#}"
    );
    assert!(
        !report_text.contains(&d.path().display().to_string()),
        "verify reported on D's file from a caller in B:\n{report:#}"
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

// ── Terminal-first administrator authorization (AAASM-6491) ─────────────────
//
// The CLI owns the operator's terminal and runs `sudo` there; the runtime only
// asks. These tests drive the compiled `aasm` against the real DI-API server,
// with the controlling terminal either a real pseudo-terminal or absent, and
// `sudo` replaced by a recording stub through the seam the CLI honours *only*
// when the runtime-sent target is not the canonical managed-settings path.
//
// Nothing here can reach the real `/Library` path or a real password prompt:
// the managed root is redirected into the temp directory, so the CLI would
// refuse to elevate for it without the stub, and the stub only copies files.

/// What the operator "types" into the pty. Asserted absent from everything the
/// product can write or print.
const PASSWORD: &str = "hunter2-aaasm6491";

impl Harness {
    fn managed_target(&self) -> std::path::PathBuf {
        self.dir.path().join("ClaudeCode").join("managed-settings.json")
    }

    fn managed_work_dir(&self) -> std::path::PathBuf {
        self.dir
            .path()
            .join("state")
            .join("integrations")
            .join("claude-code")
            .join("managed")
    }

    fn stub_record(&self) -> std::path::PathBuf {
        self.dir.path().join("sudo-stub.record")
    }

    /// A stand-in for `sudo`: records every argument and its whole environment,
    /// reads one line from `/dev/tty` for `-v`, accepts only [`PASSWORD`], and
    /// performs `install` / `rm` as an ordinary copy without `-o`/`-g`.
    fn write_sudo_stub(&self) -> std::path::PathBuf {
        let path = self.dir.path().join("sudo-stub.sh");
        let script = format!(
            r#"#!/bin/sh
REC='{rec}'
{{
  for a in "$@"; do printf 'ARG:%s\n' "$a"; done
  echo ENV_BEGIN; env; echo ENV_END
  echo CALL_END
}} >> "$REC"
case "$1" in
  -v)
    IFS= read -r pw < /dev/tty || exit 1
    [ "$pw" = '{password}' ] || {{ echo "sudo: Sorry, try again." >&2; exit 1; }}
    exit 0 ;;
  -k) exit 0 ;;
esac
shift
[ "$1" = "--" ] && shift
cmd=$1; shift
last=; penult=
for a in "$@"; do penult=$last; last=$a; done
case "$cmd" in
  /usr/bin/tee) mkdir -p "$(dirname "$last")" 2>/dev/null; cat > "$last"; exit $? ;;
  /bin/rmdir) rmdir "$last"; exit $? ;;
  /usr/bin/install)
    if [ "$1" = "-d" ]; then mkdir -p "$last"; exit 0; fi
    mkdir -p "$(dirname "$last")" && cp "$penult" "$last" && chmod 644 "$last"; exit $? ;;
  /bin/rm) rm -f "$last"; exit $? ;;
esac
exit 1
"#,
            rec = self.stub_record().display(),
            password = PASSWORD
        );
        std::fs::write(&path, script).expect("write stub");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod stub");
        path
    }

    /// Every `sudo` invocation the stub saw, as argument lists.
    fn stub_calls(&self) -> Vec<Vec<String>> {
        let raw = std::fs::read_to_string(self.stub_record()).unwrap_or_default();
        let mut calls = Vec::new();
        let mut current: Vec<String> = Vec::new();
        let mut in_env = false;
        for line in raw.lines() {
            match line {
                "ENV_BEGIN" => in_env = true,
                "ENV_END" => in_env = false,
                "CALL_END" => calls.push(std::mem::take(&mut current)),
                _ if in_env => {}
                _ => {
                    if let Some(arg) = line.strip_prefix("ARG:") {
                        current.push(arg.to_string());
                    }
                }
            }
        }
        calls
    }

    /// The environment variable names the stub observed across all calls.
    fn stub_env_names(&self) -> std::collections::BTreeSet<String> {
        let raw = std::fs::read_to_string(self.stub_record()).unwrap_or_default();
        let mut names = std::collections::BTreeSet::new();
        let mut in_env = false;
        for line in raw.lines() {
            match line {
                "ENV_BEGIN" => in_env = true,
                "ENV_END" => in_env = false,
                _ if in_env => {
                    if let Some((name, _)) = line.split_once('=') {
                        names.insert(name.to_string());
                    }
                }
                _ => {}
            }
        }
        names
    }

    /// Run `aasm integrations <args>` with the stub standing in for `sudo`.
    ///
    /// `tty`: `Some(answers)` gives the child a real pseudo-terminal as its
    /// controlling terminal and types `answers` into it once `sudo` is waiting;
    /// `None` gives it no controlling terminal at all (`setsid`, nothing
    /// attached), which is what a cron job or a detached session looks like.
    fn aasm_with_stub(&self, args: &[&str], tty: Option<&str>) -> std::process::Output {
        self.aasm_scripted(
            args,
            tty.map(|password| PtyScript {
                stdin_on_tty: false,
                early: String::new(),
                password: password.to_string(),
            }),
        )
    }

    /// As [`Self::aasm_with_stub`], with control over what is typed and where.
    ///
    /// `script.stdin_on_tty` makes the pseudo-terminal the child's stdin as well
    /// as its controlling terminal, so the command's own `[y/N]` question can be
    /// asked; `script.early` is typed at once (the line discipline queues it, in
    /// order, for whichever read comes first), and `script.password` once `sudo
    /// -v` is waiting.
    fn aasm_scripted(&self, args: &[&str], script: Option<PtyScript>) -> std::process::Output {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::process::CommandExt;
        use std::process::Stdio;

        let stub = self.write_sudo_stub();
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("aasm"));
        cmd.arg("integrations")
            .args(args)
            .arg("--no-autostart")
            .env("AA_DEVINT_SOCKET", &*self.cli_socket.lock().expect("cli socket"))
            .env("AA_DEVINT_TOKEN_FILE", &self.token_file)
            .env("AASM_STATE_DIR", self.dir.path().join("state"))
            .env("HOME", self.dir.path())
            .env("CLAUDE_CONFIG_DIR", self.dir.path().join(".claude"))
            .env("AA_CA_DIR", self.dir.path().join("aa").join("ca"))
            .env("AASM_API_KEY", "")
            .env("AASM_CLAUDE_MANAGED_ROOT", self.dir.path().join("ClaudeCode"))
            .env("AASM_TEST_ELEVATION_HELPER", &stub)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut pty_master = None;
        if script.is_some() {
            // `posix_openpt` rather than `openpty`: the latter needs `-lutil` on
            // older glibc, and this file is compiled on Linux CI even though
            // every test in it declines there.
            // SAFETY: each call is checked, and the descriptors are wrapped in
            // `OwnedFd` immediately so they close on drop.
            let (master, slave) = unsafe {
                let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
                assert!(master >= 0, "posix_openpt failed");
                let master = OwnedFd::from_raw_fd(master);
                assert_eq!(libc::grantpt(master.as_raw_fd()), 0, "grantpt failed");
                assert_eq!(libc::unlockpt(master.as_raw_fd()), 0, "unlockpt failed");
                let name = libc::ptsname(master.as_raw_fd());
                assert!(!name.is_null(), "ptsname failed");
                let slave = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
                assert!(slave >= 0, "opening the pty slave failed");
                (master, OwnedFd::from_raw_fd(slave))
            };
            let slave_fd = slave.as_raw_fd();
            if script.as_ref().is_some_and(|s| s.stdin_on_tty) {
                cmd.stdin(Stdio::from(slave.try_clone().expect("dup the pty slave")));
            }
            // SAFETY: runs between fork and exec; only async-signal-safe calls.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::ioctl(slave_fd, libc::TIOCSCTTY as _, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let child = cmd.spawn().expect("spawn aasm");
            drop(slave);
            pty_master = Some((master, child));
        } else {
            // SAFETY: `setsid` is async-signal-safe; it detaches the child from
            // this process's controlling terminal.
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let (child, typist) = match pty_master {
            Some((master, child)) => {
                let record = self.stub_record();
                let script = script.expect("pty script");
                let answer = format!("{}\n", script.password);
                let early = script.early;
                let typist = std::thread::spawn(move || {
                    use std::io::Write;
                    let mut master = std::fs::File::from(master);
                    if !early.is_empty() {
                        let _ = master.write_all(early.as_bytes());
                        let _ = master.flush();
                    }
                    // Type only once `sudo -v` is waiting, so the line is not
                    // consumed by something earlier. Bounded: no answer is
                    // typed if the stub is never reached.
                    for _ in 0..400 {
                        let seen = std::fs::read_to_string(&record).unwrap_or_default();
                        if seen.contains("ARG:-v") {
                            std::thread::sleep(std::time::Duration::from_millis(150));
                            let _ = master.write_all(answer.as_bytes());
                            let _ = master.flush();
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    // Keep the master open until the child is done with it, and
                    // *read* it meanwhile: what the line discipline echoes back
                    // sits in the master's queue, and a child whose controlling
                    // terminal still holds unread output cannot finish exiting
                    // on macOS. Bounded, so a stuck child is a failure, not a hang.
                    drain_pty(&mut master, std::time::Duration::from_secs(60));
                });
                (child, Some(typist))
            }
            None => (cmd.spawn().expect("spawn aasm"), None),
        };
        let pid = child.id();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog_flag = finished.clone();
        let watchdog = std::thread::spawn(move || {
            for _ in 0..1200 {
                if watchdog_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // SAFETY: `pid` is this test's own child; a hang is killed, never
            // left to block the suite.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        });
        let output = child.wait_with_output().expect("wait for aasm");
        finished.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = watchdog.join();
        if let Some(typist) = typist {
            let _ = typist.join();
        }
        output
    }

    /// Everything under the harness directory, concatenated, for secret scans.
    fn everything_on_disk(&self) -> String {
        fn walk(dir: &std::path::Path, out: &mut String) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.file_name().is_some_and(|n| n == "sudo-stub.sh") {
                    // The stand-in for sudo's own password check holds the password
                    // by construction; it is the test's verifier, not product output.
                } else if let Ok(text) = std::fs::read_to_string(&path) {
                    out.push_str(&text);
                }
            }
        }
        let mut out = String::new();
        walk(self.dir.path(), &mut out);
        out
    }

    fn assert_no_remnants(&self) {
        assert!(!self.managed_target().exists(), "the managed file must not exist");
        let leftovers: Vec<_> = std::fs::read_dir(self.managed_work_dir())
            .map(|d| d.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        let leftovers: Vec<_> = leftovers
            .into_iter()
            .filter(|n: &std::ffi::OsString| {
                let n = n.to_string_lossy();
                n.contains("staged") || n.contains("backup")
            })
            .collect();
        assert!(leftovers.is_empty(), "staging or backup left behind: {leftovers:?}");
    }
}

/// The exact argument lists the CLI hands `sudo` for one install, against the
/// redirected target the stub is allowed to act on.
#[test]
fn terminal_authorization_installs_through_one_sudo_call_and_never_the_dialog() {
    let scenario = "terminal_authorization_installs_through_one_sudo_call_and_never_the_dialog";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let out = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some(PASSWORD),
    );
    let message = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- terminal install ---\n{message}");
    assert!(out.status.success(), "{message}");

    let target = h.managed_target();
    assert!(target.exists(), "the stub placed the managed file");
    assert!(message.contains("authorization: sudo in this terminal"), "{message}");
    let placed = std::fs::read_to_string(&target).expect("read the placed file");
    assert!(
        placed.contains("disableBypassPermissionsMode"),
        "the placed document is the reviewed one: {placed}"
    );

    let calls = h.stub_calls();
    let target_str = target.display().to_string();
    let dir_str = target.parent().expect("parent").display().to_string();
    // The temporary is unique per run, with a fixed prefix, inside the managed directory.
    let tmp_str = calls[2][4].clone();
    assert!(
        tmp_str.starts_with(&format!("{dir_str}/.managed-settings.json.aasm-new.")),
        "{calls:?}"
    );
    assert_eq!(
        calls.len(),
        6,
        "authenticate, mkdir, tee, install, rm tmp, drop: {calls:?}"
    );
    assert_eq!(&calls[0][..2], ["-v", "-p"], "{calls:?}");
    assert!(
        calls[0][2].starts_with("[aasm] password for %u to place one root-owned file, "),
        "{calls:?}"
    );
    assert!(!calls.iter().flatten().any(|a| a == "-S" || a == "-A"), "{calls:?}");
    assert_eq!(
        calls[1],
        [
            "-n",
            "--",
            "/usr/bin/install",
            "-d",
            "-m",
            "755",
            "-o",
            "root",
            "-g",
            "wheel",
            "--",
            dir_str.as_str()
        ]
    );
    // Root is handed the verified bytes on stdin and a root-owned temporary: no
    // argv run as root ever names the user-writable staged file.
    assert_eq!(calls[2], ["-n", "--", "/usr/bin/tee", "--", tmp_str.as_str()]);
    assert_eq!(
        calls[3],
        [
            "-n",
            "--",
            "/usr/bin/install",
            "-m",
            "644",
            "-o",
            "root",
            "-g",
            "wheel",
            "--",
            tmp_str.as_str(),
            target_str.as_str()
        ]
    );
    assert_eq!(calls[4], ["-n", "--", "/bin/rm", "-f", "--", tmp_str.as_str()]);
    assert_eq!(calls[5], ["-k"]);
    assert!(
        !calls.iter().flatten().any(|a| a.contains("staged")),
        "a staged path reached the root side: {calls:?}"
    );

    assert_eq!(
        h.recording.calls().len(),
        0,
        "the GUI authority must not be reached by the default flow: {:?}",
        h.recording.calls()
    );

    // Only what the CLI chose crossed into sudo's environment.
    let names = h.stub_env_names();
    for forbidden in [
        "AASM_STATE_DIR",
        "AASM_API_KEY",
        "HOME",
        "CLAUDE_CONFIG_DIR",
        "AASM_TEST_ELEVATION_HELPER",
    ] {
        assert!(!names.contains(forbidden), "{forbidden} leaked into sudo: {names:?}");
    }
    assert!(names.contains("PATH"), "{names:?}");

    // The typed password is nowhere the product could have put it.
    let stub_record = std::fs::read_to_string(h.stub_record()).unwrap_or_default();
    assert!(!stub_record.contains(PASSWORD), "password in argv or env");
    assert!(!message.contains(PASSWORD), "password in output");
    assert!(!h.everything_on_disk().contains(PASSWORD), "password on disk");

    // And removal goes the same way and ends with the target absent.
    let removal = h.aasm_with_stub(&["remove", "claude-code", "--yes"], Some(PASSWORD));
    let message = format!("{}{}", stdout(&removal), stderr(&removal));
    println!("--- terminal remove ---\n{message}");
    assert!(removal.status.success(), "{message}");
    assert!(!target.exists(), "removal must leave the target absent");
    let calls = h.stub_calls();
    let removal_calls = &calls[6..];
    assert_eq!(removal_calls.len(), 3, "authenticate, rm, drop: {removal_calls:?}");
    assert!(
        removal_calls[0][2].contains("to delete one root-owned file"),
        "{removal_calls:?}"
    );
    assert_eq!(
        removal_calls[1],
        ["-n", "--", "/bin/rm", "-f", "--", target_str.as_str()]
    );
    assert_eq!(removal_calls[2], ["-k"]);
    assert_eq!(h.recording.calls().len(), 0);
}

/// No controlling terminal: exit 9 promptly, neither the stub nor the GUI
/// authority is reached, and nothing is left behind.
#[test]
fn without_a_terminal_the_install_exits_promptly_and_changes_nothing() {
    let scenario = "without_a_terminal_the_install_exits_promptly_and_changes_nothing";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let started = std::time::Instant::now();
    let out = h.aasm_with_stub(&["install", "claude-code", "--install-managed-settings", "--yes"], None);
    let message = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- no tty ---\n{message}");
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "must not wait");
    assert_eq!(out.status.code(), Some(9), "{message}");
    assert!(message.contains("Unavailable"), "{message}");
    assert!(message.contains("needs an interactive terminal"), "{message}");
    assert!(
        message.contains("--admin-auth gui"),
        "the remediation must be actionable: {message}"
    );
    assert!(h.stub_calls().is_empty(), "sudo must not be reached without a tty");
    assert!(h.recording.calls().is_empty(), "the dialog must not be reached either");
    h.assert_no_remnants();
}

/// A refused password: exit 9, "Permission Required", and the install is
/// rolled back — no target, no staged file, no backup, no receipt.
#[test]
fn a_refused_password_is_permission_required_and_leaves_no_remnants() {
    let scenario = "a_refused_password_is_permission_required_and_leaves_no_remnants";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let out = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some("not-the-password"),
    );
    let message = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- denied ---\n{message}");
    assert_eq!(out.status.code(), Some(9), "{message}");
    assert!(message.contains("Permission Required"), "{message}");
    assert!(message.contains("nothing was changed"), "{message}");
    assert!(h.recording.calls().is_empty());
    h.assert_no_remnants();

    let status = h.aasm(&["status", "claude-code", "--output", "json"]);
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).expect("status json");
    let phase = status["phase"].as_str().unwrap_or_default();
    assert!(
        phase != "installed" && phase != "partially_installed",
        "the rest of the install must have been rolled back, phase was {phase}"
    );
    assert!(h.aasm(&["status", "claude-code"]).status.code().is_some());
}

/// `--admin-auth gui` is the only way to the dialog path: the recording
/// authority is reached, and the stub never is.
#[test]
fn gui_authorization_is_reached_only_when_asked_for_by_name() {
    let scenario = "gui_authorization_is_reached_only_when_asked_for_by_name";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let out = h.aasm_with_stub(
        &[
            "install",
            "claude-code",
            "--install-managed-settings",
            "--admin-auth",
            "gui",
            "--yes",
        ],
        None,
    );
    let message = format!("{}{}", stdout(&out), stderr(&out));
    println!("--- gui ---\n{message}");
    assert!(out.status.success(), "{message}");
    assert!(
        message.contains("authorization: macOS dialog (--admin-auth gui)"),
        "{message}"
    );
    assert!(!h.recording.calls().is_empty(), "the GUI authority was never reached");
    assert!(
        h.stub_calls().is_empty(),
        "terminal authorization must not run under gui"
    );
}

/// Planning and the default flow never reach the dialog authority.
#[test]
fn planning_and_the_default_flow_never_reach_the_dialog_authority() {
    let scenario = "planning_and_the_default_flow_never_reach_the_dialog_authority";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let plan = h.aasm(&["plan", "claude-code", "--install-managed-settings"]);
    let rendered = format!("{}{}", stdout(&plan), stderr(&plan));
    assert!(plan.status.success(), "{rendered}");
    assert!(rendered.contains("authorization: sudo in this terminal"), "{rendered}");
    assert!(
        rendered.contains("sudo in the terminal that ran this command"),
        "the mechanism line must be in the disclosure: {rendered}"
    );
    assert_eq!(h.recording.calls().len(), 0, "planning must not elevate");
}

#[test]
fn the_cli_owns_copies_of_the_managed_identifiers_that_equal_the_adapters() {
    // The published CLI cannot import these from the held-back adapter, so it
    // keeps its own; this test (stripped with the adapter) keeps them honest.
    use aa_cli::commands::integrations::elevation as cli;
    assert_eq!(
        cli::MANAGED_SETTINGS_PATH,
        aa_devtool_claude_code::MANAGED_SETTINGS_PATH
    );
    assert_eq!(
        cli::MANAGED_SETTINGS_FILE,
        aa_devtool_claude_code::managed_settings::MANAGED_SETTINGS_FILE
    );
    assert_eq!(
        cli::STEP_ENDPOINT_MANAGED_SETTINGS,
        aa_devtool_claude_code::lifecycle::STEP_ENDPOINT_MANAGED_SETTINGS
    );
}

/// `osascript` has exactly one home: the GUI authority. If another source file
/// grows a reference, a code path outside the explicit `--admin-auth gui`
/// choice may have learned to raise the dialog.
#[test]
fn osascript_appears_only_in_the_gui_authority() {
    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if text.contains("osascript") {
                        hits.push(path.display().to_string());
                    }
                }
            }
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut hits = Vec::new();
    for krate in [
        "aa-cli",
        "aa-runtime",
        "aa-core",
        "aa-devtool-claude-code",
        "aa-devtool-contract",
    ] {
        scan(&root.join(krate).join("src"), &mut hits);
    }
    assert!(
        hits.len() == 1 && hits[0].ends_with("aa-devtool-claude-code/src/managed_settings.rs"),
        "osascript must live only in MacOsAdminAuthority, found: {hits:?}"
    );
}

/// With no terminal, `remove` and `repair` exit 9 before anything is sent that
/// could change the host, and `remove` has already shown how it would have
/// asked.
#[test]
fn remove_and_repair_without_a_terminal_exit_before_any_mutation() {
    let scenario = "remove_and_repair_without_a_terminal_exit_before_any_mutation";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let install = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some(PASSWORD),
    );
    assert!(install.status.success(), "{}{}", stdout(&install), stderr(&install));
    let before = h.stub_calls().len();
    let target = h.managed_target();
    assert!(target.exists());

    let removal = h.aasm_with_stub(&["remove", "claude-code", "--yes"], None);
    let message = format!("{}{}", stdout(&removal), stderr(&removal));
    println!("--- remove, no tty ---\n{message}");
    assert_eq!(removal.status.code(), Some(9), "{message}");
    assert!(
        message.contains("authorization: sudo in this terminal"),
        "disclosed first: {message}"
    );
    assert!(message.contains("needs an interactive terminal"), "{message}");
    assert!(target.exists(), "nothing may be removed");
    assert_eq!(h.stub_calls().len(), before, "sudo must not be reached");

    // Repair: take the managed file away so there is drift on exactly that path.
    std::fs::remove_file(&target).expect("drift the managed file");
    let repair = h.aasm_with_stub(&["repair", "claude-code", "--yes"], None);
    let message = format!("{}{}", stdout(&repair), stderr(&repair));
    println!("--- repair, no tty ---\n{message}");
    assert_eq!(repair.status.code(), Some(9), "{message}");
    assert!(message.contains("authorization: sudo in this terminal"), "{message}");
    assert!(!target.exists(), "nothing may be re-placed without authorization");
    assert_eq!(h.stub_calls().len(), before, "sudo must not be reached");
    assert!(h.recording.calls().is_empty(), "the dialog must not be reached either");
}

/// The removal preview names how authorization will be obtained *before* the
/// confirmation, and declining to confirm changes nothing.
#[test]
fn the_removal_preview_names_the_method_before_it_asks_for_confirmation() {
    let scenario = "the_removal_preview_names_the_method_before_it_asks_for_confirmation";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let install = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some(PASSWORD),
    );
    assert!(install.status.success(), "{}{}", stdout(&install), stderr(&install));
    let before = h.stub_calls().len();

    // A terminal exists but stdin is not one and `--yes` is absent: the command
    // cannot ask, so it refuses — after printing the preview.
    let removal = h.aasm_with_stub(&["remove", "claude-code"], Some(PASSWORD));
    let message = format!("{}{}", stdout(&removal), stderr(&removal));
    println!("--- remove, no --yes ---\n{message}");
    assert_eq!(removal.status.code(), Some(9), "{message}");
    let disclosed = message
        .find("authorization: sudo in this terminal")
        .expect("disclosure line");
    let refused = message.find("nothing was changed").expect("refusal");
    assert!(
        disclosed < refused,
        "the method must be named before the refusal to proceed: {message}"
    );
    assert!(h.managed_target().exists());
    assert_eq!(h.stub_calls().len(), before);
}

// ── a controlling terminal, for real ────────────────────────────────────────

/// `remove` without `--yes`, on a genuine controlling terminal: the pseudo-
/// terminal is the child's stdin (the command's own question) *and* its
/// controlling terminal (`/dev/tty`: the delete question, then the stub's
/// password read). The three lines are typed in the order the reads happen, so
/// a read that did not happen — or happened out of order — leaves a line for
/// the wrong consumer and fails the run.
#[test]
fn remove_asks_on_the_controlling_terminal_and_reads_each_answer_in_order() {
    let scenario = "remove_asks_on_the_controlling_terminal_and_reads_each_answer_in_order";
    if !require_claude(scenario) {
        return;
    }
    let h = Harness::start();
    let install = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some(PASSWORD),
    );
    assert!(install.status.success(), "{}{}", stdout(&install), stderr(&install));
    let before = h.stub_calls().len();
    assert!(h.managed_target().exists());

    let removal = h.aasm_scripted(
        &["remove", "claude-code"],
        Some(PtyScript {
            stdin_on_tty: true,
            early: "y\ny\n".to_string(),
            password: PASSWORD.to_string(),
        }),
    );
    let message = format!("{}{}", stdout(&removal), stderr(&removal));
    println!("--- remove on a tty ---\n{message}");
    assert!(removal.status.success(), "{message}");
    assert!(!h.managed_target().exists(), "the file must be gone");
    assert!(h.stub_calls().len() > before, "sudo must have been used");
    assert!(!message.contains(PASSWORD), "password in output");
}

/// Declining the delete question on `/dev/tty`, or sending end-of-file to it,
/// changes nothing and never reaches `sudo`.
#[test]
fn declining_or_closing_the_delete_question_changes_nothing() {
    let scenario = "declining_or_closing_the_delete_question_changes_nothing";
    if !require_claude(scenario) {
        return;
    }
    for (label, early) in [("n", "y\nn\n"), ("^D", "y\n\u{4}")] {
        let h = Harness::start();
        let install = h.aasm_with_stub(
            &["install", "claude-code", "--install-managed-settings", "--yes"],
            Some(PASSWORD),
        );
        assert!(install.status.success(), "{}{}", stdout(&install), stderr(&install));
        let before = h.stub_calls().len();

        let removal = h.aasm_scripted(
            &["remove", "claude-code"],
            Some(PtyScript {
                stdin_on_tty: true,
                early: early.to_string(),
                password: PASSWORD.to_string(),
            }),
        );
        let message = format!("{}{}", stdout(&removal), stderr(&removal));
        println!("--- remove, answer {label} ---\n{message}");
        assert_eq!(removal.status.code(), Some(9), "{label}: {message}");
        assert!(h.managed_target().exists(), "{label}: nothing may be removed");
        assert_eq!(h.stub_calls().len(), before, "{label}: sudo must not be reached");
    }
}

// ── an older runtime, through the real CLI ──────────────────────────────────

/// A man in the middle that makes a real runtime look like an older one.
///
/// It speaks the DI-API codec on both sides: the client's `Hello` is rewritten
/// to offer nothing above `cap`, so the real server negotiates that version and
/// serves exactly what a runtime of that age would. Optionally the removal
/// preview's steps are replaced by `removal_steps`, which is how a step kind the
/// installed adapter does not itself produce reaches the CLI. Every client
/// frame is logged so a test can say what was — and was not — sent.
struct VersionProxy {
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
}

/// One frame the CLI sent, or one fact about what came back.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Hello(Vec<u32>),
    Negotiated(u32),
    Request { verb: i32, remove_plan_id: String },
    ElevationResult,
    ElevationRequestFromRuntime,
}

impl VersionProxy {
    fn start(
        upstream: std::path::PathBuf,
        listen: std::path::PathBuf,
        cap: u32,
        removal_steps: Option<Vec<wire::StepView>>,
    ) -> Self {
        let stop = CancellationToken::new();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (stop_t, seen_t, listen_t) = (stop.clone(), seen.clone(), listen.clone());
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("proxy runtime");
            rt.block_on(async move {
                let listener = tokio::net::UnixListener::bind(&listen_t).expect("bind the version proxy");
                loop {
                    tokio::select! {
                        () = stop_t.cancelled() => break,
                        accepted = listener.accept() => {
                            let Ok((client, _)) = accepted else { break };
                            let upstream = upstream.clone();
                            let seen = seen_t.clone();
                            let steps = removal_steps.clone();
                            tokio::spawn(async move {
                                let Ok(server) = tokio::net::UnixStream::connect(&upstream).await else { return };
                                let (mut cr, mut cw) = tokio::io::split(client);
                                let (mut sr, mut sw) = tokio::io::split(server);
                                let seen_c = seen.clone();
                                let up = async move {
                                    while let Ok(frame) = codec::read_frame(&mut cr).await {
                                        let frame = match frame {
                                            DiFrame::Hello(mut hello) => {
                                                hello.di_api_versions.retain(|v| *v <= cap);
                                                seen_c.lock().expect("seen").push(Seen::Hello(hello.di_api_versions.clone()));
                                                DiFrame::Hello(hello)
                                            }
                                            DiFrame::Request(request) => {
                                                seen_c.lock().expect("seen").push(Seen::Request {
                                                    verb: request.verb,
                                                    remove_plan_id: request.remove.as_ref().map(|r| r.plan_id.clone()).unwrap_or_default(),
                                                });
                                                DiFrame::Request(request)
                                            }
                                            DiFrame::ElevationResult(result) => {
                                                seen_c.lock().expect("seen").push(Seen::ElevationResult);
                                                DiFrame::ElevationResult(result)
                                            }
                                        };
                                        if codec::write_client_frame(&mut sw, frame).await.is_err() {
                                            break;
                                        }
                                    }
                                };
                                let down = async move {
                                    while let Ok(frame) = codec::read_response_frame(&mut sr).await {
                                        let frame = match frame {
                                            DiResponseFrame::HelloAck(ack) => {
                                                seen.lock().expect("seen").push(Seen::Negotiated(ack.di_api_version));
                                                DiResponseFrame::HelloAck(ack)
                                            }
                                            DiResponseFrame::Response(mut response) => {
                                                if let (Some(steps), Some(removal)) = (&steps, response.removal.as_mut()) {
                                                    removal.steps = steps.clone();
                                                }
                                                DiResponseFrame::Response(response)
                                            }
                                            DiResponseFrame::ElevationRequest(request) => {
                                                seen.lock().expect("seen").push(Seen::ElevationRequestFromRuntime);
                                                DiResponseFrame::ElevationRequest(request)
                                            }
                                            other => other,
                                        };
                                        if codec::write_frame(&mut cw, frame).await.is_err() {
                                            break;
                                        }
                                    }
                                };
                                tokio::join!(up, down);
                            });
                        }
                    }
                }
            });
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !listen.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(listen.exists(), "the version proxy never bound its socket");
        Self {
            stop,
            thread: Some(thread),
            seen,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    fn requests(&self, verb: wire::Verb) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| matches!(s, Seen::Request { verb: v, .. } if *v == verb as i32))
            .collect()
    }
}

impl Drop for VersionProxy {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A scripted removal-preview step.
fn scripted_step(id: &str, kind: &str, privilege: &str, scope: &str, paths: &[&str]) -> wire::StepView {
    wire::StepView {
        id: id.to_string(),
        summary: format!("scripted {kind}"),
        action_kind: kind.to_string(),
        requirement: "required".to_string(),
        privilege: privilege.to_string(),
        settings_scope: scope.to_string(),
        artifact_paths: paths.iter().map(|p| (*p).to_string()).collect(),
        reversible: true,
        ..wire::StepView::default()
    }
}

/// A harness with the managed file installed (through the runtime directly, at
/// its own version) and `aasm` pointed at a proxy that caps the version at 7.
fn installed_behind_a_v7_runtime(steps: Option<Vec<wire::StepView>>) -> (Harness, VersionProxy) {
    let h = Harness::start();
    let install = h.aasm_with_stub(
        &["install", "claude-code", "--install-managed-settings", "--yes"],
        Some(PASSWORD),
    );
    assert!(install.status.success(), "{}{}", stdout(&install), stderr(&install));
    // Its own directory: the CLI counts every runtime socket in the directory it
    // is pointed at, and a second one beside the real runtime is an ambiguity it
    // rightly refuses (exit 10).
    let proxy_dir = h.dir.path().join("v7-proxy");
    std::fs::create_dir_all(&proxy_dir).expect("proxy dir");
    let listen = proxy_dir.join("devint.sock");
    let proxy = VersionProxy::start(h.socket.clone(), listen.clone(), 7, steps);
    h.point_cli_at(&listen);
    (h, proxy)
}

fn assert_refused_for_age(out: &Output, label: &str) {
    let message = format!("{}{}", stdout(out), stderr(out));
    println!("--- {label} ---\n{message}");
    assert_eq!(out.status.code(), Some(4), "{label}: {message}");
    assert!(
        message.contains("DI-API 7"),
        "{label}: names the negotiated version: {message}"
    );
    assert!(message.contains("upgrade the runtime"), "{label}: {message}");
    assert!(message.contains("--admin-auth gui"), "{label}: {message}");
}

/// `remove` against a DI-API 7 runtime, when the removal reaches the managed
/// file: exit 4, and the only thing sent after negotiation is the preview.
#[test]
fn remove_reaching_the_managed_file_is_refused_by_a_v7_runtime_before_anything_is_sent() {
    let scenario = "remove_reaching_the_managed_file_is_refused_by_a_v7_runtime";
    if !require_claude(scenario) {
        return;
    }
    let (h, proxy) = installed_behind_a_v7_runtime(None);
    let (stub_before, dialog_before) = (h.stub_calls().len(), h.recording.calls().len());

    let out = h.aasm_with_stub(&["remove", "claude-code", "--yes"], Some(PASSWORD));
    assert_refused_for_age(&out, "remove at v7");
    assert!(proxy.seen().contains(&Seen::Negotiated(7)), "{:?}", proxy.seen());
    let removals = proxy.requests(wire::Verb::Remove);
    assert_eq!(
        removals,
        vec![Seen::Request {
            verb: wire::Verb::Remove as i32,
            remove_plan_id: String::new()
        }],
        "only the preview may be sent: {:?}",
        proxy.seen()
    );
    assert!(h.managed_target().exists(), "nothing may be removed");
    assert_eq!(h.stub_calls().len(), stub_before, "sudo must not be reached");
    assert_eq!(h.recording.calls().len(), dialog_before, "no dialog either");
}

/// `repair` against a DI-API 7 runtime, when the drift is on the managed file.
#[test]
fn repair_of_the_managed_file_is_refused_by_a_v7_runtime_before_anything_is_sent() {
    let scenario = "repair_of_the_managed_file_is_refused_by_a_v7_runtime";
    if !require_claude(scenario) {
        return;
    }
    let (h, proxy) = installed_behind_a_v7_runtime(None);
    let (stub_before, dialog_before) = (h.stub_calls().len(), h.recording.calls().len());
    std::fs::remove_file(h.managed_target()).expect("drift the managed file");

    let out = h.aasm_with_stub(&["repair", "claude-code", "--yes"], Some(PASSWORD));
    assert_refused_for_age(&out, "repair at v7");
    assert!(proxy.seen().contains(&Seen::Negotiated(7)), "{:?}", proxy.seen());
    assert!(
        proxy.requests(wire::Verb::Repair).is_empty(),
        "no repair may be sent: {:?}",
        proxy.seen()
    );
    assert!(!h.managed_target().exists(), "nothing may be re-placed");
    assert_eq!(h.stub_calls().len(), stub_before, "sudo must not be reached");
    assert_eq!(h.recording.calls().len(), dialog_before, "no dialog either");
}

/// Steps that legitimately carry no path and are not managed — proxy wiring and
/// an MCP list — must not be refused just because the runtime is old.
#[test]
fn pathless_unprivileged_steps_are_not_refused_by_a_v7_runtime() {
    let scenario = "pathless_unprivileged_steps_are_not_refused_by_a_v7_runtime";
    if !require_claude(scenario) {
        return;
    }
    for (label, step) in [
        (
            "configure_proxy",
            scripted_step("proxy-env", "configure_proxy", "user", "user", &[]),
        ),
        (
            "configure_mcp_servers",
            scripted_step("mcp", "configure_mcp_servers", "user", "", &[]),
        ),
    ] {
        let (h, proxy) = installed_behind_a_v7_runtime(Some(vec![step]));
        let stub_before = h.stub_calls().len();

        let out = h.aasm_with_stub(&["remove", "claude-code", "--yes"], None);
        let message = format!("{}{}", stdout(&out), stderr(&out));
        println!("--- remove at v7, {label}-only ---\n{message}");
        assert!(out.status.success(), "{label}: {message}");
        assert!(!message.contains("upgrade the runtime"), "{label}: {message}");
        assert!(
            proxy.seen().contains(&Seen::Negotiated(7)),
            "{label}: {:?}",
            proxy.seen()
        );
        assert_eq!(h.stub_calls().len(), stub_before, "{label}: sudo is not involved");
    }
}

/// A legacy managed-settings step names no path yet is the managed file; a kind
/// this build cannot name might be. Both are refused by a v7 runtime.
#[test]
fn legacy_managed_and_unknown_steps_are_refused_by_a_v7_runtime() {
    let scenario = "legacy_managed_and_unknown_steps_are_refused_by_a_v7_runtime";
    if !require_claude(scenario) {
        return;
    }
    for (label, step) in [
        (
            "apply_legacy_managed_settings, no paths",
            scripted_step("legacy", "apply_legacy_managed_settings", "user", "", &[]),
        ),
        (
            "unknown kind",
            scripted_step("future", "kind_from_a_newer_runtime", "user", "", &[]),
        ),
    ] {
        let (h, proxy) = installed_behind_a_v7_runtime(Some(vec![step]));
        let stub_before = h.stub_calls().len();

        let out = h.aasm_with_stub(&["remove", "claude-code", "--yes"], None);
        assert_refused_for_age(&out, label);
        assert_eq!(
            proxy.requests(wire::Verb::Remove).len(),
            1,
            "{label}: only the preview: {:?}",
            proxy.seen()
        );
        assert!(h.managed_target().exists(), "{label}: nothing may be removed");
        assert_eq!(h.stub_calls().len(), stub_before, "{label}: sudo must not be reached");
    }
}
