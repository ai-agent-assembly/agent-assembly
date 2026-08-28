//! The ratified `changed`/`unchanged`/`refused`/`failed` contract, end to end
//! (AAASM-5499).
//!
//! # What these tests are for, and why an exit-code assertion is not enough
//!
//! The owner decision is that a legitimate no-op is a **success** and exits
//! `0` — a `remove` of an integration that is already gone, a `repair` of state
//! that is already correct. That makes the exit code useless as the thing that
//! tells a mutation from a no-op: it is `0` on *both* sides of the distinction.
//! `aasm integrations repair X && echo repaired` announcing a repair of a tool
//! that was never installed (AAASM-5455) is what that costs.
//!
//! So every test below asserts what a caller can actually branch on:
//!
//! - the **token on stdout**, which is what a person reads;
//! - the **token in `--output json`**, which is what a script reads;
//! - the **exit code**, which answers the other question — did it work — and is
//!   asserted alongside, never instead.
//!
//! A test that pinned only the exit code would pass against a build that
//! reported `changed` for everything, and against one that reported `unchanged`
//! for everything. Both of those mutations are run explicitly in
//! [`the_two_falsifying_mutations_are_both_caught`], which asserts that the
//! assertions above are the ones that catch them.
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
/// A local copy rather than a shared module, for the same reason the other
/// `integrations_*` test files keep their own: a harness shared between files
/// becomes a constraint on all of them.
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

    /// Install the fixture integration, failing loudly if the setup step did
    /// not work — a test whose premise silently failed proves nothing.
    fn install(&self) {
        std::fs::write(&self.settings, r#"{"theme":"solarized"}"#).expect("seed");
        let output = self.aasm(&["install", "claude-code", "--yes"]);
        assert_eq!(
            code(&output),
            exit::SUCCESS,
            "the install this test builds on failed: {}",
            combined(&output)
        );
    }

    /// Rewrite a key the receipt claims, so the next `repair` has real drift.
    fn tamper(&self) {
        std::fs::write(&self.settings, r#"{"aasmManaged":false,"theme":"gruvbox"}"#).expect("tamper");
        assert_eq!(
            code(&self.aasm(&["status", "claude-code"])),
            exit::DRIFTED,
            "the tampering produced no drift, so there is nothing to repair"
        );
    }

    fn settings_contents(&self) -> Option<String> {
        std::fs::read_to_string(&self.settings).ok()
    }

    /// The receipt file's bytes, or `None` when no receipt is on record.
    ///
    /// Read as bytes rather than as a timestamp: an `unchanged` run must leave
    /// the receipt *identical*, and a modification time is too coarse to prove
    /// that on a fast machine.
    fn receipt(&self) -> Option<Vec<u8>> {
        std::fs::read(self.store_root.join("claude-code--user.receipt.json")).ok()
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

/// The `outcome` token from `--output json`, or `None` when the report carries
/// no outcome (a preview).
fn json_outcome(output: &Output) -> Option<String> {
    let report: serde_json::Value = serde_json::from_str(&stdout(output))
        .unwrap_or_else(|e| panic!("the report was not valid JSON: {e}\n{}", combined(output)));
    report
        .get("outcome")
        .unwrap_or_else(|| panic!("the report has no `outcome` field at all: {report:#}"))
        .as_str()
        .map(str::to_string)
}

/// The exit-code table `exit.rs` pins, transcribed so an assertion below reads
/// as a contract rather than as a magic number.
mod exit {
    pub const SUCCESS: i32 = 0;
    pub const DRIFTED: i32 = 5;
    pub const ABORTED: i32 = 9;
}

// ── 1. shell exit codes ──────────────────────────────────────────────────────

/// `changed` and `unchanged` both exit `0`. This is the ratified decision, and
/// pinning it is what stops a later "obviously a no-op should exit 3" from
/// landing quietly — it is also exactly why none of the tests below stop at the
/// exit code.
#[test]
fn both_successful_outcomes_exit_zero() {
    let h = Harness::start();
    h.install();
    h.tamper();

    let changed = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(
        json_outcome(&changed).as_deref(),
        Some("changed"),
        "{}",
        combined(&changed)
    );
    assert_eq!(code(&changed), exit::SUCCESS, "{}", combined(&changed));

    let unchanged = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(
        json_outcome(&unchanged).as_deref(),
        Some("unchanged"),
        "{}",
        combined(&unchanged)
    );
    assert_eq!(code(&unchanged), exit::SUCCESS, "{}", combined(&unchanged));
}

/// A refusal exits non-zero with the code `exit.rs` already pins for it, and
/// names `refused` where a person will see it.
///
/// `remove` without `--force` on a reversal that cannot fully restore is the
/// refusal this family reaches without any fixture surgery: the command
/// declines to act, and nothing is modified.
#[test]
fn a_refusal_exits_nonzero_and_says_refused() {
    let h = Harness::start();
    h.install();
    // A confirmation is impossible in a piped run, so this refuses for want of
    // consent — a decision nobody made, which is `aborted` (9) and `refused`.
    let output = h.aasm(&["remove", "claude-code"]);

    assert_eq!(code(&output), exit::ABORTED, "{}", combined(&output));
    assert!(
        stderr(&output).contains("outcome: refused"),
        "the refusal did not name its outcome: {}",
        combined(&output)
    );
    assert!(
        stderr(&output).contains("exit 9 aborted"),
        "the refusal did not name the exit code it produced: {}",
        stderr(&output)
    );
    // A refusal is not a mutation. The integration is still installed.
    assert!(h.receipt().is_some(), "a refused removal removed the receipt anyway");
}

/// Neither success token may ever appear on a non-zero exit, and neither
/// non-zero token on a zero exit. The sign of the exit code and the outcome are
/// one fact reported twice, and they must never disagree.
#[test]
fn the_outcome_and_the_sign_of_the_exit_code_never_disagree() {
    let h = Harness::start();
    h.install();
    h.tamper();

    for args in [
        vec!["repair", "claude-code", "--yes"],
        vec!["repair", "claude-code", "--yes"],
        vec!["remove", "claude-code", "--yes"],
        vec!["remove", "claude-code", "--yes"],
        vec!["remove", "claude-code"],
    ] {
        let output = h.aasm(&args);
        let said_success = stdout(&output).contains("— changed") || stdout(&output).contains("— unchanged");
        let said_failure = stderr(&output).contains("outcome: refused") || stderr(&output).contains("outcome: failed");

        if code(&output) == exit::SUCCESS {
            assert!(
                !said_failure,
                "`{}` exited 0 and reported a non-zero outcome: {}",
                args.join(" "),
                combined(&output)
            );
        } else {
            assert!(
                !said_success,
                "`{}` exited {} and reported a success outcome: {}",
                args.join(" "),
                code(&output),
                combined(&output)
            );
        }
    }
}

// ── 2. structured output ─────────────────────────────────────────────────────

/// Every command that can reach a no-op carries the token in `--output json`,
/// under one key, spelled the same way. A script that has to learn a different
/// key per command has not been given a contract.
#[test]
fn every_command_that_reaches_a_no_op_carries_the_token_in_json() {
    let h = Harness::start();
    h.install();
    h.tamper();

    // repair: changed, then unchanged.
    let repair_changed = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(json_outcome(&repair_changed).as_deref(), Some("changed"));
    let repair_unchanged = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(json_outcome(&repair_unchanged).as_deref(), Some("unchanged"));

    // remove: changed, then unchanged.
    let remove_changed = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(json_outcome(&remove_changed).as_deref(), Some("changed"));
    let remove_unchanged = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(json_outcome(&remove_unchanged).as_deref(), Some("unchanged"));

    // repair with nothing installed at all — the AAASM-5455 state.
    let repair_absent = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);
    assert_eq!(json_outcome(&repair_absent).as_deref(), Some("unchanged"));
}

/// YAML is the other machine-readable surface and carries the same key. A
/// contract that holds in one serializer and not the other is not a contract.
#[test]
fn the_token_survives_into_yaml_too() {
    let h = Harness::start();
    h.install();

    let output = h.aasm(&["remove", "claude-code", "--yes", "--output", "yaml"]);
    let report: serde_yaml::Value = serde_yaml::from_str(&stdout(&output)).expect("the report was not valid YAML");
    assert_eq!(
        report.get("outcome").and_then(|v| v.as_str()),
        Some("changed"),
        "{}",
        stdout(&output)
    );
}

/// A preview reports `null` rather than picking a token. It changed nothing,
/// and it established nothing about whether the end state already holds — so a
/// script that branches on `changed`/`unchanged` gets neither, which is the
/// honest answer rather than the flattering one.
#[test]
fn a_preview_reports_a_null_outcome_rather_than_guessing() {
    let h = Harness::start();
    h.install();
    h.tamper();

    let repair = h.aasm(&["repair", "claude-code", "--dry-run", "--output", "json"]);
    assert_eq!(json_outcome(&repair), None, "{}", stdout(&repair));
    assert_eq!(code(&repair), exit::DRIFTED, "{}", combined(&repair));

    let remove = h.aasm(&["remove", "claude-code", "--dry-run", "--output", "json"]);
    assert_eq!(json_outcome(&remove), None, "{}", stdout(&remove));

    // …and the preview did not touch anything, which is what makes `null` the
    // right answer rather than `unchanged`.
    assert!(h.receipt().is_some(), "a preview consumed the receipt");
}

// ── 3. receipts agree with what was reported ─────────────────────────────────

/// An `unchanged` repair must leave the receipt byte-for-byte as it found it.
///
/// The claim in `repair.rs` is that saying "nothing to do" beats performing a
/// no-op rewrite that would churn the receipt. If a run reports `unchanged`
/// while the receipt on disk moved, the report is false about the one artifact
/// the product treats as the record of what it did.
#[test]
fn an_unchanged_repair_leaves_the_receipt_untouched() {
    let h = Harness::start();
    h.install();

    let before = h.receipt().expect("the install wrote no receipt");
    let output = h.aasm(&["repair", "claude-code", "--yes"]);

    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    assert!(stdout(&output).contains("— unchanged"), "{}", stdout(&output));
    assert_eq!(
        h.receipt().as_deref(),
        Some(before.as_slice()),
        "a run that reported `unchanged` rewrote its receipt"
    );
}

/// A `changed` repair must have actually restored the managed key. The token is
/// a claim about the host, and this is the host.
#[test]
fn a_changed_repair_actually_restored_the_managed_state() {
    let h = Harness::start();
    h.install();
    h.tamper();

    let output = h.aasm(&["repair", "claude-code", "--yes"]);
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));
    assert!(stdout(&output).contains("— changed"), "{}", stdout(&output));
    assert!(
        h.settings_contents()
            .expect("settings")
            .contains(r#""aasmManaged":true"#),
        "a run that reported `changed` restored nothing: {:?}",
        h.settings_contents()
    );
}

/// Removal's receipt story, in both directions: the run that reports `changed`
/// consumes the receipt, and the run that reports `unchanged` finds none and
/// creates none.
#[test]
fn the_removal_receipt_agrees_with_the_reported_outcome() {
    let h = Harness::start();
    h.install();
    assert!(h.receipt().is_some(), "the install wrote no receipt");

    let changed = h.aasm(&["remove", "claude-code", "--yes"]);
    assert_eq!(code(&changed), exit::SUCCESS, "{}", combined(&changed));
    assert!(stdout(&changed).contains("— changed"), "{}", stdout(&changed));
    assert!(
        h.receipt().is_none(),
        "a removal that reported `changed` left its receipt behind"
    );

    let unchanged = h.aasm(&["remove", "claude-code", "--yes"]);
    assert_eq!(code(&unchanged), exit::SUCCESS, "{}", combined(&unchanged));
    assert!(stdout(&unchanged).contains("— unchanged"), "{}", stdout(&unchanged));
    assert!(
        h.receipt().is_none(),
        "a removal that reported `unchanged` created a receipt"
    );
}

// ── 4. repeated idempotent invocation ────────────────────────────────────────

/// The headline case. The same command, twice, with no intervening change:
/// `changed` then `unchanged`, exit `0` both times, and **distinguishable
/// output on every surface a caller reads**.
///
/// The exit-code assertions here are the weakest ones in the test on purpose —
/// they are identical on both runs, which is precisely why the contract needed
/// something else.
#[test]
fn removing_twice_reads_as_changed_then_unchanged_at_exit_zero() {
    let h = Harness::start();
    h.install();

    let first = h.aasm(&["remove", "claude-code", "--yes"]);
    let second = h.aasm(&["remove", "claude-code", "--yes"]);

    assert_eq!(code(&first), exit::SUCCESS, "{}", combined(&first));
    assert_eq!(code(&second), exit::SUCCESS, "{}", combined(&second));
    assert_eq!(
        code(&first),
        code(&second),
        "the two runs were told apart by the exit code, which is not the contract"
    );

    assert!(stdout(&first).contains("— changed"), "{}", stdout(&first));
    assert!(stdout(&second).contains("— unchanged"), "{}", stdout(&second));
    assert_ne!(
        stdout(&first).lines().next(),
        stdout(&second).lines().next(),
        "the two runs produced the same first line"
    );
}

/// The same for `repair`, over the sequence a script actually runs: drift,
/// repair it, repair again.
#[test]
fn repairing_twice_reads_as_changed_then_unchanged_at_exit_zero() {
    let h = Harness::start();
    h.install();
    h.tamper();

    let first = h.aasm(&["repair", "claude-code", "--yes"]);
    let second = h.aasm(&["repair", "claude-code", "--yes"]);

    assert_eq!(code(&first), exit::SUCCESS, "{}", combined(&first));
    assert_eq!(code(&second), exit::SUCCESS, "{}", combined(&second));

    assert!(stdout(&first).contains("— changed"), "{}", stdout(&first));
    assert!(stdout(&second).contains("— unchanged"), "{}", stdout(&second));
    assert_ne!(
        stdout(&first).lines().next(),
        stdout(&second).lines().next(),
        "the two runs produced the same first line"
    );
    // The prose half of the no-op, from AAASM-5455, still rides with it and
    // still names *which* no-op this is.
    assert!(
        stdout(&second).contains("already matches its receipt"),
        "{}",
        stdout(&second)
    );
    assert!(
        !stdout(&first).contains("already matches its receipt"),
        "the run that restored a key claimed nothing needed restoring: {}",
        stdout(&first)
    );
}

/// The exact shell line AAASM-5455 was reported against, and the one that
/// replaces it. Asserted as a *shell* result, because that is the form the
/// complaint took.
#[test]
fn the_reported_shell_idiom_no_longer_lies() {
    let h = Harness::start();
    // Nothing is installed at all — the state the original report was about.
    let output = h.aasm(&["repair", "claude-code", "--yes", "--output", "json"]);

    // `&& echo repaired` still fires, because a no-op is still a success. That
    // is the ratified decision, and it is why the idiom itself is the bug.
    assert_eq!(code(&output), exit::SUCCESS, "{}", combined(&output));

    // The replacement idiom does not.
    assert_eq!(
        json_outcome(&output).as_deref(),
        Some("unchanged"),
        "the caller has no way to tell this was a no-op: {}",
        combined(&output)
    );
}

// ── falsification ────────────────────────────────────────────────────────────

/// Both mutations the ticket requires, run against the assertions above.
///
/// A build that reported `changed` for everything, and a build that reported
/// `unchanged` for everything, would each satisfy every exit-code assertion in
/// this file — both mutations exit `0` on both runs. This test states, as
/// executable assertions over one real pair of runs, which specific comparisons
/// are the ones that fail:
///
/// - **always-`changed`** is caught by the second run reporting `unchanged`, on
///   stdout and in JSON;
/// - **always-`unchanged`** is caught by the first run reporting `changed`, on
///   stdout and in JSON;
/// - and neither is caught by the exit codes, which this test asserts are
///   *equal* — so nobody can later "simplify" the file down to them.
#[test]
fn the_two_falsifying_mutations_are_both_caught() {
    let h = Harness::start();
    h.install();

    let first = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    let second = h.aasm(&["remove", "claude-code", "--yes", "--output", "json"]);
    let first_table = h.aasm(&["status", "claude-code"]); // keep the harness honest: it still answers
    assert!(!stdout(&first_table).is_empty());

    let (a, b) = (json_outcome(&first), json_outcome(&second));

    // Kills the always-`unchanged` mutation.
    assert_eq!(a.as_deref(), Some("changed"), "always-unchanged would pass here");
    // Kills the always-`changed` mutation.
    assert_eq!(b.as_deref(), Some("unchanged"), "always-changed would pass here");
    // And a mutation that made both report the same token, whichever it is.
    assert_ne!(a, b, "both runs reported the same outcome");

    // The exit code catches neither. Asserted, so that a future simplification
    // that drops the token assertions above cannot claim the codes cover it.
    assert_eq!(
        code(&first),
        code(&second),
        "the exit codes differ, so this file's premise no longer holds — \
         re-read the ratified contract before changing it"
    );
}
