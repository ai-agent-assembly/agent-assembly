//! `aasm integrations` refuses a runtime it cannot identify (AAASM-5628).
//!
//! # What these tests prove that the unit tests cannot
//!
//! `aa-runtime`'s own suite proves the *verdict* is computed correctly. These
//! prove the consequence a user and a QA harness actually meet: the command
//! exits non-zero, prints nothing on stdout, and says why on stderr. That
//! distinction is the whole bug. Both reproductions in the ticket had a correct
//! internal state and a **confident wrong answer on stdout** — most sharply:
//!
//! ```console
//! $ aasm integrations plan claude-code …
//! error: Claude Code is not installed on this host      # exit 3
//! $ command -v claude ; claude --version
//! /opt/homebrew/bin/claude
//! 2.1.220 (Claude Code)
//! ```
//!
//! A contributor without a pre-merge binary to compare against would
//! reasonably have filed that as a regression, or "fixed" a detection path that
//! was never broken. [`a_deleted_executable_never_produces_the_not_installed_answer`]
//! is that exact console session, asserted.
//!
//! Each test runs the compiled `aasm` binary as a subprocess against a real
//! `DevIntServer` on a real socket, because "what the command printed" is not a
//! property any in-process call can observe.
//!
//! # Nothing here touches the developer's real configuration
//!
//! Every test redirects `AA_DEVINT_SOCKET`, `AA_DEVINT_TOKEN_FILE`,
//! `AASM_STATE_DIR` and `HOME` into its own `TempDir`.

use std::path::PathBuf;
use std::process::Output;
use std::sync::Arc;

use aa_core::dev_tool::DevToolKind;
use aa_core::integration::ReceiptStore;
use aa_runtime::devint::fixture::FixtureIntegration;
use aa_runtime::devint::provenance::{BuildIdentity, IdentitySource, RuntimeProvenance, BUILD_SHA};
use aa_runtime::devint::{
    DevIntServer, DevIntServerConfig, DevIntServices, EngineLifecycle, RegisteredIntegration, TokenStore,
};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The exit code `aasm integrations` uses when the runtime that answered was
/// shown **not** to be this build — a positive finding, refused everywhere.
const EXIT_RUNTIME_UNVERIFIED: i32 = 10;

/// The exit code for a runtime whose identity could be neither confirmed nor
/// refuted. An absence: read-only commands proceed and label it, privileged
/// ones refuse with this.
const EXIT_RUNTIME_UNVERIFIABLE: i32 = 11;

/// The exit code for "this tool is not installed here" — the answer a stale
/// runtime produced for a tool that *was* installed.
const EXIT_UNSUPPORTED: i32 = 3;

/// A SHA that is definitely not this build's.
const OTHER_BUILD_SHA: &str = "1111111111111111111111111111111111111111";

/// What the runtime's adapter says about Claude Code on *its* host.
#[derive(Debug, Clone, Copy)]
enum ToolPresence {
    /// Installed — the truth on the host these tests run on.
    Detected,
    /// Absent. A stale runtime describes a host that no longer exists, which is
    /// how a healthy Claude Code 2.1.220 got reported as `not_installed`.
    Undetected,
}

/// A running DI-API server, reporting provenance the test chooses.
struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    token_file: PathBuf,
    /// Shared by every runtime this harness starts, so a second one accepts the
    /// same enrolled token. Two real runtimes would each have their own book
    /// and the last to enrol would own the token file — which would make the
    /// duplicate test fail on authentication instead of on multiplicity, and
    /// prove the wrong thing.
    tokens: TokenStore,
    shutdown: CancellationToken,
    servers: Vec<std::thread::JoinHandle<()>>,
}

impl Harness {
    /// Start one server reporting `provenance`, on `devint.sock`, whose
    /// fixture reports Claude Code as installed.
    fn start(provenance: RuntimeProvenance) -> Self {
        Self::start_with(provenance, ToolPresence::Detected)
    }

    /// Start a server whose fixture answers `presence` for Claude Code.
    ///
    /// `ToolPresence::Undetected` is the stale runtime's answer: it describes
    /// *its* host, which no longer exists, so it reports a tool that is
    /// installed and healthy here as absent.
    fn start_with(provenance: RuntimeProvenance, presence: ToolPresence) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&run).expect("run dir");
        let socket = run.join("devint.sock");
        let token_file = run.join("devint.token");

        std::env::set_var("AA_DEVINT_TOKEN_FILE", &token_file);
        std::env::set_var("AA_DEVINT_SOCKET", &socket);

        let tokens = TokenStore::new();
        aa_runtime::devint::enrol_local_client(&tokens, "aasm", aa_core::integration::now_unix_secs()).expect("enrol");

        let mut harness = Self {
            dir,
            socket: socket.clone(),
            token_file,
            tokens: tokens.clone(),
            shutdown: CancellationToken::new(),
            servers: Vec::new(),
        };
        harness.spawn_server(socket, provenance, tokens, presence);
        harness
    }

    /// Add a second runtime beside the first, in the same run directory.
    ///
    /// The only shape the duplicate case can take: a second bind on the *same*
    /// path unlinks the first, so two reachable runtimes always sit on two
    /// names.
    fn add_second_runtime(&mut self, provenance: RuntimeProvenance) {
        let second = self.socket.parent().expect("run dir").join("devint-second.sock");
        let tokens = self.tokens.clone();
        self.spawn_server(second, provenance, tokens, ToolPresence::Detected);
    }

    fn spawn_server(
        &mut self,
        socket: PathBuf,
        provenance: RuntimeProvenance,
        tokens: TokenStore,
        presence: ToolPresence,
    ) {
        let settings = self.dir.path().join(format!(
            "settings-{}.json",
            socket.file_name().and_then(|n| n.to_str()).unwrap_or("x")
        ));
        let store_root = self.dir.path().join("state/integrations");

        let fixture = FixtureIntegration::new(DevToolKind::ClaudeCode, &settings);
        let fixture = match presence {
            ToolPresence::Detected => fixture,
            ToolPresence::Undetected => fixture.undetected(),
        };
        let lifecycle = Arc::new(EngineLifecycle::new(
            vec![RegisteredIntegration::new(DevToolKind::ClaudeCode, Arc::new(fixture))],
            ReceiptStore::at(&store_root),
        ));

        let services = DevIntServices {
            lifecycle,
            tokens,
            audit: Arc::new(aa_runtime::devint::audit::TracingAuditSink),
            provenance: Arc::new(provenance),
        };
        let server_token = self.shutdown.clone();
        let config = DevIntServerConfig {
            socket_path: socket.clone(),
            max_connections: 8,
        };
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let server = DevIntServer::bind(config).expect("bind");
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
        assert!(socket.exists(), "the test server never bound {}", socket.display());
        self.servers.push(handle);
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
            .env("AASM_API_KEY", "");
        cmd.output().expect("run aasm")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for handle in self.servers.drain(..) {
            let _ = handle.join();
        }
        std::env::remove_var("AA_DEVINT_SOCKET");
        std::env::remove_var("AA_DEVINT_TOKEN_FILE");
    }
}

fn code(output: &Output) -> i32 {
    output.status.code().expect("exit code")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Provenance for a live runtime from a *different* checkout.
fn another_checkout(exe: PathBuf) -> RuntimeProvenance {
    RuntimeProvenance {
        identity: BuildIdentity {
            core_version: BuildIdentity::of_this_build().core_version,
            build_sha: OTHER_BUILD_SHA.to_string(),
            // Authoritative on purpose: this must be refused as a *different*
            // build, not merely as one that cannot say what it is.
            sha_source: IdentitySource::Checkout,
        },
        pid: 87_718,
        executable_path: exe,
        source_path: "/Users/dev/aa-qa-base".to_string(),
        started_at_unix_secs: 1_700_000_000,
    }
}

/// Provenance for a runtime that carries **no** build identity at all.
///
/// What a binary built outside any checkout reports: `build_sha = "unknown"`
/// from an `absent` source. Nothing about it is wrong — it simply cannot say
/// what it is, which is a different situation from being the wrong build and
/// gets a different answer.
fn no_build_identity(exe: PathBuf) -> RuntimeProvenance {
    RuntimeProvenance {
        identity: BuildIdentity {
            core_version: BuildIdentity::of_this_build().core_version,
            build_sha: "unknown".to_string(),
            sha_source: IdentitySource::Absent,
        },
        pid: 24_601,
        executable_path: exe,
        source_path: String::new(),
        started_at_unix_secs: 1_700_000_000,
    }
}

/// A binary that exists on disk, so a mismatch test fails on identity alone.
fn live_binary(dir: &std::path::Path, name: &str) -> PathBuf {
    let exe = dir.join(name);
    std::fs::write(&exe, b"a real binary").expect("write");
    exe
}

/// Falsification — a client from build B against a runtime from build A must
/// not produce an answer.
///
/// The command exits 10 and stdout is **empty**: a harness has nothing to
/// record, which is the property the whole ticket is about. A warning beside a
/// confident report on stdout would not be one.
#[test]
fn a_runtime_from_another_build_refuses_instead_of_answering() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let harness = Harness::start(another_checkout(live_binary(scratch.path(), "aa-runtime")));

    let output = harness.aasm(&["list", "--output", "json"]);
    assert_eq!(code(&output), EXIT_RUNTIME_UNVERIFIED, "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).trim().is_empty(),
        "a refused command must produce no report to record, got: {}",
        stdout(&output)
    );

    let err = stderr(&output);
    assert!(err.contains("87718"), "the answering pid must be named: {err}");
    assert!(err.contains(&OTHER_BUILD_SHA[..12]), "{err}");
    assert!(err.contains(&BUILD_SHA[..BUILD_SHA.len().min(12)]), "{err}");
    assert!(err.contains("aa-qa-base"), "the peer's checkout is worth naming: {err}");
    assert!(!err.contains("not installed"), "{err}");
}

/// Falsification — the ticket's second reproduction, asserted as the console
/// session it was reported as.
///
/// A runtime whose executable has been deleted keeps serving and answers about
/// *its* host. `plan` used to exit 3 with "Claude Code is not installed on this
/// host" while Claude Code was healthy and on `PATH`. That answer is the
/// dangerous one, so this test asserts both halves: the right exit code, and
/// the **absence** of the plausible wrong sentence.
///
/// The runtime here reports **this build's identity** — only its binary is
/// gone. A fix that only compares build SHAs cannot pass this test.
#[test]
fn a_deleted_executable_never_produces_the_not_installed_answer() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let exe = live_binary(scratch.path(), "aa-runtime");
    // The fixture reports Claude Code as absent, exactly as the stale runtime
    // did. Without the provenance check this command reaches `plan`'s
    // detection gate and exits 3 with the sentence below — so the assertions
    // that it does not are load-bearing rather than vacuous.
    let harness = Harness::start_with(
        RuntimeProvenance {
            executable_path: exe.clone(),
            ..RuntimeProvenance::detect()
        },
        ToolPresence::Undetected,
    );
    // The worktree goes away while the runtime keeps serving.
    std::fs::remove_file(&exe).expect("delete the executable");

    let output = harness.aasm(&["plan", "claude-code"]);
    let err = stderr(&output);

    assert_ne!(
        code(&output),
        EXIT_UNSUPPORTED,
        "a stale runtime must never be reported as a missing tool: {err}"
    );
    assert!(
        !err.contains("is not installed on this host"),
        "the exact sentence that was mistaken for a regression: {err}"
    );
    assert_eq!(code(&output), EXIT_RUNTIME_UNVERIFIED, "stderr: {err}");
    assert!(stdout(&output).trim().is_empty(), "{}", stdout(&output));
    assert!(err.contains("no longer exists"), "{err}");
    assert!(
        err.contains(&exe.display().to_string()),
        "the vanished executable must be named: {err}"
    );
}

/// Falsification — two runtimes from the **same** build, both listening.
///
/// Both pass every identity check; the refusal comes from the count. This is
/// what makes the test independent of the mismatch case: a fix that only
/// compares build identity leaves both runtimes verified and this test failing.
#[test]
fn two_runtimes_of_one_build_are_reported_rather_than_silently_resolved() {
    let mut harness = Harness::start(RuntimeProvenance::detect());
    harness.add_second_runtime(RuntimeProvenance::detect());

    let output = harness.aasm(&["list"]);
    let err = stderr(&output);
    assert_eq!(code(&output), EXIT_RUNTIME_UNVERIFIED, "stderr: {err}");
    assert!(stdout(&output).trim().is_empty(), "{}", stdout(&output));
    assert!(err.contains("2 Agent Assembly runtimes"), "{err}");
    assert!(err.contains("devint-second.sock"), "the other must be named: {err}");
    assert!(
        !err.contains("not installed"),
        "a duplicate must not read as a product answer: {err}"
    );
}

/// …and the escape hatch does not turn a duplicate into a verified result.
///
/// `--allow-unverified-runtime` bypasses the multiplicity refusal, so the
/// command answers. What it must not do is publish
/// `{"standing": "verified", "reachable_runtimes": 2}` — the CLI reference tells
/// a wrapper to branch on `standing` alone, and two runtimes compiled from one
/// commit have identical identities, so the identity `verdict` genuinely is
/// `verified` and cannot be what a harness reads.
#[test]
fn the_escape_hatch_does_not_make_one_of_two_runtimes_verified() {
    let mut harness = Harness::start(RuntimeProvenance::detect());
    harness.add_second_runtime(RuntimeProvenance::detect());

    let output = harness.aasm(&["list", "--output", "json", "--allow-unverified-runtime"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));

    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    let provenance = &report["runtime"]["provenance"];
    assert_eq!(provenance["reachable_runtimes"], 2, "{provenance}");
    if BuildIdentity::of_this_build().is_authoritative() {
        // Without this the assertion below could pass for the wrong reason —
        // an unidentifiable build is not `verified` whatever the population is.
        assert_eq!(
            provenance["verdict"], "verified",
            "the identity comparison must have succeeded, or the next assertion proves nothing: {provenance}"
        );
    }
    assert_ne!(
        provenance["standing"], "verified",
        "a result from one of two runtimes was recorded as verified: {provenance}"
    );
    assert!(
        provenance["detail"]
            .as_str()
            .expect("detail")
            .contains("2 Agent Assembly runtimes"),
        "the standing must carry its reason: {provenance}"
    );
}

/// The QA-harness requirement: a recorded result names the process that
/// produced it.
///
/// `pid`, `build_sha` and `executable_path` reach `--output json` on both the
/// surfaces AAASM-5628 names — `status` and `list` — so evidence can be
/// attributed rather than asserted.
#[test]
fn a_verified_run_carries_the_answering_build_and_pid_into_json() {
    let harness = Harness::start(RuntimeProvenance::detect());

    for args in [
        vec!["list", "--output", "json"],
        vec!["status", "claude-code", "--output", "json"],
    ] {
        let output = harness.aasm(&args);
        let out = stdout(&output);
        let report: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("{args:?} did not produce JSON ({e}): {out}\n{}", stderr(&output)));
        let provenance = &report["runtime"]["provenance"];

        assert_eq!(provenance["verdict"], "verified", "{args:?}: {provenance}");
        assert_eq!(
            provenance["build_sha"].as_str().expect("build_sha"),
            BUILD_SHA,
            "{args:?}"
        );
        assert_eq!(
            provenance["pid"].as_u64().expect("pid"),
            u64::from(std::process::id()),
            "{args:?}: the pid must be the process that actually served"
        );
        assert_eq!(provenance["executable_present"], true, "{args:?}");
        assert_eq!(provenance["reachable_runtimes"], 1, "{args:?}");
        assert!(
            !provenance["executable_path"].as_str().expect("path").is_empty(),
            "{args:?}"
        );
    }
}

/// `list`'s banner names the build for a human, not only for `jq`.
///
/// The banner said `core <version> (DI-API vN)`, which two checkouts share —
/// so a whole campaign ran against the wrong build with nothing on screen
/// disagreeing.
#[test]
fn the_list_banner_names_the_build_that_answered() {
    let harness = Harness::start(RuntimeProvenance::detect());
    let output = harness.aasm(&["list"]);
    let out = stdout(&output);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(out.contains("Agent Assembly core"), "{out}");
    assert!(out.contains(&BUILD_SHA[..BUILD_SHA.len().min(12)]), "{out}");
    assert!(
        out.contains(&format!("pid {}", std::process::id())),
        "the banner must name the answering process: {out}"
    );
}

/// The escape hatch downgrades the refusal to a warning — and the result it
/// then produces is still *marked* unverified.
///
/// A hatch that suppressed the verdict would recreate the defect for anyone who
/// used it: the point is that an unverified result must never be recorded as a
/// verified one, not that it can never be obtained.
#[test]
fn the_escape_hatch_still_marks_the_result_as_unverified() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let harness = Harness::start(another_checkout(live_binary(scratch.path(), "aa-runtime")));

    let output = harness.aasm(&["list", "--output", "json", "--allow-unverified-runtime"]);
    assert_eq!(code(&output), 0, "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("unverified"),
        "the warning must still be visible: {}",
        stderr(&output)
    );

    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    let provenance = &report["runtime"]["provenance"];
    assert_eq!(
        provenance["verdict"], "mismatch",
        "the recorded result must carry its own doubt: {provenance}"
    );
    assert_eq!(provenance["build_sha"], OTHER_BUILD_SHA);
    assert_eq!(provenance["pid"], 87_718);
}

/// A privileged operation refuses a runtime whose identity cannot be
/// established — the owner decision's rule, asserted per command.
///
/// `install`, `repair` and `remove` change host state; `verify` asserts that
/// enforcement is established. Each produces a claim *about a build*, and a
/// claim attributed to a runtime that cannot be identified is unfounded rather
/// than merely weak. Exit 11 — distinct from 10, because nothing here was shown
/// to be *wrong*; it could not be shown to be right.
///
/// Downgrading `Sensitivity::Privileged` to `ReadOnly` for any of these turns
/// the exit code into 0 and fails here.
#[test]
fn privileged_operations_refuse_an_unverifiable_runtime() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let harness = Harness::start(no_build_identity(live_binary(scratch.path(), "aa-runtime")));

    for args in [
        vec!["install", "claude-code", "--yes"],
        vec!["verify", "claude-code"],
        vec!["repair", "claude-code", "--yes"],
        vec!["remove", "claude-code", "--yes"],
    ] {
        let output = harness.aasm(&args);
        let err = stderr(&output);
        assert_eq!(
            code(&output),
            EXIT_RUNTIME_UNVERIFIABLE,
            "{args:?} must refuse an unidentifiable runtime: {err}"
        );
        assert!(
            stdout(&output).trim().is_empty(),
            "{args:?} must produce no report to record, got: {}",
            stdout(&output)
        );
        // Named, not generic — and never a plausible product answer.
        assert!(
            err.contains("24601"),
            "{args:?}: the answering pid must be named: {err}"
        );
        assert!(
            err.contains("unverifiable"),
            "{args:?}: the standing must be stated: {err}"
        );
        assert!(
            err.contains("build_sha"),
            "{args:?}: the absent field must be named: {err}"
        );
        assert!(!err.contains("not installed"), "{args:?}: {err}");
    }
}

/// A read-only surface still answers, and reports the provenance truthfully.
///
/// Refusing here would make an unidentifiable runtime undiagnosable: these are
/// exactly the commands an operator uses to find out which runtime answered and
/// stop the wrong one. What must never happen is the answer arriving *dressed
/// as verified* — so this asserts both halves.
#[test]
fn read_only_surfaces_report_an_unverifiable_runtime_truthfully() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let harness = Harness::start(no_build_identity(live_binary(scratch.path(), "aa-runtime")));

    for args in [
        vec!["list", "--output", "json"],
        vec!["status", "claude-code", "--output", "json"],
    ] {
        let output = harness.aasm(&args);
        let out = stdout(&output);
        assert_eq!(
            code(&output),
            0,
            "{args:?} is read-only and must answer: {}",
            stderr(&output)
        );

        let report: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("{args:?} did not produce JSON ({e}): {out}\n{}", stderr(&output)));
        let provenance = &report["runtime"]["provenance"];

        // Never verified, never matching — in the JSON a harness records.
        assert_eq!(provenance["standing"], "unverifiable", "{args:?}: {provenance}");
        assert_eq!(provenance["verdict"], "unverifiable", "{args:?}: {provenance}");
        assert_ne!(provenance["standing"], "verified", "{args:?}: {provenance}");
        assert_eq!(provenance["build_id_source"], "absent", "{args:?}: {provenance}");
        assert_eq!(provenance["pid"], 24_601, "{args:?}: {provenance}");

        // The diagnostic names which fields were absent, matched or mismatched.
        let fields = provenance["fields"].as_array().expect("fields");
        let build_sha = fields
            .iter()
            .find(|f| f["field"] == "build_sha")
            .unwrap_or_else(|| panic!("{args:?}: build_sha not reported: {provenance}"));
        assert_eq!(build_sha["status"], "absent", "{args:?}: {provenance}");
        assert!(
            fields
                .iter()
                .any(|f| f["status"] == "matched" || f["status"] == "absent"),
            "{args:?}: every field must state what it did: {provenance}"
        );

        // …and the operator is told on stderr, not only in the JSON.
        assert!(
            stderr(&output).contains("unverifiable"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

/// The whole three-state rule, on one command, in one place.
///
/// `plan` is read-only, so its exit code is a clean readout of the standing:
/// 0 for verified and unverifiable, 10 for refuted. Collapsing `unverifiable`
/// back into either neighbour changes one of these three and fails here.
#[test]
fn one_read_only_command_distinguishes_all_three_standings() {
    let scratch = tempfile::tempdir().expect("tempdir");

    // Refuted — a different build. Read-only refuses too: it was shown wrong.
    let refuted = Harness::start(another_checkout(live_binary(scratch.path(), "wrong-build")));
    assert_eq!(
        code(&refuted.aasm(&["plan", "claude-code"])),
        EXIT_RUNTIME_UNVERIFIED,
        "a runtime shown to be another build is refused even by a read-only command"
    );
    drop(refuted);

    // Unverifiable — no identity on the peer. Read-only answers.
    let unverifiable = Harness::start(no_build_identity(live_binary(scratch.path(), "no-identity")));
    let output = unverifiable.aasm(&["plan", "claude-code", "--output", "json"]);
    assert_eq!(
        code(&output),
        0,
        "a read-only command must still answer: {}",
        stderr(&output)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
    assert_eq!(report["runtime"]["provenance"]["standing"], "unverifiable");
    drop(unverifiable);

    // Verified — this build, when this build has an identity to compare.
    if BuildIdentity::of_this_build().is_authoritative() {
        let verified = Harness::start(RuntimeProvenance::detect());
        let output = verified.aasm(&["plan", "claude-code", "--output", "json"]);
        assert_eq!(code(&output), 0, "{}", stderr(&output));
        let report: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("json");
        assert_eq!(report["runtime"]["provenance"]["standing"], "verified");
    }
}

/// A read-only `status` may answer under an unverifiable standing — it may not
/// let `host_enforced  active` stand as an established claim about this host.
///
/// The narrowest reading of "read-only surfaces may proceed" that is still
/// honest. Every protection level in that block describes whatever host the
/// answering runtime is on, and if that runtime cannot be identified, neither
/// can the host. So the ladder carries the caveat immediately above it, rather
/// than only in the `Runtime:` block a reader may have scrolled past.
///
/// Removing the caveat leaves the level rendering unchanged and fails here.
#[test]
fn a_status_ladder_from_an_unidentifiable_runtime_is_marked_as_reported_not_established() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let harness = Harness::start(no_build_identity(live_binary(scratch.path(), "aa-runtime")));

    let output = harness.aasm(&["status", "claude-code"]);
    let out = stdout(&output);
    assert_eq!(code(&output), 0, "status is read-only: {}", stderr(&output));

    let ladder = out
        .find("Protection levels:")
        .unwrap_or_else(|| panic!("no protection ladder rendered: {out}"));
    let caveat = out
        .find("attributable to this build")
        .unwrap_or_else(|| panic!("the ladder must carry its caveat: {out}"));
    assert!(
        caveat < ladder,
        "the caveat must precede the levels a reader is about to believe: {out}"
    );
    assert!(out.contains("reported, not established"), "{out}");
    assert!(out.contains("unverifiable"), "{out}");
}

/// …and a verified runtime does not get the caveat, so it is not noise.
#[test]
fn a_verified_status_ladder_carries_no_caveat() {
    if !BuildIdentity::of_this_build().is_authoritative() {
        return;
    }
    let harness = Harness::start(RuntimeProvenance::detect());
    let output = harness.aasm(&["status", "claude-code"]);
    let out = stdout(&output);
    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(out.contains("Protection levels:"), "{out}");
    assert!(
        !out.contains("attributable to this build"),
        "a verified reading must not be hedged: {out}"
    );
}
