//! `aasm integrations` against a socket that accepts and never answers
//! (AAASM-5667).
//!
//! # The situation
//!
//! `~/.aa/run/` is owner-only, so anything that can bind a `devint*.sock` there
//! is already the same user — inside the trust boundary ADR 0030 §5.1 draws.
//! What that process can still do is *bind and not serve*: accept the
//! connection and answer nothing. Neither half of the client's handshake was
//! bounded, so `aasm integrations` waited on it forever — and it is precisely
//! the command an operator runs to find out what the runtime is doing.
//!
//! This is therefore an **availability** regression test, not an
//! authentication one. What it asserts is that the CLI *comes back*: with a
//! diagnosis, a non-zero exit, and in bounded time.

use std::path::PathBuf;
use std::process::Output;
use std::time::{Duration, Instant};

use aa_runtime::devint::TokenStore;

/// Generous relative to the client's 5s handshake bound, tight enough that a
/// genuine hang cannot pass: the point is "it returned", not "it was fast".
const MUST_RETURN_WITHIN: Duration = Duration::from_secs(60);

/// A socket that accepts every connection and answers nothing.
///
/// Runs on its own thread with its own current-thread runtime so the accepted
/// streams stay alive for as long as the fixture does — dropping them would
/// give the client an EOF, which it already handles, and would test the wrong
/// thing.
struct StalledRuntime {
    dir: tempfile::TempDir,
    socket: PathBuf,
    token_file: PathBuf,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl StalledRuntime {
    fn start() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let run = dir.path().join("run");
        std::fs::create_dir_all(&run).expect("run dir");
        let socket = run.join("devint.sock");
        let token_file = run.join("devint.token");

        // The CLI reads the enrolment token before it connects, so it has to be
        // a real one: a missing token would fail the command earlier and prove
        // nothing about the handshake. `AA_DEVINT_TOKEN_FILE` is set and removed
        // within one scope, but `cargo test` runs this file's tests on parallel
        // threads in one process (`cargo nextest` isolates each into its own, so
        // it never contends here) — the env guard keeps a second test's own
        // set/remove pair from landing inside this window (AAASM-5989).
        {
            let _env_guard = aa_cli::env_guard::lock();
            std::env::set_var("AA_DEVINT_TOKEN_FILE", &token_file);
            aa_runtime::devint::enrol_local_client(&TokenStore::new(), "aasm", aa_core::integration::now_unix_secs())
                .expect("enrol");
            std::env::remove_var("AA_DEVINT_TOKEN_FILE");
        }

        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind stalled socket");
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_thread = std::sync::Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            listener.set_nonblocking(true).expect("nonblocking");
            let mut held = Vec::new();
            while !stop_for_thread.load(std::sync::atomic::Ordering::Relaxed) {
                match listener.accept() {
                    // Accepted and kept, deliberately never written to.
                    Ok((stream, _)) => held.push(stream),
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });

        Self {
            dir,
            socket,
            token_file,
            stop,
            server: Some(server),
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
            .env("AASM_API_KEY", "");
        cmd.output().expect("run aasm")
    }
}

impl Drop for StalledRuntime {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.server.take() {
            let _ = handle.join();
        }
    }
}

/// The CLI must return a diagnosis rather than wait on a socket that will never
/// answer.
///
/// `list` is the read-only surface — the one an operator uses to *diagnose* a
/// bad runtime — so it is the worst one to be able to hang.
#[test]
fn integrations_list_does_not_hang_on_a_socket_that_never_answers() {
    let fixture = StalledRuntime::start();

    let started = Instant::now();
    let output = fixture.aasm(&["list"]);
    let elapsed = started.elapsed();

    assert!(
        elapsed < MUST_RETURN_WITHIN,
        "aasm integrations list must return against a non-responsive socket, took {elapsed:?}"
    );
    assert!(
        !output.status.success(),
        "a runtime that never answered must not produce a successful report"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did not complete the DI-API handshake"),
        "the operator must be told what timed out, got: {stderr}"
    );
}

/// **Positive control.** The same command, the same fixture harness, against a
/// path with *no* socket at all, must still reach the runtime-unavailable
/// diagnosis quickly.
///
/// Without this, the test above would pass if `aasm integrations list` had been
/// broken into failing immediately for every reason — the assertion "it came
/// back and it failed" is only meaningful when the failure it names is the
/// handshake and not something upstream of the connection.
#[test]
fn the_same_command_reports_an_absent_socket_differently() {
    let fixture = StalledRuntime::start();
    let missing = fixture.dir.path().join("run").join("devint-absent.sock");

    let mut cmd = assert_cmd::Command::cargo_bin("aasm").expect("aasm binary");
    let output = cmd
        .arg("integrations")
        .arg("list")
        .arg("--no-autostart")
        .env("AA_DEVINT_SOCKET", &missing)
        .env("AA_DEVINT_TOKEN_FILE", &fixture.token_file)
        .env("AASM_STATE_DIR", fixture.dir.path().join("state"))
        .env("HOME", fixture.dir.path())
        .env("AASM_API_KEY", "")
        .output()
        .expect("run aasm");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        !stderr.contains("did not complete the DI-API handshake"),
        "an absent socket is a different diagnosis from a stalled one: {stderr}"
    );
    assert!(
        stderr.contains("not running"),
        "an absent socket must still read as 'the runtime is not running': {stderr}"
    );
}
