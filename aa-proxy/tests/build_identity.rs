//! AAASM-5984 AC1/AC6: `aa-proxy` states its build identity in `--version`
//! and its startup log — assert against the real compiled binary, not a
//! stub, so a regression in the derive attribute or the startup log call
//! actually reddens this.
//!
//! `env!("CARGO_BIN_EXE_aa-proxy")` makes cargo build the binary as a
//! dependency of this test target, so its existence is guaranteed by
//! construction — no precondition guard needed.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_runtime::build_identity::{
    parse_version_banner, BuildIdentity, IdentitySource, BUILD_IDENTITY_SOURCE, BUILD_SHA,
};

fn version_output() -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_aa-proxy"))
        .arg("--version")
        .output()
        .expect("run aa-proxy --version");
    assert!(out.status.success(), "aa-proxy --version should exit 0");
    String::from_utf8(out.stdout).expect("--version output is UTF-8")
}

/// AC6: the identity `--version` states equals the compiled constant.
#[test]
fn version_output_states_the_compiled_build_identity() {
    let recovered = parse_version_banner(&version_output());
    assert_eq!(recovered.build_sha, BUILD_SHA);
    assert_eq!(recovered.sha_source, IdentitySource::from_wire(BUILD_IDENTITY_SOURCE));
}

/// Falsification 2: a test that only checks "a version string was printed"
/// cannot distinguish this binary from one built at a different commit. Prove
/// it by constructing that exact foreign banner (same version, different
/// SHA) and showing the version-only assertion still passes while the
/// identity assertion fails.
#[test]
fn a_version_only_assertion_cannot_distinguish_a_foreign_build() {
    let real_output = version_output();
    let real = parse_version_banner(&real_output);

    let foreign_output = real_output.replacen(BUILD_SHA, &"f".repeat(BUILD_SHA.len().max(8)), 1);
    let foreign = parse_version_banner(&foreign_output);

    // The version-only assertion cannot tell these apart.
    assert_eq!(real.core_version, foreign.core_version);
    // The identity assertion can — this is the whole point of AC1/AC3.
    assert_ne!(
        real.build_sha, foreign.build_sha,
        "the fixture must actually change the SHA"
    );
}

/// AC4: `--version` never prints a fabricated identity. Not reachable against
/// the real binary in-tree (there is always a checkout on this machine, so
/// `build.rs` resolves `checkout`) — see
/// `aa_runtime::build_identity::tests` for the sentinel path exercised
/// directly against fabricated banners.
#[test]
fn version_output_never_reports_an_empty_sha_as_authoritative() {
    let recovered = parse_version_banner(&version_output());
    assert!(!recovered.build_sha.is_empty());
    if recovered.build_sha == aa_runtime::build_identity::UNKNOWN_SHA {
        assert_eq!(recovered.sha_source, IdentitySource::Absent);
    }
}

/// AC1: the startup log line names the build, so an operator or a script
/// reading stderr (not just `--version`) can attribute a run to a commit.
/// `AA_PROXY_ADDR=not-an-address` makes `main` fail fast at config parsing,
/// after the identity line but before anything with a port, a CA, or a
/// keychain prompt — deterministic and cheap.
#[test]
fn startup_log_states_the_build_identity() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aa-proxy"))
        .env("RUST_LOG", "info")
        .env("AA_PROXY_ADDR", "not-an-address")
        // tracing_subscriber::fmt()'s default writer is stdout, not stderr —
        // capture both rather than assuming which one carries the log line.
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aa-proxy");

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("aa-proxy did not exit within 10s against an invalid AA_PROXY_ADDR");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(!status.success(), "an invalid AA_PROXY_ADDR should fail config parsing");

    let mut stdout = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take().expect("piped stdout"), &mut stdout).expect("read stdout");
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().expect("piped stderr"), &mut stderr).expect("read stderr");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains(BUILD_SHA) && combined.contains("aa-proxy starting"),
        "startup log should state the build identity; got:\n{combined}"
    );
}

/// AC6, structural: a `BuildIdentity::of_this_build()` call made from this
/// integration-test binary must equal the one the running `aa-proxy` binary
/// reports — same compiled constants, same `cargo build`.
#[test]
fn this_build_identity_matches_the_probed_binary() {
    let compiled = BuildIdentity::of_this_build();
    let probed = parse_version_banner(&version_output());
    assert_eq!(compiled.build_sha, probed.build_sha);
    assert_eq!(compiled.sha_source, probed.sha_source);
}
