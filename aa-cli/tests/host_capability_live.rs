//! Live `aasm host` behaviour against this machine's real Xcode/Simulator
//! toolchain (AAASM-6298, QA ST-11b, journey J89; feature AAASM-6171).
//!
//! **FIDELITY:** `real_local_process` on macOS only. Every test here drives
//! the built `aasm` binary; the gate runs for real and, when it admits,
//! `xcodebuild -list` / `simctl list` really run. Nothing here builds a
//! scheme (no DerivedData / compile-cache writes) and nothing here touches
//! keychain, signing identities, TCC-gated locations or the network.
//!
//! Every toolchain-dependent test is `#[ignore]`d so a host without Xcode
//! reports them as SKIPPED, never as passed. `real_local_process` evidence
//! exists only for a run on a macOS host with Xcode via
//! `cargo nextest run -p aa-cli --test host_capability_live --run-ignored all -E 'not test(desired_)'`;
//! on a host without Xcode that run PANICS (a missing toolchain is a failure,
//! never a silent pass). `AA_REQUIRE_HOST_TOOLCHAIN=1` is also honoured and
//! has the same effect.
#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;

use assert_cmd::Command;

fn toolchain_present() -> bool {
    StdCommand::new("/usr/bin/xcode-select")
        .arg("-p")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        && StdCommand::new("/usr/bin/xcrun")
            .args(["--find", "xcodebuild"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

macro_rules! require_toolchain {
    () => {
        if !toolchain_present() {
            // Reached only when an ignored test is run on purpose: failing loudly
            // keeps "passed" meaning "ran against a real toolchain".
            let required = std::env::var("AA_REQUIRE_HOST_TOOLCHAIN").as_deref() == Ok("1");
            panic!(
                "no Xcode toolchain on this host (AA_REQUIRE_HOST_TOOLCHAIN={required}); \
                 these tests need `xcode-select -p` and `xcrun --find xcodebuild` to succeed"
            );
        }
    };
}

fn aasm() -> Command {
    let mut c = Command::cargo_bin("aasm").expect("aasm binary");
    c.env_remove("CLAUDE_CODE_OAUTH_TOKEN");
    c
}

/// A throwaway SwiftPM package declaring exactly one scheme-producing target.
fn fixture_package() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("Package.swift"),
        "// swift-tools-version:5.9\nimport PackageDescription\nlet package = Package(name: \"QaPkg\", targets: [.target(name: \"QaLib\")])\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join("Sources/QaLib")).unwrap();
    std::fs::write(dir.path().join("Sources/QaLib/QaLib.swift"), "public let qa = 1\n").unwrap();
    dir
}

fn write_lease(dir: &Path, name: &str, subject: &str, not_before: u64, expires: u64) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(
        &p,
        format!(
            "{{\"lease_id\":\"qa-lease\",\"subject_agent_id\":\"{subject}\",\"issuer_agent_id\":\"qa-issuer\",\"basis_reason\":\"qa fixture\",\"not_before_unix_secs\":{not_before},\"expires_at_unix_secs\":{expires}}}"
        ),
    )
    .unwrap();
    p
}

const FAR_FUTURE: u64 = 4_102_444_800; // 2100-01-01

// ---- AC2 (positive): a granted operation runs for real -----------------------

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn granted_xcode_list_really_runs_and_reports_the_real_scheme() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, FAR_FUTURE);
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.contains("QaPkg"),
        "real xcodebuild output must name the package: {stdout}"
    );
}

// ---- AC1 / AC4 (negative controls: each differs from the positive in ONE input) -

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn expired_lease_file_refuses_and_runs_nothing() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, 1_000);
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refused"), "stderr: {stderr}");
    assert!(
        !stdout.contains("QaPkg"),
        "a refused operation must not produce toolchain output"
    );
}

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn not_yet_valid_lease_file_refuses() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(
        pkg.path(),
        "lease.json",
        "aasm-host-operator",
        FAR_FUTURE - 10,
        FAR_FUTURE,
    );
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("refused"));
}

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn missing_or_malformed_lease_file_fails_closed_not_open() {
    require_toolchain!();
    let pkg = fixture_package();
    // missing
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(pkg.path().join("nope.json"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("QaPkg"));
    // malformed
    let bad = pkg.path().join("bad.json");
    std::fs::write(&bad, "{not json").unwrap();
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&bad)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("QaPkg"));
}

/// AC4: a grant that was live for one invocation is withdrawn before the next.
/// `aasm host` is one process per operation and re-reads the lease each time,
/// so withdrawing the grant (expiring the file's window) blocks the next use.
#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn withdrawing_the_grant_between_two_invocations_blocks_the_second() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, FAR_FUTURE);
    let run = |lease: &Path| {
        aasm()
            .args(["host", "xcode", "list", "--project"])
            .arg(pkg.path())
            .arg("--lease-file")
            .arg(lease)
            .output()
            .unwrap()
    };
    assert!(run(&lease).status.success(), "first use under a live grant must run");
    write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, 1_000); // revoke == expire the window
    let second = run(&lease);
    assert!(!second.status.success(), "second use after withdrawal must be refused");
    assert!(String::from_utf8_lossy(&second.stderr).contains("refused"));
    std::fs::remove_file(&lease).unwrap();
    let third = run(&lease);
    assert!(!third.status.success(), "a deleted grant must fail closed");
}

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn a_build_of_a_scheme_the_container_does_not_declare_is_refused_before_any_build() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, FAR_FUTURE);
    let out = aasm()
        .args([
            "host",
            "xcode",
            "build",
            "--scheme",
            "DefinitelyNotAScheme",
            "--project",
        ])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refused") && stderr.contains("DefinitelyNotAScheme"),
        "stderr: {stderr}"
    );
    assert!(
        !pkg.path().join(".aasm-host-derived-data").exists(),
        "a refused build must not create DerivedData"
    );
}

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn argument_injection_into_the_build_is_rejected_by_the_cli_before_the_gate() {
    require_toolchain!();
    let pkg = fixture_package();
    for (flag, bad) in [
        ("--scheme", "-derivedDataPath"),
        ("--scheme", "SWIFT_ACTIVE_COMPILATION_CONDITIONS=INJECTED"),
        ("--configuration", "Debug OTHER_SWIFT_FLAGS=-Xfrontend"),
        ("--destination", "id=x;touch /tmp/aasm-qa-pwn"),
    ] {
        let mut cmd = aasm();
        cmd.args(["host", "xcode", "build", "--project"]).arg(pkg.path());
        if flag != "--scheme" {
            cmd.args(["--scheme", "QaPkg-Package"]);
        }
        // `--flag=value` so clap hands a leading-dash value to the product validator
        // instead of rejecting it as an unknown flag itself.
        let out = cmd.arg(format!("{flag}={bad}")).output().unwrap();
        assert!(!out.status.success(), "{flag}={bad} must fail");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("invalid"),
            "{flag}={bad}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert!(!Path::new("/tmp/aasm-qa-pwn").exists());
}

// ---- AC3: the typed surface offers no generic-exec path -------------------------

#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn the_cli_has_no_subcommand_that_runs_an_arbitrary_host_command() {
    for args in [
        vec!["host", "exec", "--", "/usr/bin/true"],
        vec!["host", "xcode", "exec", "--", "/usr/bin/true"],
        vec!["host", "codesign", "--identity", "x"],
        vec!["host", "simulator", "boot", "--udid", "x"],
        vec!["host", "xcode", "list", "--project", ".", "--", "/usr/bin/true"],
    ] {
        let out = aasm().args(&args).output().unwrap();
        assert!(!out.status.success(), "{args:?} must be rejected");
        assert_eq!(out.status.code(), Some(2), "{args:?} should be a clap usage error");
    }
}

// ---- Real behaviour that does NOT meet the ticket's "not granted must refuse" ----

/// CHARACTERISATION (defect): with no `--lease-file` the contract is
/// `HostCapabilityContract::not_required()`, whose first gate line admits
/// unconditionally. So "no grant" on the CLI is not a refusal: the operation
/// runs ungated. The ticket requires the opposite; see the `#[ignore]`d test.
#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn characterisation_xcode_list_with_no_lease_file_runs_ungated() {
    require_toolchain!();
    let pkg = fixture_package();
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("QaPkg"));
}

/// CHARACTERISATION (defect): `aasm host simulator list` has no `--lease-file`
/// at all and hard-codes `not_required()`, so it can never be refused.
#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn characterisation_simulator_list_has_no_grant_input_and_is_always_ungated() {
    require_toolchain!();
    let out = aasm().args(["host", "simulator", "list", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        !help.contains("lease"),
        "if this starts failing the surface grew a grant input: {help}"
    );
    let rejected = aasm()
        .args(["host", "simulator", "list", "--lease-file", "/nonexistent"])
        .output()
        .unwrap();
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "--lease-file is not accepted on simulator list"
    );
}

/// DESIRED CONTRACT (AAASM-6298 ticket text): a host-capability operation with
/// no grant must be refused. Currently it runs.
#[test]
#[ignore = "product defect: `aasm host xcode list` without --lease-file runs ungated (HostCapabilityContract::not_required admits unconditionally); ticket requires refusal when not granted"]
fn desired_xcode_list_without_a_grant_is_refused() {
    require_toolchain!();
    let pkg = fixture_package();
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(!String::from_utf8_lossy(&out.stdout).contains("QaPkg"));
}

#[test]
#[ignore = "product defect: `aasm host simulator list` has no grant input and is always ungated; ticket requires refusal when not granted"]
fn desired_simulator_list_without_a_grant_is_refused() {
    require_toolchain!();
    let out = aasm().args(["host", "simulator", "list"]).output().unwrap();
    assert!(!out.status.success());
}

// ---- AC2 attribution: what the CLI actually records ------------------------------

/// CHARACTERISATION (defect): the launch identity is the literal
/// `aasm-host-operator`; a lease naming any real agent is refused as "not this
/// launch's own identity". So a grant can only ever be attributed to the CLI's
/// fixed operator id, never to a specific requesting agent.
#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn characterisation_only_the_fixed_operator_identity_can_hold_a_lease_on_the_cli() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "agent-x", 0, FAR_FUTURE);
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not this launch's own identity"), "stderr: {stderr}");
}

/// CHARACTERISATION (defect): a granted, successful operation leaves no record
/// naming the lease or the identity on any stream the CLI writes.
#[test]
#[ignore = "needs an Xcode toolchain; run with --run-ignored all on a macOS host with Xcode"]
fn characterisation_a_granted_operation_emits_no_attribution_record() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "aasm-host-operator", 0, FAR_FUTURE);
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(out.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !all.contains("qa-lease") && !all.contains("aasm-host-operator"),
        "output: {all}"
    );
}

#[test]
#[ignore = "product defect: `aasm host` emits no record of a performed operation (achieved_record/refusal_record have no non-test caller) and cannot hold a lease for a requesting agent; ticket requires the operation be recorded against the requesting identity"]
fn desired_a_granted_operation_is_recorded_against_the_requesting_identity() {
    require_toolchain!();
    let pkg = fixture_package();
    let lease = write_lease(pkg.path(), "lease.json", "agent-x", 0, FAR_FUTURE);
    let out = aasm()
        .args(["host", "xcode", "list", "--project"])
        .arg(pkg.path())
        .arg("--lease-file")
        .arg(&lease)
        .output()
        .unwrap();
    assert!(out.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains("agent-x"));
}
