//! `aasm policy validate` and `aasm lease init --policy` warn where a governed
//! lease runtime would deny a tool (AAASM-6386).
//!
//! Driven against the real binary. Deleted from the published tree with the
//! gate the warnings consult (`.ci/strip-for-publish.sh`).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use assert_cmd::prelude::*;

const UNLEASED: &str = "tools:\n  note_writer: { allow: true, capabilities: [filesystem_write] }\n  calc: { allow: true, capabilities: [none] }\n";
const NO_CAPS: &str = "tools:\n  x: { allow: true }\n";
const LEASED: &str = "tools:\n  note_writer: { allow: true, capabilities: [filesystem_write] }\n  calc: { allow: true, capabilities: [none] }\nauthority:\n  leases:\n    - domain: filesystem_write\n      scope: whole\n      reason: test\n";

fn aasm(home: &Path) -> Command {
    let mut c = Command::cargo_bin("aasm").expect("aasm binary");
    // Hermetic: nothing inherited from the developer's shell may change the run.
    c.env("HOME", home);
    for var in [
        "AA_LEASE_STATE",
        "AA_LEASE_POLICY",
        "AA_AGENT_ID",
        "AA_POLICY",
        "AA_POLICY_PATH",
        "AA_LEASE_HEALTH_URL",
    ] {
        c.env_remove(var);
    }
    c
}

fn policy(dir: &Path, yaml: &str) -> PathBuf {
    let p = dir.join("policy.yaml");
    std::fs::write(&p, yaml).unwrap();
    p
}

fn validate(home: &Path, p: &Path) -> Output {
    aasm(home).args(["policy", "validate"]).arg(p).output().unwrap()
}

fn lease_init(home: &Path, pol: &Path) -> (Output, tempfile::TempDir) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = aasm(home)
        .args(["lease", "init", "--subject", "agent-1", "--policy"])
        .arg(pol)
        .arg("--state")
        .arg(d.path().join("lease.json"))
        .output()
        .unwrap();
    (out, d)
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn validate_warns_about_a_capability_with_no_matching_lease_and_still_succeeds() {
    let d = tempfile::tempdir().unwrap();
    let out = validate(d.path(), &policy(d.path(), UNLEASED));
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Policy is valid"));
    let e = err(&out);
    assert!(
        e.contains("warning:") && e.contains("note_writer") && e.contains("filesystem_write"),
        "{e}"
    );
    assert!(e.contains("authority.leases"), "{e}");
    assert!(!e.contains("calc"), "a `none` tool needs no lease: {e}");
}

#[test]
fn validate_warns_about_a_tool_without_capabilities() {
    let d = tempfile::tempdir().unwrap();
    let out = validate(d.path(), &policy(d.path(), NO_CAPS));
    assert_eq!(out.status.code(), Some(0));
    let e = err(&out);
    assert!(
        e.contains("\"x\"") && e.contains("declares no `capabilities`") && e.contains("[none]"),
        "{e}"
    );
}

#[test]
fn validate_is_quiet_when_every_tool_is_admitted() {
    let d = tempfile::tempdir().unwrap();
    let out = validate(d.path(), &policy(d.path(), LEASED));
    assert_eq!(out.status.code(), Some(0));
    assert!(!err(&out).contains("warning:"), "{}", err(&out));
}

#[test]
fn lease_init_warns_the_same_way_and_still_creates_the_record() {
    let d = tempfile::tempdir().unwrap();
    let (out, state_dir) = lease_init(d.path(), &policy(d.path(), UNLEASED));
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert!(state_dir.path().join("lease.json").exists());
    let e = err(&out);
    assert!(
        e.contains("note_writer") && e.contains("filesystem_write") && e.contains("authority.leases"),
        "{e}"
    );
}

#[test]
fn lease_init_is_quiet_for_a_covered_policy() {
    let d = tempfile::tempdir().unwrap();
    let (out, _s) = lease_init(d.path(), &policy(d.path(), LEASED));
    assert_eq!(out.status.code(), Some(0));
    assert!(!err(&out).contains("warning:"), "{}", err(&out));
}
