//! End-to-end test for `aasm admin run-retention` — AAASM-1747.
//!
//! Until the gateway admin transport (AAASM-1590) lands, the subcommand
//! is a stub that prints a pointer at the in-flight wiring ticket and
//! exits 0. These tests pin both the exit-code contract (success so help
//! / arg-parsing CI stays green) and the stub-message contract (so the
//! pointer to S-I is reliably surfaced).

use assert_cmd::Command;

#[test]
fn admin_run_retention_dry_run_exits_success() {
    Command::cargo_bin("aasm")
        .expect("aasm binary must build")
        .args(["admin", "run-retention", "--dry-run"])
        .assert()
        .success();
}

#[test]
fn admin_run_retention_stub_message_points_at_aaasm_1590() {
    let output = Command::cargo_bin("aasm")
        .expect("aasm binary must build")
        .args(["admin", "run-retention"])
        .output()
        .expect("aasm must run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("AAASM-1590"),
        "stub message must point operators at the in-flight wiring ticket, got: {stderr}"
    );
}
