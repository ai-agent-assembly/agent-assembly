//! `aasm run --dry-run` lease plan: the operator-visible text and exit code
//! (AAASM-6259, ADR 0038 "Plan-time / runtime parity").
//!
//! Driven through the real binary because the claim is about what an operator
//! reads. The verdict values themselves are pinned against the runtime gate in
//! `run.rs`'s `lease_plan_parity` tests; this file pins the surface: the section
//! exists, says it is a plan, says what it does not evaluate, and does not turn
//! a DENY verdict into a failing exit code.

#![cfg(unix)]

use std::path::{Path, PathBuf};

const POLICY_SPEC: &str = "  tools:
    calc:
      allow: true
      capabilities: [none]
    reader:
      allow: true
      capabilities: [filesystem_read]
    writer:
      allow: true
      capabilities: [filesystem_write]
    spawner:
      allow: true
      capabilities: [process_creation]
  authority:
    leases:
      - domain: filesystem_read
        scope: whole
        reason: plan test
";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "aasm-run-lease-plan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_policy(dir: &Path, spec: &str) -> PathBuf {
    let path = dir.join("plan.yaml");
    std::fs::write(
        &path,
        format!("apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: plan\nspec:\n{spec}"),
    )
    .expect("write policy");
    path
}

fn dry_run(dir: &Path, policy: &Path) -> (Option<i32>, String) {
    let output = assert_cmd::Command::cargo_bin("aasm")
        .expect("aasm binary")
        .env("AASM_STATE_DIR", dir.join("state"))
        .args(["run", "exec", "--dry-run", "--no-proxy", "--policy"])
        .arg(policy)
        .args(["--", "/bin/echo", "hi"])
        .output()
        .expect("aasm run");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

#[test]
fn the_dry_run_prints_a_lease_plan_with_per_tool_verdicts_and_exits_zero() {
    let scratch = Scratch::new();
    let policy = write_policy(&scratch.0, POLICY_SPEC);
    let (code, out) = dry_run(&scratch.0, &policy);

    // A plan full of DENY lines is still a successful preview.
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("--- lease plan (PLAN: point-in-time, not authorization) ---"),
        "{out}"
    );
    assert!(out.contains("revocation: not evaluated"), "{out}");
    assert!(out.contains("enforcement: runtime-only"), "{out}");

    assert!(out.contains("lease: filesystem_read scope=whole\n"), "{out}");
    assert!(out.contains("tool calc [none]: PERMIT\n"), "{out}");
    assert!(out.contains("tool reader [filesystem_read]: PERMIT\n"), "{out}");
    assert!(out.contains("tool writer [filesystem_write]: DENY ("), "{out}");
    assert!(out.contains("tool spawner [process_creation]: DENY ("), "{out}");
    assert!(out.contains("tool <undeclared>: DENY ("), "{out}");
    assert!(out.contains("action LLM_CALL: PERMIT\n"), "{out}");
    assert!(out.contains("action FILE_OPERATION: DENY ("), "{out}");
    assert!(out.contains("action PROCESS_EXEC: DENY ("), "{out}");
}

#[test]
fn a_policy_authoring_no_leases_says_so_and_still_plans_every_tool() {
    let scratch = Scratch::new();
    let spec = POLICY_SPEC.split("  authority:").next().expect("spec head");
    let policy = write_policy(&scratch.0, spec);
    let (code, out) = dry_run(&scratch.0, &policy);

    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("leases: none authored\n"), "{out}");
    assert!(out.contains("tool reader [filesystem_read]: DENY ("), "{out}");
    assert!(out.contains("tool calc [none]: PERMIT\n"), "{out}");
}

#[test]
fn the_plan_never_claims_a_verdict_when_no_policy_is_enforced() {
    let scratch = Scratch::new();
    let missing = scratch.0.join("absent.yaml");
    let (_, out) = dry_run(&scratch.0, &missing);

    assert!(out.contains("--- lease plan (PLAN"), "{out}");
    assert!(out.contains("plan: not available"), "{out}");
    assert!(!out.contains("tool <undeclared>"), "{out}");
}
