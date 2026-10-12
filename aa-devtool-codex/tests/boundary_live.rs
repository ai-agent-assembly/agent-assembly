//! Real-`codex` checks for `boundary::evaluate` (AAASM-6331). Ignored by
//! default: they need `codex` on PATH, and they fail (never skip) without it.
//! Every run uses a throwaway `CODEX_HOME` and cwd — the user's real
//! `~/.codex` is never read or written.

use std::path::Path;
use std::process::Command;

use aa_devtool_codex::boundary::{evaluate, Fact, Floor, ProbeOutput};

fn codex(home: &Path, cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("codex")
        .env("CODEX_HOME", home)
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("`codex` must be on PATH for this test; it does not skip");
    assert!(
        out.status.success(),
        "codex {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

/// Runs both probes with `config` as the user file and `overrides` as `-c` flags.
fn probe(config: &str, overrides: &[&str], floor: Floor) -> aa_devtool_codex::boundary::BoundaryReport {
    let home = tempfile::tempdir().unwrap();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let mut pi = vec!["debug", "prompt-input"];
    let mut dr = vec!["doctor", "--json"];
    for o in overrides {
        pi.extend(["-c", o]);
        dr.extend(["-c", o]);
    }
    pi.push("hello");
    let prompt_input = codex(home.path(), cwd.path(), &pi);
    let doctor = codex(home.path(), cwd.path(), &dr);
    evaluate(
        floor,
        ProbeOutput {
            prompt_input: &prompt_input,
            doctor: &doctor,
        },
    )
}

const USER: &str = "sandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\n";

#[test]
#[ignore = "needs codex-cli 0.160.0 on PATH"]
fn live_user_read_only_meets_the_read_only_floor() {
    let r = probe(USER, &[], Floor::ReadOnly);
    assert!(r.allows_launch(), "{r:?}");
}

#[test]
#[ignore = "needs codex-cli 0.160.0 on PATH"]
fn live_c_override_to_workspace_write_is_below_the_read_only_floor() {
    let r = probe(USER, &["sandbox_mode=\"workspace-write\""], Floor::ReadOnly);
    assert!(matches!(r.filesystem, Fact::Below(_)), "{r:?}");
    assert!(!r.allows_launch());
}

#[test]
#[ignore = "needs codex-cli 0.160.0 on PATH"]
fn live_c_override_to_full_access_is_below_even_the_workspace_floor() {
    let r = probe(USER, &["sandbox_mode=\"danger-full-access\""], Floor::WorkspaceWrite);
    assert!(matches!(r.filesystem, Fact::Below(_)), "{r:?}");
    assert!(!r.allows_launch());
}

#[test]
#[ignore = "needs codex-cli 0.160.0 on PATH"]
fn live_network_override_is_below_the_read_only_floor() {
    let r = probe(
        USER,
        &[
            "sandbox_mode=\"workspace-write\"",
            "sandbox_workspace_write.network_access=true",
        ],
        Floor::ReadOnly,
    );
    assert!(matches!(r.network, Fact::Below(_)), "{r:?}");
}

#[test]
#[ignore = "needs codex-cli 0.160.0 on PATH"]
fn live_workspace_write_meets_the_workspace_floor() {
    let r = probe("sandbox_mode = \"workspace-write\"\n", &[], Floor::WorkspaceWrite);
    assert!(r.allows_launch(), "{r:?}");
}
