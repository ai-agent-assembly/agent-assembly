//! AAASM-6162 — a real, governed `aasm run --workspace-tx` launch, driving a
//! real POSIX "coding agent" shell script through a genuine edit -> build ->
//! test cycle, proves the transactional-workspace ACs end to end. Reuses the
//! real-gateway/real-proxy fixtures `cli_run_execution_receipt.rs` already
//! established rather than building a third copy of them.
//!
//! # What each test actually proves, and why "exited 0" is never the
//! assertion
//!
//! `commit()` refuses unless the transaction reached `Closed` first — so a
//! forgotten `close()` would make every commit refuse, and two of the three
//! possible outcomes (discarded, refused) leave the base tree byte-for-byte
//! identical to a successful commit's *starting* point. Asserting "the run
//! exited 0" would therefore pass even if commits never actually applied.
//! Every test below instead enumerates the base tree's real contents after
//! the run and compares it against an explicit expectation, or takes a
//! whole-tree digest before/after.
//!
//! # Platform split (mirrors `cli_run_execution_receipt.rs`)
//!
//! Tests 1-3 exercise the default `--isolation none` path (no execution
//! boundary, no execution receipt) and run on any POSIX host, including the
//! macOS host this suite was authored and range-build-checked on. Test 4
//! additionally requests `--isolation process --isolation-backend
//! aasm-native` and is `#[cfg(target_os = "linux")]`ed out of a macOS build
//! entirely — on this authoring host it is genuinely unverified, not merely
//! un-run, and the receipt AC's on-host evidence is the unit-level coverage
//! in `aa-cli/src/commands/run_workspace_tx.rs` and
//! `aa-cli/src/commands/execution_receipt/project.rs`'s own `#[cfg(test)]`
//! modules plus `aa-cli/tests/receipt_verify.rs`.
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

mod grpc_gateway_support;
mod proxy_trust_support;

use grpc_gateway_support::GrpcGateway;
use proxy_trust_support::TrustedProxy;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/workspace_tx");

/// A minimal, always-permitted policy — same shape as
/// `cli_run_execution_receipt.rs`'s own fixture, for the same reason
/// (AAASM-5349's "some effective policy resolves" precondition), plus a
/// `filesystem.write` grant that fixture does not need: test 4 is the only
/// test in this file that runs under real confinement
/// (`--isolation-backend aasm-native`), and the fixture's `agent.sh` writes
/// real files (edits, a new file, a build artifact) into whatever directory
/// becomes its cwd — including the transaction's staged directory once
/// `--workspace-tx` remaps it there. `aa-isolation-native`'s own
/// documented contract is "an absent grant is the strictest posture
/// available" (`aa-isolation-native/src/backend.rs`), so without this the
/// confined write fails closed and the agent cycle this test drives can
/// never succeed, regardless of `--workspace-tx`.
fn write_test_policy(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let path = dir.join("policy.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\nspec:\n  tools:\n    \
             read_file:\n      allow: true\n  filesystem:\n    read:\n      allow:\n        - /\n    \
             write:\n      allow:\n        - /\n"
        ),
    )?;
    Ok(path)
}

/// Copy the fixture project into `dst`, preserving the executable bit on the
/// three shell scripts (`git` preserves it in the checkout this reads from;
/// a plain byte copy does not re-apply it on every platform, so it is set
/// explicitly here).
fn copy_fixture(dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in walkdir_flat(Path::new(FIXTURE))? {
        let rel = entry.strip_prefix(FIXTURE).expect("fixture entries are under FIXTURE");
        let target = dst.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&entry, &target)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let name = entry.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name.ends_with(".sh") {
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))?;
                }
            }
        }
    }
    Ok(())
}

/// A flat (non-recursive-crate-dependency) directory walk — this fixture is
/// two levels deep at most, so a hand-rolled recursive walk avoids adding a
/// `walkdir` dependency for one small fixture.
fn walkdir_flat(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                out.push(path.clone());
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    Ok(out)
}

/// A snapshot of every real path under `root`: relative path -> a tag
/// distinguishing a directory, a symlink (with its literal target), or a
/// file (with its content) — enough to assert "no other path appeared or
/// changed" rather than only checking the paths a test happens to name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir,
    File(Vec<u8>),
    Symlink(PathBuf),
}

fn snapshot(root: &Path) -> BTreeMap<String, Entry> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .expect("entries are under root")
                .to_string_lossy()
                .into_owned();
            let meta = std::fs::symlink_metadata(&path).expect("symlink_metadata");
            if meta.file_type().is_symlink() {
                out.insert(rel, Entry::Symlink(std::fs::read_link(&path).expect("read_link")));
            } else if meta.is_dir() {
                out.insert(rel, Entry::Dir);
                stack.push(path);
            } else {
                out.insert(rel, Entry::File(std::fs::read(&path).expect("read file")));
            }
        }
    }
    out
}

/// Build the real `aasm run --workspace-tx exec -- sh agent.sh <mode>`
/// command this file drives.
#[allow(clippy::too_many_arguments)]
fn build_launch(
    root: &Path,
    agent_id: &str,
    policy: &Path,
    proxy: &TrustedProxy,
    gateway_endpoint: &str,
    aasm_state_dir: &Path,
    project_dir: &Path,
    mode: &str,
    extra_args: &[&str],
) -> anyhow::Result<Command> {
    let home = root.join("home");
    std::fs::create_dir_all(&home)?;

    let dedicated_proxy_bin = proxy_trust_support::aa_proxy_binary();
    let dedicated_proxy_dir = dedicated_proxy_bin
        .parent()
        .expect("the built binary has a parent directory");

    let mut cmd = Command::new(proxy.aasm());
    cmd.current_dir(project_dir)
        .env("PATH", proxy_trust_support::prefixed_path(dedicated_proxy_dir)?)
        .env("HOME", &home)
        .env("AASM_STATE_DIR", aasm_state_dir)
        .env("AA_CA_DIR", root.join("ca"))
        .env("AA_DATA_DIR", proxy.data_dir())
        .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
        .args(["run", "--policy", &policy.to_string_lossy(), "--agent-id", agent_id])
        .args(extra_args)
        .args(["exec", "--", "sh", "agent.sh", mode])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    Ok(cmd)
}

fn tail(s: &str, n: usize) -> String {
    s.lines()
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

/// The expected base tree after a successful commit of the fixture's
/// "success"/"protected" agent modes: `src/lib.txt` modified, `src/new.txt`
/// added, `src/dead.txt` deleted, `src/link.txt` a new symlink to
/// `lib.txt`, and `out/artifact.txt` produced by `build.sh` from the
/// already-edited `src/lib.txt` (the real ordering dependency the design
/// calls for).
fn expected_after_success_commit(fixture_src: &Path) -> BTreeMap<String, Entry> {
    let mut expected = snapshot(fixture_src);
    expected.remove("src/dead.txt");
    expected.insert(
        "src/lib.txt".to_string(),
        Entry::File(b"original content\nmodified-by-agent\n".to_vec()),
    );
    expected.insert("src/new.txt".to_string(), Entry::File(b"new content\n".to_vec()));
    expected.insert("src/link.txt".to_string(), Entry::Symlink(PathBuf::from("lib.txt")));
    expected.insert("out".to_string(), Entry::Dir);
    expected.insert(
        "out/artifact.txt".to_string(),
        Entry::File(b"original content\nmodified-by-agent\n".to_vec()),
    );
    expected
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transactional_run_that_succeeds_applies_exactly_the_measured_change_set() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6162-success")?;
    let project_dir = root.join("project");
    let state_dir = root.join("state");
    copy_fixture(&project_dir)?;

    let mut cmd = build_launch(
        root,
        "aaasm6162-success-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir,
        "success",
        &["--workspace-tx"],
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the agent's own edit/build/test cycle must succeed\nstderr tail:\n{}",
        tail(&stderr, 60)
    );
    assert!(
        stderr.contains("workspace_tx.committed=true"),
        "expected a committed workspace_tx block; stderr:\n{stderr}"
    );

    let after = snapshot(&project_dir);
    let expected = expected_after_success_commit(Path::new(FIXTURE));
    assert_eq!(
        after, expected,
        "the base tree after commit must equal exactly the enumerated expected set — no more, no less"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_transactional_run_that_fails_leaves_the_base_byte_for_byte_unchanged() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6162-fail")?;
    let project_dir = root.join("project");
    let state_dir = root.join("state");
    copy_fixture(&project_dir)?;
    let before = snapshot(&project_dir);

    let mut cmd = build_launch(
        root,
        "aaasm6162-fail-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir,
        "fail",
        &["--workspace-tx"],
    )?;
    let out = cmd.output()?;
    assert!(!out.status.success(), "the fixture's failing agent mode must fail");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("workspace_tx.committed=false"),
        "expected a discarded workspace_tx block; stderr:\n{stderr}"
    );

    let after = snapshot(&project_dir);
    assert_eq!(
        before, after,
        "a discarded transaction must leave the base byte-for-byte unchanged"
    );

    // Negative control, in the same test: the identical failing agent
    // *without* --workspace-tx must mutate the base — proving the assertion
    // above is measuring the transaction, not an agent that happens not to
    // write anything.
    let project_dir_control = root.join("project-control");
    copy_fixture(&project_dir_control)?;
    let before_control = snapshot(&project_dir_control);
    let mut control_cmd = build_launch(
        root,
        "aaasm6162-fail-control-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir_control,
        "fail",
        &[],
    )?;
    let control_out = control_cmd.output()?;
    assert!(!control_out.status.success());
    let after_control = snapshot(&project_dir_control);
    assert_ne!(
        before_control, after_control,
        "the control run (same failing agent, no --workspace-tx) must mutate the base — otherwise the \
         discard assertion above proves nothing"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_set_touching_a_protected_selector_is_refused_and_leaves_the_base_unchanged() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6162-protected")?;
    let state_dir = root.join("state");

    // Denied: touches the protected selector, no approval.
    let project_dir = root.join("project");
    copy_fixture(&project_dir)?;
    let before = snapshot(&project_dir);
    let mut cmd = build_launch(
        root,
        "aaasm6162-protected-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir,
        "protected",
        &["--workspace-tx", "--workspace-tx-protect", "protected"],
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the agent's own cycle must succeed even though the commit refuses"
    );
    assert!(
        stderr.contains("workspace_tx.refusal=protected_path_not_approved"),
        "expected a protected-path refusal; stderr:\n{stderr}"
    );
    let after = snapshot(&project_dir);
    assert_eq!(
        before, after,
        "a refused commit (protected selector, no approval) must leave the base unchanged"
    );

    // Control: the identical run, with --workspace-tx-approve, commits.
    let project_dir_approved = root.join("project-approved");
    copy_fixture(&project_dir_approved)?;
    let mut approved_cmd = build_launch(
        root,
        "aaasm6162-protected-approved-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir_approved,
        "protected",
        &[
            "--workspace-tx",
            "--workspace-tx-protect",
            "protected",
            "--workspace-tx-approve",
        ],
    )?;
    let approved_out = approved_cmd.output()?;
    let approved_stderr = String::from_utf8_lossy(&approved_out.stderr).into_owned();
    assert!(
        approved_stderr.contains("workspace_tx.committed=true"),
        "expected the approved run to commit; stderr:\n{approved_stderr}"
    );
    let approved_config = std::fs::read_to_string(project_dir_approved.join("protected/config.yaml"))?;
    assert!(
        approved_config.contains("protected-edit-by-agent"),
        "the approved commit must have applied the protected-path change: {approved_config}"
    );

    Ok(())
}

/// AAASM-6291 ST-4 live conflict test: a real concurrent writer mutates the
/// exact base path an in-flight `--workspace-tx` run has already staged a
/// change to, *while the run is still open* -- not simulated at the library
/// level (that's already `base_drift_inside_the_change_set_...` in
/// `aa-workspace-tx/tests/commit_falsification.rs`), but through a real
/// `aasm run` subprocess synchronized with the agent fixture's `conflict`
/// mode via file flags (`$AWTX_READY`/`$AWTX_GO`), never a sleep race.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_base_drift_during_an_in_flight_run_refuses_commit_and_applies_nothing() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6291-conflict")?;
    let state_dir = root.join("state");

    let project_dir = root.join("project");
    copy_fixture(&project_dir)?;
    let before = snapshot(&project_dir);

    let ready = root.join("ready");
    let go = root.join("go");
    let mut cmd = build_launch(
        root,
        "aaasm6291-conflict-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir,
        "conflict",
        &["--workspace-tx"],
    )?;
    cmd.env("AWTX_READY", &ready).env("AWTX_GO", &go);
    let mut child = cmd.spawn()?;

    wait_for(&ready, "the conflict agent to signal AWTX_READY", &mut child)?;

    // The conflicting write: mutate the exact path the in-flight run has
    // already staged a change to, before signalling it to proceed to exit
    // (and thus to settle/commit).
    std::fs::write(
        project_dir.join("src/lib.txt"),
        b"concurrently mutated while the run was in flight\n",
    )?;
    std::fs::write(&go, b"go")?;

    let out = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the agent's own cycle must succeed even though the commit refuses\nstderr tail:\n{}",
        tail(&stderr, 60)
    );
    assert!(
        stderr.contains("workspace_tx.refusal=base_drift"),
        "expected a base-drift refusal; stderr:\n{stderr}"
    );

    let after = snapshot(&project_dir);
    let mut expected = before.clone();
    expected.insert(
        "src/lib.txt".to_string(),
        Entry::File(b"concurrently mutated while the run was in flight\n".to_vec()),
    );
    assert_eq!(
        after, expected,
        "a drift-refused commit must leave the base exactly as the concurrent writer left it -- nothing from \
         the in-flight run's own staged change set may apply on top"
    );

    // Control, in the same test: the identical conflict-mode run, with no
    // concurrent writer, must commit its one staged change -- proving the
    // refusal above was actually caused by the drift, not some unrelated
    // defect that refuses every "conflict"-mode commit regardless.
    let project_dir_control = root.join("project-control");
    copy_fixture(&project_dir_control)?;
    let ready_control = root.join("ready-control");
    let go_control = root.join("go-control");
    let mut control_cmd = build_launch(
        root,
        "aaasm6291-conflict-control-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir_control,
        "conflict",
        &["--workspace-tx"],
    )?;
    control_cmd
        .env("AWTX_READY", &ready_control)
        .env("AWTX_GO", &go_control);
    let mut control_child = control_cmd.spawn()?;
    wait_for(
        &ready_control,
        "the control agent to signal AWTX_READY",
        &mut control_child,
    )?;
    std::fs::write(&go_control, b"go")?;

    let control_out = control_child.wait_with_output()?;
    let control_stderr = String::from_utf8_lossy(&control_out.stderr).into_owned();
    assert!(
        control_stderr.contains("workspace_tx.committed=true"),
        "the control run (same mode, no concurrent write) must commit; stderr:\n{control_stderr}"
    );
    assert_eq!(
        std::fs::read(project_dir_control.join("src/lib.txt"))?,
        b"original content\nmodified-by-agent\n".to_vec(),
        "the control run's own staged change must have applied"
    );

    Ok(())
}

/// Bounded wait for `flag` to appear, synchronizing with the agent fixture's
/// readiness signal rather than sleeping a fixed duration and hoping. Kills
/// `child` and returns an error naming what was being waited for if the
/// deadline passes first.
fn wait_for(flag: &Path, what: &str, child: &mut std::process::Child) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !flag.exists() {
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("agent process exited ({status}) before signalling {what}");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            anyhow::bail!("timed out after 60s waiting for {what}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_confined_transactional_run_writes_tx_metadata_into_its_receipt() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6162-confined")?;
    let project_dir = root.join("project");
    let state_dir = root.join("state");
    copy_fixture(&project_dir)?;

    let mut cmd = build_launch(
        root,
        "aaasm6162-confined-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &project_dir,
        "success",
        &[
            "--workspace-tx",
            "--isolation",
            "process",
            "--isolation-backend",
            "aasm-native",
        ],
    )?;
    cmd.env(
        "AA_ISOLATION_LAUNCHER",
        proxy_trust_support::aa_isolation_launch_binary(),
    );
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the confined agent cycle must succeed\nstderr tail:\n{}",
        tail(&stderr, 60)
    );

    let receipts_dir = state_dir.join("execution-receipts");
    let entries: Vec<PathBuf> = std::fs::read_dir(&receipts_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one receipt, found {entries:?}");
    let raw = std::fs::read_to_string(&entries[0])?;

    let verify_out = Command::new(proxy.aasm())
        .args(["receipt", "verify", &entries[0].to_string_lossy()])
        .output()?;
    assert!(
        verify_out.status.success(),
        "a genuine, freshly-written receipt must verify cleanly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_str(&raw)?;
    let workspace = &envelope["body"]["workspace"];
    assert_eq!(workspace["committed"], serde_json::json!(true));
    // `Digest` is a single-field tuple struct over `String`, which serde's
    // derive serializes transparently as a bare JSON string (`"sha256:..."`),
    // not as an object -- confirmed by a real CI failure on this exact
    // assertion (`is_object()` on a string value).
    assert!(
        workspace["base_digest"].is_string(),
        "base_digest must be present: {workspace}"
    );
    assert!(
        workspace["result_digest"].is_string(),
        "result_digest must be present: {workspace}"
    );
    assert_ne!(
        workspace["base_digest"], workspace["result_digest"],
        "base and result digests must differ for a real change set"
    );
    // Exact enumeration is test 1's job (a full-tree snapshot comparison,
    // which this cfg(linux) test cannot itself run on the authoring host).
    // Here: modified is exactly src/lib.txt; deleted is exactly
    // src/dead.txt; added covers at least the new file, the new symlink,
    // and the new build-output directory/file the agent's own build.sh
    // produces.
    let added = workspace["added_count"].as_u64().unwrap_or(0);
    let modified = workspace["modified_count"].as_u64().unwrap_or(0);
    let deleted = workspace["deleted_count"].as_u64().unwrap_or(0);
    assert_eq!(modified, 1, "src/lib.txt is the only modified path");
    assert_eq!(deleted, 1, "src/dead.txt is the only deleted path");
    assert!(added >= 3, "expected at least 3 added paths, got {added}");

    let not_transactional: Vec<String> = workspace["not_transactional"]
        .as_array()
        .expect("not_transactional array")
        .iter()
        .map(|v| v["value"].as_str().unwrap_or_default().to_string())
        .collect();
    // `aa-cli` is not a dependency of this crate (it is the binary under
    // test, invoked as a subprocess, never linked), so this mirrors
    // `aa_cli::commands::execution_receipt::schema::NOT_TRANSACTIONAL`
    // literally rather than importing it — a real CI-only compile failure
    // on this exact line (`aa_cli` unresolved) is what found this during
    // AAASM-6162 self-review; the cfg(linux) gate around this whole test
    // hid it from every local macOS build.
    const NOT_TRANSACTIONAL: [&str; 4] = [
        "network_side_effects",
        "database_side_effects",
        "paths_outside_declared_surface",
        "processes_and_ipc",
    ];
    for token in NOT_TRANSACTIONAL {
        assert!(
            not_transactional.iter().any(|t| t == token),
            "missing disclaimer token {token} in {not_transactional:?}"
        );
    }
    assert!(
        !raw.contains("src/new.txt") && !raw.contains("src/lib.txt"),
        "the raw receipt file must never carry a change-set path as text"
    );

    Ok(())
}
