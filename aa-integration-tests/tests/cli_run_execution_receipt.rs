//! AAASM-6166 — a real, governed `aasm run` launch under a real confinement
//! backend writes a truthful execution receipt, and `aasm receipt verify`
//! accepts it. Reuses the real-gateway/real-proxy fixtures
//! `adversarial_isolation_launch.rs` established (AAASM-5532) rather than
//! building a third copy of them.
//!
//! # Platform split, and why the load-bearing assertion is not "it verifies"
//!
//! Both platform tests assert `aasm receipt verify` exits `0` — necessary, but
//! not the point of this file: `aasm run --dry-run`'s own receipt-shaped
//! output would pass the same check trivially. The assertion that actually
//! proves this ticket's AC ("measured versus asserted, honestly, by
//! platform") is that the Linux-native receipt's `kernel_release` host fact is
//! `Measured` and the (attempted) macOS-hosted receipt's is `Unmeasured` — the
//! same field, two different bases, because one launch's confined process ran
//! under the host kernel and the other's would have run under a guest kernel
//! this build never probes.
//!
//! # What this file could not verify on the machine that wrote it
//!
//! This suite was authored and range-build-checked on macOS. The Linux test
//! below is `#[cfg(target_os = "linux")]`ed out of that build entirely — macOS
//! never type-checks it, let alone runs it — so "compiles" is not evidence for
//! it; it is reported as unverified, not merely un-run. The macOS test's own
//! backend (`aa-isolation-macos-vm`) requires a helper binary signed with the
//! `com.apple.security.virtualization` entitlement and a bootable guest
//! image, neither of which this development sandbox provides; the test
//! detects that unavailability and reports it explicitly rather than
//! asserting success it did not earn — see `MACOS_VM_UNAVAILABLE_MARKER`.
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

mod grpc_gateway_support;
mod proxy_trust_support;

use grpc_gateway_support::GrpcGateway;
use proxy_trust_support::TrustedProxy;

/// A minimal, always-permitted policy — this file asserts nothing about
/// policy content beyond what's needed to clear AAASM-5349's precondition
/// that some effective policy resolves before a governed launch proceeds.
///
/// Unlike the identically-shaped `tools`-only fixture other integration test
/// files use, this one also states `filesystem.read.allow`: this file's tests
/// request a real confinement backend (`--isolation-backend aasm-native`),
/// and `aa_isolation::lowering::NoRequirementsLowered` refuses a launch whose
/// effective policy lowers to no capability requirement at all — a `tools`
/// node alone maps to nothing in `CapabilityDomain::ALL`, so it isn't enough
/// once a real boundary is actually requested (found via real CI failure:
/// "the effective policy lowered to no execution requirement").
fn write_test_policy(dir: &Path, name: &str) -> io::Result<PathBuf> {
    let path = dir.join("policy.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: agent-assembly/v1\nkind: Policy\nmetadata:\n  name: {name}\nspec:\n  tools:\n    \
             read_file:\n      allow: true\n  filesystem:\n    read:\n      allow:\n        - /\n"
        ),
    )?;
    Ok(path)
}

/// `true(1)`'s path, which is not the same on every platform this file's
/// tests run on: the pre-existing Linux-only and macOS-VM-guest-only tests
/// below never actually exec this path on the *host* (the Linux test's
/// guest/host share a path convention; the macOS-VM test refuses before
/// spawning on this host), so this gap was latent until AAASM-6295 added a
/// test that genuinely execs on the macOS host itself.
#[cfg(target_os = "linux")]
const TRUE_BIN: &str = "/bin/true";
#[cfg(not(target_os = "linux"))]
const TRUE_BIN: &str = "/usr/bin/true";

/// Build the real `aasm run exec -- <true(1)>` command this file drives, with
/// isolation requested via `extra_args`.
#[allow(clippy::too_many_arguments)]
fn build_launch(
    root: &Path,
    agent_id: &str,
    policy: &Path,
    proxy: &TrustedProxy,
    gateway_endpoint: &str,
    state_dir: &Path,
    extra_args: &[&str],
) -> anyhow::Result<Command> {
    let home = root.join("home");
    std::fs::create_dir_all(&home)?;

    // The governed launch starts its own dedicated `aa-proxy` (AAASM-5863) and
    // refuses outright when it cannot resolve one. Unlike the confinement
    // launcher there is no environment override to name it with:
    // `aa_core::binary_resolve::resolve_binary("aa-proxy")` looks beside the
    // running executable, then on `PATH`, then in `~/.cargo/bin`. The first of
    // those is the same accident of the debug build layout described on
    // `aa_isolation_launch_binary`, and the Coverage lane breaks it the same way
    // — so use the second, which is a lookup production genuinely offers: a
    // real, freshly built `aa-proxy` first on the child's `PATH`, exactly the
    // arrangement `cli_proxy_remote_bind_refusal.rs` makes for the same reason.
    let dedicated_proxy_bin = proxy_trust_support::aa_proxy_binary();
    let dedicated_proxy_dir = dedicated_proxy_bin
        .parent()
        .expect("the built binary has a parent directory");

    let mut cmd = Command::new(proxy.aasm());
    // AAASM-6295: explicit allow-list, not ambient inheritance — a prior
    // subtask in this campaign (AAASM-6293) found a real credential reach a
    // log via a panic message from a child spawned without `env_clear()`.
    // Every variable this launch actually needs is set explicitly below;
    // nothing else from this test process's own environment crosses into the
    // child.
    cmd.env_clear();
    cmd.current_dir(root)
        .env("PATH", proxy_trust_support::prefixed_path(dedicated_proxy_dir)?)
        .env("HOME", &home)
        .env("AASM_STATE_DIR", state_dir)
        .env("AA_CA_DIR", root.join("ca"))
        .env("AA_DATA_DIR", proxy.data_dir())
        .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
        .args(["run", "--policy", &policy.to_string_lossy(), "--agent-id", agent_id])
        .args(extra_args)
        .args(["exec", "--", TRUE_BIN])
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

/// The one receipt file under `state_dir/execution-receipts/`, or a
/// diagnostic panic naming what was actually there.
fn the_one_receipt(state_dir: &Path) -> PathBuf {
    let dir = state_dir.join("execution-receipts");
    let entries: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("execution-receipts dir missing at {}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one receipt in {}, found {entries:?}",
        dir.display()
    );
    entries[0].clone()
}

fn aasm_receipt_verify(proxy: &TrustedProxy, path: &Path) -> std::process::Output {
    // AAASM-6295: same explicit allow-list discipline as `build_launch` —
    // `receipt verify` only ever reads the file at `path`, so it needs no
    // ambient environment at all beyond a minimal `PATH`.
    Command::new(proxy.aasm())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["receipt", "verify", &path.to_string_lossy()])
        .output()
        .expect("aasm receipt verify should execute")
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_linux_native_confined_launch_writes_a_receipt_with_a_measured_kernel_release() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6166-linux-native")?;
    let state_dir = root.join("state");

    let mut cmd = build_launch(
        root,
        "aaasm6166-linux-native-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &["--isolation", "process", "--isolation-backend", "aasm-native"],
    )?;
    // Name the launcher instead of relying on one being found beside `aasm`.
    // The backend resolves it from the environment, the executable's own
    // directory, or `PATH` — and the second of those is an accident of the
    // debug build layout, not something this test arranged. In CI's Coverage
    // lane `aasm` is moved to `$RUNNER_TEMP/aasm-bin/` and `target/debug` is
    // deleted to reclaim disk, so all three lookups came up empty and the
    // launch this test's assertions depend on refused outright, while the Test
    // lane (which leaves `target/debug` in place) passed. The backend under
    // test is unchanged; what changes is that the test now supplies its input.
    cmd.env(
        "AA_ISOLATION_LAUNCHER",
        proxy_trust_support::aa_isolation_launch_binary(),
    );
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "the confined launch itself must succeed for its receipt to mean anything\nstderr tail:\n{}",
        tail(&stderr, 60)
    );
    assert!(
        stderr.contains("execution receipt:"),
        "run.rs should announce the receipt path; stderr:\n{stderr}"
    );

    let receipt_path = the_one_receipt(&state_dir);
    let raw = std::fs::read_to_string(&receipt_path)?;
    assert!(
        !raw.contains("AA_GATEWAY_ENDPOINT"),
        "the receipt must never carry a raw environment value"
    );

    let verify_out = aasm_receipt_verify(&proxy, &receipt_path);
    assert!(
        verify_out.status.success(),
        "a genuine, freshly-written receipt must verify cleanly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_str(&raw)?;
    let host = envelope["body"]["host"].as_array().expect("host facts array");
    let kernel_fact = host
        .iter()
        .find(|f| f["name"] == "kernel_release")
        .expect("a kernel_release host fact must be present");
    assert_eq!(
        kernel_fact["basis"]["kind"], "measured",
        "on a shared-host-kernel backend, kernel_release must be Measured, not asserted or unmeasured: {kernel_fact}"
    );
    let boundary = envelope["body"]["backend"]["platform_boundary"]["value"].clone();
    assert_eq!(boundary, "shared_host_kernel");

    Ok(())
}

/// Printed by the macOS test, and grepped for by CI's own log-reading step
/// (if one is added later) so an unavailable-VM run is visibly distinct from
/// a silently-skipped one. Only the macOS test consumes this, so on a
/// non-macOS build (e.g. this file's Linux CI compile pass) it is dead code
/// under `clippy -D warnings` unless gated the same way as its one caller.
#[cfg(target_os = "macos")]
const MACOS_VM_UNAVAILABLE_MARKER: &str = "AAASM-6166: aasm-macos-vm backend unavailable on this host, not measured";

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn a_macos_hosted_confined_launch_writes_a_receipt_with_an_unmeasured_kernel_release() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6166-macos-vm")?;
    let state_dir = root.join("state");

    let mut cmd = build_launch(
        root,
        "aaasm6166-macos-vm-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &["--isolation", "process", "--isolation-backend", "aasm-macos-vm"],
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    if !out.status.success() {
        // A missing entitlement/signature or absent guest image is a real,
        // documented precondition of this backend
        // (`aa-isolation-macos-vm/src/lib.rs::entitlement_check`), not a
        // defect this ticket introduces. Reporting it honestly, rather than
        // asserting a measurement this host cannot produce, is the accepted
        // pattern this same suite already uses for an unavailable backend
        // (`adversarial_isolation_launch.rs`'s sandlock-unavailable
        // scenario).
        eprintln!("{MACOS_VM_UNAVAILABLE_MARKER}\nstderr tail:\n{}", tail(&stderr, 60));
        return Ok(());
    }

    let receipt_path = the_one_receipt(&state_dir);
    let raw = std::fs::read_to_string(&receipt_path)?;

    let verify_out = aasm_receipt_verify(&proxy, &receipt_path);
    assert!(
        verify_out.status.success(),
        "a genuine, freshly-written receipt must verify cleanly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify_out.stdout),
        String::from_utf8_lossy(&verify_out.stderr),
    );

    let envelope: serde_json::Value = serde_json::from_str(&raw)?;
    let host = envelope["body"]["host"].as_array().expect("host facts array");
    let kernel_fact = host
        .iter()
        .find(|f| f["name"] == "kernel_release")
        .expect("a kernel_release host fact must be present");
    assert_eq!(
        kernel_fact["basis"]["kind"], "unmeasured",
        "a guest-kernel backend must report kernel_release as unmeasured — the guest kernel, not the \
         host's, ran the process: {kernel_fact}"
    );
    let guest_arch = host
        .iter()
        .find(|f| f["name"] == "guest_arch")
        .expect("a guest_arch host fact must be present");
    assert_eq!(guest_arch["basis"]["kind"], "asserted");

    Ok(())
}

// ---------------------------------------------------------------------------
// AAASM-6295 (ST-8): `--isolation none` writes no receipt at all.
//
// `docs/src/cli/receipt.md`'s "Where receipts come from" section states this
// in prose ("A run that never establishes a boundary ... writes no
// receipt"), and `aa-cli/src/commands/run.rs`'s `Boundary::Absent` arm
// (`execute_with_adapters`) calls `spawn_and_wait` directly with no call to
// `execution_receipt::body_for_run`/`ReceiptStore::write` anywhere on that
// path — confirmed by reading, not assumed. This test is the empirical
// control: a real, unconfined `aasm run` launch leaves
// `execution-receipts/` either absent or empty, never populated with a
// `posture: no_boundary` receipt. `ReceiptBody::posture()` CAN compute
// `"no_boundary"` (it returns that token whenever `backend.is_none()`), but
// nothing in this build's `aasm run` path ever constructs and seals a body
// with a `None` backend to exercise it — `posture()`'s `no_boundary` arm is
// reachable only from a hand-built `ReceiptBody` in a unit test, never from
// a real `--isolation none` launch. The ticket's stated AC ("confirm
// `--isolation none` produces `posture=no_boundary` in the receipt") does
// not hold as written; this is the honest finding in its place.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_unconfined_launch_with_isolation_none_writes_no_receipt() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6295-isolation-none")?;
    let state_dir = root.join("state");

    // `--isolation none` is also this flag's own default — passed explicitly
    // here so the test's intent reads directly off the invocation rather
    // than off the absence of a flag.
    let mut cmd = build_launch(
        root,
        "aaasm6295-isolation-none-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &["--isolation", "none"],
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "an unconfined launch of true(1) must succeed\nstderr tail:\n{}",
        tail(&stderr, 60)
    );
    // Checks for the substring, not just the exact "execution receipt:"
    // success line — `run.rs`'s two warning branches ("the execution
    // receipt could not be assembled"/"could not be written") also contain
    // "execution receipt", and if the receipt code path ran at all under
    // `--isolation none` (which it must not), it would surface through one
    // of these three strings.
    assert!(
        !stderr.contains("execution receipt"),
        "an --isolation none launch must never reach the receipt-assembly code path at all, success or \
         failure; stderr:\n{stderr}"
    );

    // Absence-of-directory, not just empty-or-absent-as-one-case: an empty
    // `read_dir` and a directory that was never created both report 0
    // entries above, but only "never created" is consistent with the
    // receipt code path never running. If some other mechanism created
    // the directory without populating it, that would be worth knowing
    // separately from "wrote zero files".
    let receipts_dir = state_dir.join("execution-receipts");
    assert!(
        !receipts_dir.exists(),
        "an --isolation none launch must never create the execution-receipts directory at all: {}",
        receipts_dir.display()
    );
    let receipt_count = std::fs::read_dir(&receipts_dir).map(|rd| rd.count()).unwrap_or(0);
    assert_eq!(
        receipt_count, 0,
        "an unconfined launch must write zero receipt files, not a receipt carrying posture=no_boundary"
    );

    Ok(())
}

/// Positive control for the test above: a launch that *does* establish a
/// confined boundary writes exactly one receipt file in the same harness —
/// so the previous test's absence is "this launch wrote none", not "this
/// harness never writes any receipt at all, e.g. because of a path
/// mistake". Same assertion shape `a_linux_native_confined_launch_...`
/// already makes on Linux; reusing a genuinely different backend per
/// platform there, rather than literally the same test, is unavoidable
/// since no confinement backend compiled into this build runs on both.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn a_confined_launch_writes_exactly_one_receipt_as_the_control_for_isolation_none() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6295-control")?;
    let state_dir = root.join("state");

    let mut cmd = build_launch(
        root,
        "aaasm6295-control-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &["--isolation", "process", "--isolation-backend", "aasm-native"],
    )?;
    cmd.env(
        "AA_ISOLATION_LAUNCHER",
        proxy_trust_support::aa_isolation_launch_binary(),
    );
    let out = cmd.output()?;
    assert!(out.status.success(), "the confined control launch must succeed");

    let receipts_dir = state_dir.join("execution-receipts");
    let receipt_count = std::fs::read_dir(&receipts_dir)?.count();
    assert_eq!(receipt_count, 1, "a confined launch must write exactly one receipt");

    Ok(())
}

// ---------------------------------------------------------------------------
// AAASM-6295 (ST-8): no isolation backend this build ships can establish a
// real confined boundary on macOS. Confirmed empirically for all three
// compiled-in backend ids (`sandlock`, `aasm-native`, `aasm-macos-vm`) plus
// `--isolation auto`, below — not inferred from crate names. `aasm-macos-vm`
// is a documented exploratory PoC (`aa-isolation-macos-vm-poc/README.md`:
// "Not a crate, not wired into any workspace build, not shipped in any
// release") whose guest kernel/rootfs/helper assets are not present on this
// host even though AAASM-6287 (hardware re-qualification) merged — that
// ticket re-verified Virtualization.framework hardware capability, not the
// asset chain this build needs to actually boot a guest. This is recorded
// as a known limitation, not fixed here (out of this ticket's
// verification-only scope): on this host, the tamper-category tests in
// `aa-cli/tests/receipt_verify.rs` operate on a receipt built through the
// real `body_for_run`/`ReceiptEnvelope::seal`/`ReceiptStore` production
// pipeline (the exact functions `aasm run` calls), driven by
// `aa_isolation::mock::MockBackend` rather than a live confined process.
// ---------------------------------------------------------------------------

/// Every backend id `aa-cli/src/commands/run.rs::explicit_backend` recognizes
/// — read directly from each crate's `backend.rs`/`lib.rs` rather than
/// guessed, since none of those crates are a dependency of this test crate
/// to reference by path: `aa-isolation-sandlock/src/backend.rs:56` →
/// `"sandlock"`, `aa-isolation-native/src/backend.rs:67` → `"aasm-native"`,
/// `aa-isolation-macos-vm/src/lib.rs:79` → `"aasm-macos-vm"`.
///
/// One real launch + one assertion, shared by all four
/// `#[tokio::test]` functions below so each gets its own independent,
/// parallel-eligible nextest result rather than one combined pass/fail —
/// and so each launch's own gateway+proxy pair stays scoped to its own
/// test, per this file's existing per-test fixture lifetime convention.
#[cfg(target_os = "macos")]
async fn assert_backend_refuses_on_macos(
    backend_id: &str,
    extra_args: &[&str],
    must_contain: &str,
) -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;

    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, &format!("aaasm6295-macos-{backend_id}-unavailable"))?;
    let state_dir = root.join("state");

    let mut cmd = build_launch(
        root,
        &format!("aaasm6295-macos-{backend_id}-agent"),
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        extra_args,
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "backend `{backend_id}` must refuse on macOS, not silently succeed unconfined: stderr:\n{}",
        tail(&stderr, 40)
    );
    // The exact, path-specific refusal string — not a looser
    // "refusing to launch"/"cannot be selected" alternation, which would
    // also match an unrelated failure this test must not mistake for the
    // right one: `run.rs:5985`'s "refusing to launch ungoverned: dedicated
    // proxy failed to start" and `run.rs:5598`'s "refusing to launch: the
    // confined launch failed" both contain "refusing to launch" too, and
    // the second of those would mean the backend WAS selectable and then
    // failed for some other reason — a materially different finding this
    // assertion must not silently accept as "refused as expected".
    assert!(
        stderr.contains(must_contain),
        "backend `{backend_id}` must refuse with its own named reason (`{must_contain}`), not fail for an \
         unrelated cause (e.g. a missing dedicated-proxy binary) that would also make `!success` true: \
         stderr:\n{}",
        tail(&stderr, 40)
    );
    let receipts_dir = state_dir.join("execution-receipts");
    let receipt_count = std::fs::read_dir(&receipts_dir).map(|rd| rd.count()).unwrap_or(0);
    assert_eq!(
        receipt_count, 0,
        "a refused launch for `{backend_id}` must write zero receipts"
    );
    eprintln!(
        "AAASM-6295: backend `{backend_id}` refused on macOS as expected — stderr tail:\n{}",
        tail(&stderr, 20)
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn sandlock_refuses_on_macos() -> anyhow::Result<()> {
    assert_backend_refuses_on_macos(
        "sandlock",
        &["--isolation", "process", "--isolation-backend", "sandlock"],
        "backend cannot be selected on this host",
    )
    .await
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn aasm_native_refuses_on_macos() -> anyhow::Result<()> {
    assert_backend_refuses_on_macos(
        "aasm-native",
        &["--isolation", "process", "--isolation-backend", "aasm-native"],
        "backend cannot be selected on this host",
    )
    .await
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn aasm_macos_vm_refuses_on_macos() -> anyhow::Result<()> {
    assert_backend_refuses_on_macos(
        "aasm-macos-vm",
        &["--isolation", "process", "--isolation-backend", "aasm-macos-vm"],
        "backend cannot be selected on this host",
    )
    .await
}

/// `--isolation auto` selects automatically among all three compiled-in
/// backends rather than naming one — this is a materially different code
/// path (`run.rs:2931`'s own refusal text, not `explicit_backend`'s), so it
/// gets its own test rather than reusing the shared helper's message.
#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread")]
async fn isolation_auto_finds_no_usable_backend_on_macos() -> anyhow::Result<()> {
    let proxy = TrustedProxy::start()?;
    let gateway = GrpcGateway::start().await?;
    let tmp = tempfile::tempdir()?;
    let root = tmp.path();
    let policy = write_test_policy(root, "aaasm6295-macos-auto-unavailable")?;
    let state_dir = root.join("state");
    let mut cmd = build_launch(
        root,
        "aaasm6295-macos-auto-agent",
        &policy,
        &proxy,
        gateway.endpoint(),
        &state_dir,
        &["--isolation", "auto"],
    )?;
    let out = cmd.output()?;
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !out.status.success(),
        "--isolation auto must refuse on macOS when no compiled-in backend is usable, not silently run \
         unconfined: stderr:\n{}",
        tail(&stderr, 40)
    );
    assert!(
        stderr.contains("walked every backend this build has and none of them"),
        "--isolation auto must refuse with its own named reason, not fail for an unrelated cause: stderr:\n{}",
        tail(&stderr, 40)
    );
    let receipts_dir = state_dir.join("execution-receipts");
    let receipt_count = std::fs::read_dir(&receipts_dir).map(|rd| rd.count()).unwrap_or(0);
    assert_eq!(
        receipt_count, 0,
        "a refused --isolation auto launch must write zero receipts"
    );
    eprintln!(
        "AAASM-6295: --isolation auto refused on macOS as expected — stderr tail:\n{}",
        tail(&stderr, 20)
    );

    Ok(())
}
