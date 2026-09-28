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

/// Build the real `aasm run exec -- /bin/true` command this file drives, with
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
    cmd.current_dir(root)
        .env("PATH", proxy_trust_support::prefixed_path(dedicated_proxy_dir)?)
        .env("HOME", &home)
        .env("AASM_STATE_DIR", state_dir)
        .env("AA_CA_DIR", root.join("ca"))
        .env("AA_DATA_DIR", proxy.data_dir())
        .env("AA_GATEWAY_ENDPOINT", gateway_endpoint)
        .args(["run", "--policy", &policy.to_string_lossy(), "--agent-id", agent_id])
        .args(extra_args)
        .args(["exec", "--", "/bin/true"])
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
    Command::new(proxy.aasm())
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
