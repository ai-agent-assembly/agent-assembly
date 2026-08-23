//! Real-hardware verification of [`aa_isolation_macos_vm::MacosVmBackend`]'s
//! `prepare`/`spawn`/`wait_for_exit` against a genuinely booted guest.
//!
//! `#[ignore]`d: needs `AA_ISOLATION_MACOS_VM_{HELPER,KERNEL,ROOTFS}` set to
//! real artifacts (see `aa-isolation-macos-vm-poc/README.md`) and Virtualization.framework
//! entitlements on this host — neither exists in CI. Run explicitly:
//!
//! ```text
//! AA_ISOLATION_MACOS_VM_HELPER=... AA_ISOLATION_MACOS_VM_KERNEL=... AA_ISOLATION_MACOS_VM_ROOTFS=... \
//!   cargo test -p aa-isolation-macos-vm --test real_hardware -- --ignored --nocapture
//! ```
//!
//! This bypasses `aa_isolation::plan::negotiate` deliberately (calls
//! `prepare`/`spawn`/`wait_for_exit` directly against a hand-built
//! `EnforcementPlan`) — see AAASM-5837's Jira history for why: with zero
//! `CapabilityReport` rows, `negotiate` correctly refuses every real launch
//! through the ordinary `aasm run` CLI path today, which is a genuine,
//! separately-tracked gap (a capability probe, not yet built) — not evidence
//! that `prepare`/`spawn`/`wait_for_exit` themselves are unproven. This test
//! is what proves those three methods against the real substrate.

use aa_isolation::{BackendIdentity, EnforcementPlan, ExecutionSpec, IdentityRef, IsolationBackend, LaunchPosture};
use aa_isolation_macos_vm::MacosVmBackend;

fn hand_built_plan(backend: &BackendIdentity, spec: ExecutionSpec) -> EnforcementPlan {
    // `EnforcementPlan` has no public constructor outside `negotiate` — build
    // one the only way available: through `negotiate` itself, against a
    // spec with zero requirements, which always succeeds regardless of the
    // backend's capability rows (see `aa_isolation::plan::negotiate`).
    aa_isolation::plan::negotiate(&spec, backend, &backend_capabilities_available(), &|_r, _o| {
        aa_isolation::Lowering::new(Vec::<String>::new())
    })
    .expect("an empty requirement set always plans")
}

fn backend_capabilities_available() -> aa_isolation::BackendCapabilities {
    aa_isolation::BackendCapabilities::new(
        aa_isolation::BackendAvailability::Available,
        aa_isolation::PlatformBoundary::GuestKernel,
        Vec::new(),
    )
    .expect("no duplicate domains")
}

#[test]
#[ignore]
fn a_real_launch_round_trips_through_prepare_spawn_wait_for_exit() {
    let backend = MacosVmBackend::discover();
    assert!(
        backend.capabilities().availability().is_available(),
        "backend is Unavailable — set AA_ISOLATION_MACOS_VM_{{HELPER,KERNEL,ROOTFS}}: {:?}",
        backend.capabilities().availability()
    );

    // No working directory is configured, so nothing is shared into the
    // guest (see `paths` module docs) — this launch grants only the fixed
    // resident-binary exec right `to_launcher_argv` adds automatically. A
    // command that touches no other file is therefore the only thing that
    // can succeed under this test's own setup; `busybox cat /etc/testfile`
    // is exercised instead by `protocol-harness`, which explicitly grants
    // `/etc`.
    let spec =
        ExecutionSpec::new("/usr/local/bin/busybox", IdentityRef::root("real-hardware-test")).with_args(["true"]);
    let plan = hand_built_plan(&backend.identity(), spec);

    let prepared = backend.prepare(plan).expect("prepare");
    let handle = backend.spawn(prepared).expect("spawn");
    assert_eq!(handle.posture(), LaunchPosture::Ready);

    let disposition = backend.wait_for_exit(&handle).expect("wait_for_exit");
    assert_eq!(disposition.code(), Some(0), "expected exit 0, got {disposition}");

    // Calling wait_for_exit twice must return the same answer (trait
    // contract) without hanging on an already-drained connection.
    let second = backend.wait_for_exit(&handle).expect("second wait_for_exit");
    assert_eq!(second.code(), Some(0));
}
