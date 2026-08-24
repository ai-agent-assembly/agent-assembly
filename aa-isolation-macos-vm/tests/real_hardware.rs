//! Real-hardware verification of [`aa_isolation_macos_vm::MacosVmBackend`]'s
//! `prepare`/`spawn`/`wait_for_exit` against a genuinely booted guest.
//!
//! `#[ignore]`d: needs `AA_ISOLATION_MACOS_VM_{HELPER,KERNEL,ROOTFS}` set to
//! real artifacts (see `aa-isolation-macos-vm-poc/README.md`) and Virtualization.framework
//! entitlements on this host — neither exists in CI. Run explicitly:
//!
//! ```text
//! AA_ISOLATION_MACOS_VM_HELPER=... AA_ISOLATION_MACOS_VM_KERNEL=... AA_ISOLATION_MACOS_VM_ROOTFS=... \
//!   cargo test -p aa-isolation-macos-vm --test real_hardware -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `--test-threads=1` is required, not a suggestion. **AAASM-5854 fixed the
//! specific hazard this note used to describe** — every boot used to attach
//! the same `rootfs.img` read-write; `vmm::boot_attempt` now copies it into
//! each boot's own disposable scratch directory, and that class of collision
//! (a concurrent boot's effect reading back as the wrong outcome) is gone —
//! repeated verification for that fix included this file passing cleanly
//! under the default parallel runner. `--test-threads=1` is kept anyway
//! because a second, distinct, still-open issue exists independently of the
//! rootfs sharing: this file's own three tests, each booting a guest at
//! nearly the same instant under the default runner, intermittently hit
//! `VZVirtualMachine.start failed: ... "A directory sharing device
//! configuration is invalid." ... "No such file or directory"` — a
//! Virtualization.framework-level race in concurrent `VZVirtualMachine`
//! *start* validation, confirmed via un-suppressed helper stderr, not a
//! defect in this crate's own directory creation (the shared directory is
//! created synchronously before the helper is spawned, and nothing removes
//! it early). Not root-caused or fixed this pass — `--test-threads=1`
//! remains the correct, documented product constraint until it is.
//!
//! The first test below bypasses `aa_isolation::plan::negotiate` deliberately
//! (calls `prepare`/`spawn`/`wait_for_exit` directly against a hand-built
//! `EnforcementPlan`) — this predates AAASM-5813's capability probe
//! (`aa_isolation_macos_vm::probe`/`capability`), from when this backend's
//! `discover()` reported zero `CapabilityReport` rows and `negotiate`
//! refused every real launch. Left in place because it isolates
//! `prepare`/`spawn`/`wait_for_exit` from `plan()`'s own correctness. The
//! tests below it exercise the real `plan()` path — no bypass — now that
//! `discover()` measures real capability rows.

use aa_isolation::{
    permit_only_selector, BackendIdentity, CapabilityDomain, ControlRequirement, DescendantCoverage, EnforcementPlan,
    ExecutionSpec, FailurePosture, IdentityRef, IsolationBackend, LaunchPosture, RequirementScope,
};
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

/// AAASM-5813 AC3: `discover()`'s probe must have produced real,
/// prevention-capable rows for both filesystem domains, each backed by an
/// observed grandchild denial — not zero rows, and not a report that merely
/// looks complete without a measurement behind it.
#[test]
#[ignore]
fn discover_measures_real_capability_rows() {
    let backend = MacosVmBackend::discover();
    assert!(
        backend.capabilities().availability().is_available(),
        "backend is Unavailable — set AA_ISOLATION_MACOS_VM_{{HELPER,KERNEL,ROOTFS}}: {:?}",
        backend.capabilities().availability()
    );

    let capabilities = backend.capabilities();
    for domain in [CapabilityDomain::FilesystemRead, CapabilityDomain::FilesystemWrite] {
        let report = capabilities
            .report_for(domain)
            .unwrap_or_else(|| panic!("{domain} not reported at all"));
        assert!(
            report.can_prevent(),
            "{domain} did not measure a prevention capability: {report:?}"
        );
        assert_eq!(
            report.descendants(),
            DescendantCoverage::ProcessTree,
            "{domain}: {report:?}"
        );
        assert_eq!(
            report.failure_posture(),
            FailurePosture::FailClosed,
            "{domain}: {report:?}"
        );
    }
}

/// AAASM-5813 AC1, through the real product path: a spec carrying an actual
/// `FilesystemWrite` prevention requirement now plans through
/// `backend.plan()` — real `negotiate`, no hand-built bypass — because
/// `discover()`'s probe gave it a prevention-capable row to satisfy the
/// requirement against. This is the gap the crate's module docs describe:
/// AAASM-5837 proved the trait mechanism; this proves the policy-driven path
/// AAASM-5813 actually asks for.
#[test]
#[ignore]
fn a_real_filesystem_write_requirement_now_plans_through_negotiate() {
    let backend = MacosVmBackend::discover();
    assert!(
        backend.capabilities().availability().is_available(),
        "backend is Unavailable — set AA_ISOLATION_MACOS_VM_{{HELPER,KERNEL,ROOTFS}}: {:?}",
        backend.capabilities().availability()
    );

    let scratch = std::env::temp_dir().join(format!("aa-macos-vm-negotiate-test-{}", std::process::id()));
    std::fs::create_dir_all(&scratch).expect("create scratch dir");

    let spec = ExecutionSpec::new(
        "/usr/local/bin/busybox",
        IdentityRef::root("real-hardware-negotiate-test"),
    )
    .with_args(["true"])
    .with_working_dir(scratch.clone())
    .with_requirement(
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite).with_scope(RequirementScope::Selectors(vec![
            permit_only_selector(&scratch.to_string_lossy()),
        ])),
    );

    let plan = backend
        .plan(&spec)
        .expect("a real FilesystemWrite requirement plans now that discover() measured a capability row");

    let prepared = backend.prepare(plan).expect("prepare");
    let handle = backend.spawn(prepared).expect("spawn");
    let disposition = backend.wait_for_exit(&handle).expect("wait_for_exit");
    assert_eq!(disposition.code(), Some(0), "expected exit 0, got {disposition}");

    let _ = std::fs::remove_dir_all(&scratch);
}
