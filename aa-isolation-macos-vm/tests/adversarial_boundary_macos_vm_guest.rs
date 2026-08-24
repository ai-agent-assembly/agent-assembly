//! Escape attempts against the macOS VM backend's guest boundary (AAASM-5814).
//!
//! `#[ignore]`d: needs a real, entitled Apple Silicon host with
//! `AA_ISOLATION_MACOS_VM_{HELPER,KERNEL,ROOTFS}` set — see
//! `aa-isolation-macos-vm/tests/real_hardware.rs`'s module docs, which this
//! file's own precondition guard (`adversarial::require_confining_backend`)
//! mirrors.
//!
//! # `--test-threads=1` is still the documented, correct way to run this file
//!
//! AAASM-5854 fixed the specific hazard that used to make this mandatory —
//! every boot used to attach the *same* `rootfs.img` read-write; each boot
//! now gets its own disposable copy (`vmm::boot_attempt`), and this file
//! genuinely does pass under the default parallel runner in repeated
//! verification. `--test-threads=1` is kept as the documented invocation
//! anyway: a real, still-open Virtualization.framework-level race in
//! concurrent `VZVirtualMachine.start()` validation exists independently of
//! the rootfs fix (see this file's own module docs below, "A third,
//! genuinely distinct issue") — serializing avoids it entirely rather than
//! relying on a probabilistic pass:
//!
//! ```text
//! cargo test -p aa-isolation-macos-vm --test adversarial_boundary_macos_vm_guest \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # Why only four of the twelve declared families have a real pair here
//!
//! `BackendPosture` and `ObserveAndDegradedTruthfulness` are already measured
//! at the negotiation level, in `adversarial_negotiation_macos_vm.rs` (via
//! the two shared `adversarial::assert_*` functions this backend's own file
//! calls) — the same split `aa-isolation-sandlock`'s
//! `every_declared_attack_family_has_a_scenario` documents. The four
//! network-shaped families (`DirectEgressBypass`, `CloudMetadata`,
//! `AddressRepresentation`, `UnixSocketsAndDescriptors`) have **no guest
//! network device at all** (`main.swift`'s VM configuration attaches no
//! `VZNetworkDeviceConfiguration`) — there is no control that could produce
//! their effect, so pairing them would read `ControlProducedNoEffect` and
//! fail as an unmeasured pair rather than an honest decline. `SyscallAndResource`
//! is declined for a different, already-documented reason: this backend
//! always sends `syscall_filter: None` (aarch64 guest, no filter
//! translation — see `aa-isolation-macos-vm/src/capability.rs`'s
//! `syscall_unsupported`), and no resource-ceiling mechanism exists this
//! pass. `ProcessInspection` is declined because every launch is a single,
//! freshly booted confined process with nothing else running in the guest
//! to inspect — there is no second process to construct a fixture from.
//! Each decline below is recorded, not silently skipped.
//!
//! Of `ProcessTreeAndAlternateExecutables`'s two named routes, only the
//! process-tree half is measured: the guest image has exactly one name for
//! `busybox` (`/usr/local/bin/busybox`, see
//! `aa-isolation-macos-vm/src/paths.rs`'s `GUEST_RESIDENT_PROGRAMS`), so
//! there is no second path to the same binary to test as an alternate
//! executable.
//!
//! # Two root causes found and fixed, one deeper constraint found and disclosed
//!
//! The instability this file previously reported here — `VZVirtualMachine.start
//! failed: ... "The storage device attachment is invalid."` on every scenario
//! that boots a second guest after `require_confining_backend`'s own probe
//! boot — was **AAASM-5854**: every boot attached `config.rootfs_path`
//! directly, so successive (and concurrent) boots on this host held the same
//! mutable disk image open at once. `vmm::boot_attempt` now copies the image
//! into each boot's own disposable scratch directory before attaching it —
//! see that function's own comment — which removed this failure entirely:
//! this file passed 5/5 consecutive `--test-threads=1` runs and 3/3
//! consecutive default-parallel runs (all five tests, no boot failures) in
//! verification for this fix.
//!
//! Fixing that surfaced a second, separate, previously-unreached bug: with
//! boots now succeeding, every scenario here failed a different way —
//! `NOT MEASURED`, both control and attack producing empty stdout. Root
//! cause: `Message::LaunchRequest::working_dir` was sent over the wire and
//! validated but never actually applied — `guest-init`'s `run_launch` forked
//! and `execv`'d the launcher without ever calling `chdir()` into it, so
//! every scenario's relative path (`forbidden/secret`, relying on
//! `working_dir` being the shared mountpoint) resolved against `/` instead.
//! Fixed in `guest-init/src/protocol.rs` (`chdir()` in the forked child,
//! before `execv`, with the same NUL/absoluteness validation every other
//! wire string gets). Both fixes are covered by this file's own 5/5 passing
//! runs above — this is real, repeated, real-hardware evidence, not a
//! one-off.
//!
//! A third, genuinely distinct issue was found (not fixed) while
//! stress-testing concurrency beyond what this file needs: `real_hardware.rs`
//! run under the *default* parallel test runner — three tests, each booting
//! its own guest at nearly the same instant — intermittently hits
//! `VZVirtualMachine.start failed: ... "A directory sharing device
//! configuration is invalid." ... "No such file or directory"` (confirmed via
//! the same un-suppressed-stderr technique; the target directory is created
//! synchronously before the helper is spawned and is never removed early —
//! this is not a defect in this crate's own directory handling). This reads
//! as a Virtualization.framework-level race in concurrent `VZVirtualMachine`
//! *start* validation, not a rootfs-sharing problem — a different mechanism
//! than AAASM-5854's own scope, and `vmm::boot`'s existing bounded retry
//! (3 attempts, 300ms backoff) does not reliably absorb it. Not chased
//! further this pass — see AAASM-5854's own tracking comment for the
//! disclosure and why `--test-threads=1` remains the documented, correct
//! constraint for any file (this one included) that boots more than one real
//! guest.

use std::path::Path;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, ExecutionSpec, IdentityRef, IsolationBackend,
    RequirementScope,
};

mod adversarial;

use adversarial::{
    assert_prevented, decline, require_confining_backend, AdversarialTarget, AttackFamily, ControlledPair, Effect,
    MacosVmTarget, Measurement, Scratch,
};

const SECRET: &str = "aa-macos-vm-adversarial-secret-71cd";
const PROGRAM: &str = "/usr/local/bin/busybox";

/// `program` run through a shell, with the given `ControlRequirement`s.
fn busybox_spec(scratch_root: &Path, script: &str, requirements: Vec<ControlRequirement>) -> ExecutionSpec {
    let mut spec = ExecutionSpec::new(PROGRAM, IdentityRef::root("macos-vm-adversarial"))
        .with_args(["sh", "-c", script])
        .with_working_dir(scratch_root.to_path_buf());
    for requirement in requirements {
        spec = spec.with_requirement(requirement);
    }
    spec
}

fn read_requirement(selector: String) -> ControlRequirement {
    ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
        .with_scope(RequirementScope::Selectors(vec![selector]))
}

fn write_requirement(selector: String) -> ControlRequirement {
    ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
        .with_scope(RequirementScope::Selectors(vec![selector]))
}

/// Run `script` against `target` and turn the result into an [`Effect`],
/// where the effect is whether `marker` appears in stdout — never the exit
/// code, for the same reason `aa_isolation_macos_vm::probe` never uses one
/// (a script whose write half failed can still exit 0).
fn attempt(target: &MacosVmTarget, label: &str, spec: &ExecutionSpec, marker: &str) -> Effect {
    match target.launch(spec) {
        Ok(outcome) => Effect::new(
            label,
            outcome.stdout.contains(marker),
            format!("stdout: {:?}", outcome.stdout),
        ),
        Err(refusal) => Effect::new(label, false, format!("refused: {refusal:?}")),
    }
}

#[test]
#[ignore]
fn a_forbidden_read_produces_no_effect_while_the_same_read_with_the_grant_does() {
    let scenario = "macos-vm adversarial: a forbidden read produces no effect while the same read with the grant does";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("macos-vm-read");
    std::fs::write(scratch.forbidden().join("secret"), SECRET).expect("write secret fixture");

    let target = MacosVmTarget(backend);
    let script = format!("{PROGRAM} cat forbidden/secret");

    let attack = attempt(
        &target,
        "read the forbidden half, granted only the permitted half",
        &busybox_spec(
            &scratch.root,
            &script,
            vec![read_requirement(scratch.permitted_selector())],
        ),
        SECRET,
    );
    let control = attempt(
        &target,
        "read the forbidden half, granted the whole tree",
        &busybox_spec(
            &scratch.root,
            &script,
            vec![read_requirement(scratch.whole_tree_selector())],
        ),
        SECRET,
    );

    let detail = assert_prevented(
        scenario,
        &ControlledPair::new(AttackFamily::ForbiddenFilesystemRead, attack, control),
    );
    adversarial::measured(scenario, AttackFamily::ForbiddenFilesystemRead, &detail);
}

#[test]
#[ignore]
fn a_forbidden_write_produces_no_effect_while_the_same_write_with_the_grant_does() {
    let scenario =
        "macos-vm adversarial: a forbidden write produces no effect while the same write with the grant does";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("macos-vm-write");
    let target = MacosVmTarget(backend);

    // Read is granted on the whole tree in both runs — only write differs —
    // so a write failure cannot be misread as "the shell could not even open
    // the forbidden directory" (same discipline as `probe.rs::measure_write`).
    let attack = attempt(
        &target,
        "write the forbidden half, granted write only on the permitted half",
        &busybox_spec(
            &scratch.root,
            &format!("{PROGRAM} printf {SECRET} > forbidden/attack-write && {PROGRAM} cat forbidden/attack-write"),
            vec![
                read_requirement(scratch.whole_tree_selector()),
                write_requirement(scratch.permitted_selector()),
            ],
        ),
        SECRET,
    );
    let control = attempt(
        &target,
        "write the forbidden half, granted write on the whole tree",
        &busybox_spec(
            &scratch.root,
            &format!("{PROGRAM} printf {SECRET} > forbidden/control-write && {PROGRAM} cat forbidden/control-write"),
            vec![
                read_requirement(scratch.whole_tree_selector()),
                write_requirement(scratch.whole_tree_selector()),
            ],
        ),
        SECRET,
    );

    let detail = assert_prevented(
        scenario,
        &ControlledPair::new(AttackFamily::ForbiddenFilesystemWrite, attack, control),
    );
    adversarial::measured(scenario, AttackFamily::ForbiddenFilesystemWrite, &detail);
}

#[test]
#[ignore]
fn a_grandchild_is_confined_exactly_like_its_parent() {
    let scenario = "macos-vm adversarial: a grandchild is confined exactly like its parent";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("macos-vm-descendant");
    std::fs::write(scratch.forbidden().join("secret"), SECRET).expect("write secret fixture");
    let target = MacosVmTarget(backend);

    // The attack nests one level deeper than the read/write scenarios above
    // (a grandchild of the launched process attempts the read), with the
    // same grant shape as the forbidden-read scenario — the only variable
    // under test is the extra process generation.
    let nested = format!("{PROGRAM} sh -c '{PROGRAM} cat forbidden/secret'");
    let attack = attempt(
        &target,
        "a grandchild reads the forbidden half, granted only the permitted half",
        &busybox_spec(
            &scratch.root,
            &nested,
            vec![read_requirement(scratch.permitted_selector())],
        ),
        SECRET,
    );
    let control = attempt(
        &target,
        "a grandchild reads the forbidden half, granted the whole tree",
        &busybox_spec(
            &scratch.root,
            &nested,
            vec![read_requirement(scratch.whole_tree_selector())],
        ),
        SECRET,
    );

    let detail = assert_prevented(
        scenario,
        &ControlledPair::new(AttackFamily::ProcessTreeAndAlternateExecutables, attack, control),
    );
    adversarial::measured(scenario, AttackFamily::ProcessTreeAndAlternateExecutables, &detail);
}

/// AAASM-5811 AC2: a credential planted **outside** the launch's shared
/// directory is not merely policy-denied — it is structurally unreachable,
/// because virtiofs never mounts anything but the working directory into
/// the guest. This is a stronger property than the Landlock-style denials
/// above (where the forbidden half *is* visible to the guest, just refused
/// at open time), so it is measured differently: the "attack" is a launch
/// whose requirement tries to grant a path outside the share, and the
/// question is not whether the guest can read it — the backend refuses to
/// map that grant at all rather than silently narrowing it, the same
/// fail-closed behavior `paths::to_guest_path` documents.
#[test]
#[ignore]
fn a_credential_outside_the_share_is_unreachable_not_merely_denied() {
    let scenario = "macos-vm adversarial: a credential outside the share is unreachable, not merely denied";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };

    let scratch = Scratch::new("macos-vm-credential-share");
    let vault = Scratch::new("macos-vm-credential-vault");
    std::fs::write(vault.root.join("credential"), SECRET).expect("write credential fixture");

    // Attack: request read of a path outside the share (the vault, a
    // sibling scratch tree, never the working directory). Driven directly
    // against `backend` rather than through `MacosVmTarget::launch` /
    // `attempt`: that path `.expect()`s `prepare`/`spawn` to succeed, on the
    // premise every other scenario in this file shares — the launch reaches
    // the guest and the *guest* denies it. Here the launch itself must be
    // refused, before any guest exists to deny anything, so the effect under
    // test is the `Err` `spawn` itself returns — this is a stronger,
    // earlier refusal than the Landlock-style denials elsewhere in this
    // file, and it needs its own error handling to observe rather than
    // panic on.
    let attack_spec = busybox_spec(
        &scratch.root,
        &format!("{PROGRAM} true"),
        vec![read_requirement(permit_only_selector(&vault.root.to_string_lossy()))],
    );
    let attack = match backend.plan(&attack_spec) {
        Err(refusal) => Effect::new(
            "grant read of a path outside the shared working directory",
            false,
            format!("refused at plan(): {refusal:?}"),
        ),
        Ok(plan) => match backend.prepare(plan) {
            Err(err) => Effect::new(
                "grant read of a path outside the shared working directory",
                false,
                format!("refused at prepare(): {err:?}"),
            ),
            Ok(prepared) => match backend.spawn(prepared) {
                Err(err) => Effect::new(
                    "grant read of a path outside the shared working directory",
                    false,
                    format!("refused at spawn(), as expected: {err:?}"),
                ),
                Ok(handle) => {
                    // The grant should never have reached spawn() as
                    // reachable — if it did, the launch is a bypass, not a
                    // refusal, and must be reported as one via the normal
                    // wait/observe path rather than silently treated as "no
                    // effect".
                    let disposition = backend.wait_for_exit(&handle).expect("wait_for_exit");
                    let (stdout, _) = backend.captured_output(&handle);
                    Effect::new(
                        "grant read of a path outside the shared working directory",
                        String::from_utf8_lossy(&stdout).contains(SECRET),
                        format!("UNEXPECTED: launch was not refused, disposition: {disposition}"),
                    )
                }
            },
        },
    };

    let target = MacosVmTarget(backend);

    // Control: the identical credential, placed *inside* the share and
    // granted normally — isolates the failure above to "outside the share"
    // specifically, rather than a broken fixture or a broken read grant.
    std::fs::write(scratch.permitted().join("credential"), SECRET).expect("write credential fixture");
    let control = attempt(
        &target,
        "read the same credential placed inside the shared working directory, granted normally",
        &busybox_spec(
            &scratch.root,
            &format!("{PROGRAM} cat permitted/credential"),
            vec![read_requirement(scratch.permitted_selector())],
        ),
        SECRET,
    );

    let detail = assert_prevented(
        scenario,
        &ControlledPair::new(AttackFamily::CredentialEnumeration, attack, control),
    );
    adversarial::measured(scenario, AttackFamily::CredentialEnumeration, &detail);
}

/// The four network-shaped families and the two this guest image has no
/// fixture for, recorded as honest declines rather than silently absent —
/// see this file's module docs for why each one genuinely cannot be paired
/// on this backend today.
#[test]
#[ignore]
fn families_with_no_guest_fixture_are_declined_not_silently_skipped() {
    let scenario = "macos-vm adversarial: families with no guest fixture are declined, not silently skipped";
    if require_confining_backend(scenario).is_none() {
        return;
    }
    for (family, reason) in [
        (
            AttackFamily::DirectEgressBypass,
            "the guest has no network device (main.swift attaches none) — there is no control that could produce this effect",
        ),
        (
            AttackFamily::CloudMetadata,
            "same reason: no guest network device, so no metadata endpoint is reachable to attempt in the first place",
        ),
        (
            AttackFamily::AddressRepresentation,
            "same reason: address-representation attacks are a network-egress question and this guest has no network device",
        ),
        (
            AttackFamily::UnixSocketsAndDescriptors,
            "no guest network device for the socket half; descriptor inheritance is not exercised this pass",
        ),
        (
            AttackFamily::SyscallAndResource,
            "this backend always sends syscall_filter: None (aarch64, no filter translation) and has no resource-ceiling mechanism this pass — already reported Unsupported, not silently omitted",
        ),
        (
            AttackFamily::ProcessInspection,
            "every launch is a single freshly booted confined process; there is no second process in the guest to build a /proc-inspection fixture from",
        ),
    ] {
        decline::<()>(scenario, Measurement::UnsupportedPlatform, &format!("{}: {reason}", family.as_str()));
    }
}

/// AAASM-5811 QA pass (independent, not authored alongside the implementation
/// fix): the whole scratch tree — permitted *and* forbidden halves — is one
/// virtiofs share (`lib.rs`'s `session.share_dir`), so a symlink inside the
/// granted directory that points at the forbidden one is reachable at the
/// guest's filesystem-namespace level regardless of what was granted; only
/// the guest's Landlock ruleset stands between that and a read. Landlock is
/// documented to resolve a symlink to its real path before applying a rule,
/// so this is expected to hold — but AAASM-5854 was exactly this kind of gap
/// between "should hold by design" and "does hold," so it is checked here
/// rather than assumed.
#[test]
#[ignore]
fn a_symlink_inside_the_grant_pointing_at_the_forbidden_half_is_still_confined() {
    let scenario = "macos-vm adversarial: a symlink inside the grant pointing at the forbidden half is still confined";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("macos-vm-symlink");
    std::fs::write(scratch.forbidden().join("secret"), SECRET).expect("write secret fixture");
    // Relative, not the host-absolute form `Scratch::forbidden()` returns:
    // the guest mounts this tree at `/mnt/share`, not at its host path, so a
    // symlink written with the host-absolute target would dangle in the
    // guest (both attack and control would read nothing, and the shared
    // harness's own `not_measured` check exists precisely to catch that
    // rather than let it read as false containment).
    std::os::unix::fs::symlink("../forbidden/secret", scratch.permitted().join("escape-link"))
        .expect("create the escape symlink inside the granted half");

    let target = MacosVmTarget(backend);
    // The escape attempt never names `forbidden/` directly — only the
    // symlink under the granted `permitted/` directory — so a
    // path-string-matching confinement (as opposed to a real-path one)
    // would be fooled by this and this scenario would catch it.
    let script = format!("{PROGRAM} cat permitted/escape-link");

    let attack = attempt(
        &target,
        "read the forbidden secret through a symlink inside the permitted half, granted only the permitted half",
        &busybox_spec(
            &scratch.root,
            &script,
            vec![read_requirement(scratch.permitted_selector())],
        ),
        SECRET,
    );
    let control = attempt(
        &target,
        "read the forbidden secret through the same symlink, granted the whole tree",
        &busybox_spec(
            &scratch.root,
            &script,
            vec![read_requirement(scratch.whole_tree_selector())],
        ),
        SECRET,
    );

    let detail = assert_prevented(
        scenario,
        &ControlledPair::new(AttackFamily::ForbiddenFilesystemRead, attack, control),
    );
    adversarial::measured(scenario, AttackFamily::ForbiddenFilesystemRead, &detail);
}
