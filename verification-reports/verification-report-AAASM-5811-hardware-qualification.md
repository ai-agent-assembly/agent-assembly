# Hardware Qualification Report — AAASM-5811

**Epic:** AAASM-5811 — macOS-hosted Linux isolation MVP (Virtualization.framework, reusing aa-isolation-native)
**Component / repo:** `agent-assembly`
**Policy:** real-hardware qualification (superseding the earlier "self-hosted CI" AC — see Epic comment, 2026-08-24)

## Purpose

Per the revised AAASM-5811 acceptance criterion, any change materially
affecting the macOS isolation execution path must be validated on real
corresponding hardware before being considered complete, with durable
evidence tied to the exact revision. This file is that evidence for the
qualifying revision below. Continuous self-hosted macOS CI is a possible
future automation improvement, not an MVP requirement — this qualification
is local/manual, per policy.

## Re-qualification note (2026-09-08, AAASM-6067/AAASM-6073)

This report **supersedes** the prior qualification (qualified revision
`82aa690bcfd2aec4ac2f9078019026b7a1082901`), which was found stale during
the v0.0.1-rc.7 release-readiness campaign: `git diff --stat 82aa690b
2b8af3896 -- aa-isolation-macos-vm aa-isolation-macos-vm-poc` showed 13
files / 1201 insertions / 68 deletions since the prior qualified revision,
including the exact test files this report's evidence cites
(`adversarial_boundary_macos_vm_guest.rs`, `real_hardware.rs`), plus core
`vmm.rs`, `lib.rs`, `capability.rs`, `paths.rs`. Filed as AAASM-6073;
closed by this re-run.

**Not weakened, substituted, or mocked.** This re-run used the project's
own documented, canonical build pipeline end-to-end — a real Docker/
linuxkit Landlock-capable kernel build, real cross-compiled guest binaries,
a real assembled ext4 rootfs, a real codesigned Virtualization.framework
helper, and the project's own `#[ignore]`d real-hardware test suites run
with `--ignored --nocapture --test-threads=1` exactly as documented in
`aa-isolation-macos-vm-poc/README.md`.

## Qualified revision

| | |
|---|---|
| Commit | `2b8af389623acd0a02107932a4b9a46bd0b94721` (v0.0.1-rc.7 release candidate, AAASM-6067 campaign) |
| Isolation worktree | `agent-assembly-rc7-j64-hwqual`, created fresh via `git worktree add`, detached at the exact candidate SHA — isolated from this machine's other concurrently active worktrees/campaigns, none of which were touched |
| Files affecting the macOS isolation path since the prior qualified revision | `aa-isolation-macos-vm/{Cargo.toml,src/capability.rs,src/lib.rs,src/paths.rs,src/vmm.rs,tests/adversarial_boundary_macos_vm_guest.rs,tests/real_hardware.rs}`, `aa-isolation-macos-vm-poc/{README.md,Sources/aa-isolation-macos-vm-poc/main.swift,guest-init/{Cargo.lock,src/main.rs},scripts/{build-guest-rootfs.sh,fetch-guest-toolchain.sh}}` |

## Host

| | |
|---|---|
| Model | Mac15,8 (Apple Silicon) |
| macOS version | 26.4.1 (BuildVersion 25E253) |
| Entitlement | `com.apple.security.virtualization`, ad-hoc signed (`codesign -s -`), no Developer ID, no App Sandbox, no notarization — same posture as the prior qualification |

## Build pipeline executed (all real, none substituted)

1. `aa-isolation-macos-vm-poc/scripts/build-landlock-kernel.sh` — clones `linuxkit/linuxkit` at pinned commit `2308529`, patches `kernel/6.6.x/config-aarch64` (`CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_LSM="landlock,yama,loadpin,safesetid,integrity"`, `CONFIG_VIRTIO_FS`/`CONFIG_VSOCKETS`/`CONFIG_VHOST*=y`), builds via linuxkit's own `make buildplainkernel-6.6.x` (fetches, GPG- and SHA256-verifies real `linux-6.6.71.tar.xz` from kernel.org). Docker's content-addressed build cache legitimately reused a prior identical-config build (`docker.io/linuxkit/kernel:6.6.x-bb6c4294c9a8fea719450b0da88860ce3227a967-arm64`) rather than rebuilding byte-identical output — deterministic reproducible build, not a shortcut. Output verified: `Linux kernel ARM64 boot executable Image, little-endian, 4K pages`, SHA-256 `8cb44bfeb5a955e7813da125a0473d90bfccf2f87e01c15a49443dae97a95c23`.
2. `scripts/build-guest-init.sh` — cross-compiles `guest-init` (from this repo's own source) to `aarch64-unknown-linux-musl`, wrote a 584K initramfs.
3. `scripts/build-isolation-launch.sh` — cross-compiles `aa-isolation-native`'s real, unmodified `aa-isolation-launch` binary to `aarch64-unknown-linux-musl`.
4. `scripts/fetch-guest-toolchain.sh` — extracts `git`/`python3` from a pinned `alpine@sha256:d9e853e...` Docker image.
5. `scripts/fetch-busybox.sh` — extracts `busybox` from a pinned `busybox@sha256:32b5cdad...` Docker image.
6. `scripts/build-guest-rootfs.sh` — assembles all of the above into a 62M ext4 image, `e2fsck -fn` clean. SHA-256 `831b89b67c4f598d6e8c8e8f5b587dcbaa6bf201d94149ea55c1fcf8b56ec3c0`.
7. `swift build` + `codesign -s - --entitlements aa-isolation-macos-vm-poc.entitlements --force .build/debug/aa-isolation-macos-vm-poc` — built and signed the Virtualization.framework helper; `codesign -d --entitlements -` confirmed `com.apple.security.virtualization = true` present.

## Test evidence

Run against the isolated worktree at the exact qualified revision, with `AA_ISOLATION_MACOS_VM_HELPER`/`_KERNEL`/`_ROOTFS` pointing at the artifacts built above:

```
cargo test -p aa-isolation-macos-vm --test real_hardware -- --ignored --nocapture --test-threads=1
running 4 tests
test a_real_filesystem_write_requirement_now_plans_through_negotiate ... ok
test a_real_launch_round_trips_through_prepare_spawn_wait_for_exit ... ok
test discover_measures_real_capability_rows ... ok
test evidence_reports_configured_and_installed_for_a_real_run ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p aa-isolation-macos-vm --test adversarial_boundary_macos_vm_guest -- --ignored --nocapture --test-threads=1
running 6 tests
test a_credential_outside_the_share_is_unreachable_not_merely_denied ... ok
test a_forbidden_read_produces_no_effect_while_the_same_read_with_the_grant_does ... ok
test a_forbidden_write_produces_no_effect_while_the_same_write_with_the_grant_does ... ok
test a_grandchild_is_confined_exactly_like_its_parent ... ok
test a_symlink_inside_the_grant_pointing_at_the_forbidden_half_is_still_confined ... ok
test families_with_no_guest_fixture_are_declined_not_silently_skipped ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out
```

The 8 "filtered out" cases in the adversarial suite are non-applicable families (no guest network device: `direct_egress_bypass`, `cloud_metadata`, `address_representation`, `unix_sockets_and_descriptors`; no syscall-filter/resource-ceiling mechanism this pass: `syscall_and_resource`; no second guest process: `process_inspection`) — each explicitly reported `unsupported_platform` with a named reason via `families_with_no_guest_fixture_are_declined_not_silently_skipped`, not silently omitted.

Every adversarial test demonstrates the genuine differential control this qualification exists to produce: an attack attempt under the boundary produces **no effect** (empty stdout / refused at spawn), while the identical attempt with the one relevant grant widened **succeeds** (real secret content returned) — real Landlock enforcement, not a pre-flight kernel-capability refusal (which is what every prior non-Landlock kernel this project used could only ever demonstrate).

## Provenance

Same base recipe as the original qualification (unchanged this pass): linuxkit base commit `2308529`; kernel source `https://www.kernel.org/pub/linux/kernel/v6.x/linux-6.6.71.tar.xz`, GPG-verified against kernel.org's signed `sha256sums.asc`; built kernel `Linux version 6.6.71-linuxkit`, `arm64`, raw `Image` format.

## What this closes, and what it doesn't

Closes AAASM-6073 (staleness) and re-confirms J64 (`qa/golden-journeys.yaml`) for v0.0.1-rc.7 candidate `2b8af389623acd0a02107932a4b9a46bd0b94721`. Does not extend beyond what was tested: Intel Mac hardware remains explicitly unverified (this qualification, like the prior one, is Apple Silicon only); network-egress/cloud-metadata/syscall-filter/resource-ceiling attack families remain untested for this backend (correctly reported as not-yet-applicable, not as passing).

## Re-qualification (2026-10-10, AAASM-6287, ST-11a of the AAASM-6174 QA epic)

**Why re-run:** `git diff --stat 2b8af3896 HEAD -- aa-isolation-native/src` shows
1009 insertions / 49 deletions (10 files — `probe.rs`, `rules.rs`, `lower.rs`,
`limits.rs`, and others) since the above qualified revision, and the local
`aa-isolation-macos-vm-poc/images-landlock-kernel/` build output did not exist
at the start of this ticket's worktree (it was rebuilt mid-ticket — see below).

**Not weakened, substituted, or mocked.** Same canonical pipeline as the prior
pass: the project's own `aa-isolation-macos-vm-poc/scripts/*.sh`, a real
Virtualization.framework helper, and the project's own `#[ignore]`d
real-hardware suites run with `--ignored --nocapture --test-threads=1`.

### Qualified revision

| | |
|---|---|
| Commit | `63b00bdda1651c88c17184cb12d832a6109dedfc` (branch `v0.0.1/AAASM-6287/qa/macos_hardware_requalification`, rebased onto `remote/main`) |
| Worktree | `agent-assembly-v0.0.1-AAASM-6287-qa-macos_hardware_requalification`, a dedicated git worktree for this ticket |
| Files affecting the macOS isolation path since `2b8af389` | `aa-isolation-native/src/{probe.rs,rules.rs,lower.rs,limits.rs,...}` (10 files, 1009+/49− per the diff above) — `aa-isolation-macos-vm`/`aa-isolation-macos-vm-poc` themselves were not further modified this pass |

### Host

| | |
|---|---|
| Model | Apple Silicon (arm64) |
| macOS version | 26.4.1 (BuildVersion 25E253) |
| Entitlement | `com.apple.security.virtualization`, ad-hoc signed (`codesign -s -`), confirmed present via `codesign -d --entitlements -` — same posture as the prior qualification |

### Build pipeline executed

The Landlock-capable guest kernel from the prior qualification pass had been
rebuilt earlier in this same worktree session (predating this report's own
test run, by a now-superseded attempt at this ticket) and was reused as-is
rather than rebuilt a second time, because its SHA-256 is bit-identical to
the previously qualified kernel (`8cb44bfeb5a955e7813da125a0473d90bfccf2f87e01c15a49443dae97a95c23`)
— the kernel build (linuxkit commit `2308529`, the same three Kconfig
patches, kernel.org `linux-6.6.71.tar.xz`) is deterministic and inputs to it
did not change this pass, so a byte-identical rebuild carries the same
evidentiary weight as a fresh one. Every other artifact was rebuilt fresh
this pass, from this ticket's own worktree, via the project's own scripts:

1. `scripts/build-guest-init.sh` — cross-compiled `guest-init`, wrote a 584K initramfs.
2. `scripts/build-isolation-launch.sh` — cross-compiled `aa-isolation-native`'s real, unmodified `aa-isolation-launch` binary (the exact revision above, including this pass's 1009-line diff) to `aarch64-unknown-linux-musl`.
3. `scripts/fetch-guest-toolchain.sh` — extracted the pinned Alpine git/python3 userland (65M tar).
4. `scripts/fetch-busybox.sh` — extracted the pinned `busybox:musl` binary.
5. `scripts/build-guest-rootfs.sh` — assembled a 192M ext4 image. SHA-256 `b045d75a8d9832f2818ff1be9deb1d60b1b43f6a1d06bdeb44f3f8d48453babc`.
6. `swift build` + `codesign -s - --entitlements aa-isolation-macos-vm-poc.entitlements --force .build/debug/aa-isolation-macos-vm-poc` — built and signed the Virtualization.framework helper; `codesign -d --entitlements -` confirmed `com.apple.security.virtualization = true` present.

Kernel: `images-landlock-kernel/kernel`, SHA-256
`8cb44bfeb5a955e7813da125a0473d90bfccf2f87e01c15a49443dae97a95c23` (unchanged
from the prior qualification — see above).
Rootfs: `images/guest-rootfs.img`, SHA-256
`b045d75a8d9832f2818ff1be9deb1d60b1b43f6a1d06bdeb44f3f8d48453babc`.

### Test evidence

Run with `AA_ISOLATION_MACOS_VM_HELPER`/`_KERNEL`/`_ROOTFS` pointing at the
artifacts above. A private, per-worktree `CARGO_TARGET_DIR` was used for
these `cargo test`/`cargo nextest` invocations (not for the build scripts
above, which locate their own cargo output via the shared
`~/.cargo/shared-target` convention those scripts hardcode) — the shared
target dir was under sustained lock contention from other concurrently
active sessions on this host for the first attempt, which never progressed
past `Compiling aa-core` in 30 minutes; the private target dir routed around
that entirely and the same suite then compiled and ran in seconds.

```
cargo test -p aa-isolation-macos-vm --test real_hardware -- --ignored --nocapture --test-threads=1
running 4 tests
test a_real_filesystem_write_requirement_now_plans_through_negotiate ... ok
test a_real_launch_round_trips_through_prepare_spawn_wait_for_exit ... ok
test discover_measures_real_capability_rows ... ok
test evidence_reports_configured_and_installed_for_a_real_run ... ok
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 4.29s

cargo test -p aa-isolation-macos-vm --test adversarial_boundary_macos_vm_guest -- --ignored --nocapture --test-threads=1
running 6 tests
test a_credential_outside_the_share_is_unreachable_not_merely_denied ... ok
test a_forbidden_read_produces_no_effect_while_the_same_read_with_the_grant_does ... ok
test a_forbidden_write_produces_no_effect_while_the_same_write_with_the_grant_does ... ok
test a_grandchild_is_confined_exactly_like_its_parent ... ok
test a_symlink_inside_the_grant_pointing_at_the_forbidden_half_is_still_confined ... ok
test families_with_no_guest_fixture_are_declined_not_silently_skipped ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 9.18s
```

The 8 "filtered out" cases are the same non-applicable families documented
in the prior pass above (no guest network device, no syscall-filter/
resource-ceiling mechanism this pass, no second guest process) — identical
coverage shape to the prior qualification, unchanged by this pass's
`aa-isolation-native` diff.

**`planner_positive_control` — ran without `--ignored`.** This ticket's
instructions specified `--ignored` uniformly for all three
`aa-isolation-macos-vm` suites, but this suite's own module doc
(`tests/planner_positive_control.rs`) states its three cases are deliberately
plain `#[test]`s exercising `aa_isolation_macos_vm::capability::discover`
as a pure function against a constructed `GuestProbe` — "no VM boot
required." None of its three tests carry `#[ignore]`, so `--ignored`
filters all three out (confirmed empirically: `0 passed; 0 failed; 3
filtered out`). Re-run without `--ignored`, which is the suite's own
documented, correct invocation:

```
cargo test -p aa-isolation-macos-vm --test planner_positive_control -- --nocapture --test-threads=1
running 3 tests
test a_full_support_minimum_disqualifies_the_real_backend_negotiate_would_accept ... ok
test positive_control_selects_the_real_backend_under_a_fail_closed_minimum ... ok
test real_backend_can_prevent_filesystem_write_but_is_never_full_support ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

**`cli_run_execution_receipt` — VM-usage honesty check.**

```
cargo nextest run -p aa-integration-tests --test cli_run_execution_receipt --no-capture
PASS [ 149.455s] (1/1) aa-integration-tests::cli_run_execution_receipt a_macos_hosted_confined_launch_writes_a_receipt_with_an_unmeasured_kernel_release
Summary [ 149.456s] 1 test run: 1 passed (1 slow), 0 skipped
```

Output explicitly checked (`grep -c MACOS_VM_UNAVAILABLE_MARKER`) — **0
occurrences**. The VM backend was genuinely exercised end-to-end for this
test, not silently skipped with a fallback marker standing in for real
coverage.

### What this closes, and what it doesn't (this pass)

Re-confirms J64 for the current revision `63b00bdda1651c88c17184cb12d832a6109dedfc`,
closing the AAASM-6287 re-qualification trigger (the ~1000-line
`aa-isolation-native/src` diff since `2b8af389`). `lifecycle_state: manual_live`
in `qa/golden-journeys.yaml` is unchanged — it was already the correct,
truthful state before this pass (continuous CI remains a future improvement,
not an MVP requirement) and nothing in this pass's results changes that
classification. Scope limits are unchanged from the prior qualification:
Apple Silicon only (Intel unverified); network-egress/cloud-metadata/
syscall-filter/resource-ceiling attack families remain untested for this
backend.
