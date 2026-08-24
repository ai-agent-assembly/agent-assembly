# Hardware Qualification Report — AAASM-5811

**Epic:** AAASM-5811 — macOS-hosted Linux isolation MVP (Virtualization.framework, reusing aa-isolation-native)
**Component / repo:** `agent-assembly`
**Policy:** real-hardware qualification (superseding the earlier "self-hosted CI" AC — see Epic comment, 2026-08-24)

## Purpose

Per the revised AAASM-5811 acceptance criterion, any change materially
affecting the macOS isolation execution path (macOS `IsolationBackend`,
the Virtualization.framework Swift helper, VM lifecycle, the host↔guest
vsock protocol, virtiofs/project-directory scoping, guest image/kernel
integration, macOS capability discovery, entitlements/signing, confinement
behavior, descendant containment, platform-specific backend selection) must
be validated on real corresponding hardware before being considered
complete, with durable evidence tied to the exact revision. This file is
that evidence for the qualifying revision below. Continuous self-hosted
macOS CI is a possible future automation improvement, not an MVP
requirement — this qualification is local/manual, per policy.

## Qualified revision

| | |
|---|---|
| Commit (merge) | `82aa690bcfd2aec4ac2f9078019026b7a1082901` |
| PR | [#2171](https://github.com/ai-agent-assembly/agent-assembly/pull/2171) — AAASM-5854 |
| Files affecting the macOS isolation path | `aa-isolation-macos-vm/src/vmm.rs`, `aa-isolation-macos-vm-poc/guest-init/src/protocol.rs`, plus test-module docs |
| `main` HEAD at time of this report | `6fd573c7b` (one merge ahead — PR #2170/AAASM-5857, confirmed via `git diff --stat 82aa690b remote/main -- aa-isolation-macos-vm aa-isolation-macos-vm-poc` = empty, i.e. **no macOS-isolation-path changes since the qualified revision**) |

## Hardware

| | |
|---|---|
| Machine | MacBook Pro, Apple M3 Max |
| Architecture | arm64 (Apple Silicon) |
| macOS version | 26.4.1 (build 25E253) |
| Guest architecture | aarch64 (Linux, Landlock-capable substitute kernel) |
| Entitlement | `com.apple.security.virtualization`, local ad-hoc codesign (AAASM-5840 pattern — no Apple provisioning grant required for this trust level) |

**Intel/x86_64 status: not hardware-verified.** No Intel Mac was inspected or
tested this pass. No x86_64 claim is made anywhere in this report or in the
Epic. AAASM-5811's own docs (`docs/src/security/execution-isolation.md`)
already state Intel + Apple Silicon as the *target* compatibility floor per
ADR — that is a design target, not a hardware-verification claim, and must
not be conflated with one.

## Scenarios executed and results

All real Virtualization.framework guest boots, real product path
(`MacosVmBackend::plan`/`prepare`/`spawn`/`wait_for_exit`/`captured_output`),
no mocking, no scenario weakening.

| Suite | Threading | Runs | Result |
|---|---|---|---|
| `adversarial_boundary_macos_vm_guest.rs` (5 real `ControlledPair` scenarios: forbidden read, forbidden write, grandchild/descendant confinement, credential-outside-share structural unreachability, declined-families honesty) | `--test-threads=1` | 5 consecutive | 5/5 clean |
| `adversarial_boundary_macos_vm_guest.rs` | default parallel | 3 consecutive | 3/3 clean |
| `real_hardware.rs` (3 scenarios: prepare/spawn/wait_for_exit round-trip, `discover()` capability measurement, real `FilesystemWrite` requirement through `negotiate`) | `--test-threads=1` | 3 consecutive | 3/3 clean |
| `real_hardware.rs` | default parallel | 4 consecutive | 1/4 clean — see AAASM-5870 |
| `aa-isolation-macos-vm` unit tests | n/a (no VM) | 1 | 22/22 pass |

## Known, disclosed, non-blocking residual (AAASM-5870)

`real_hardware.rs` under the *default parallel* test runner intermittently
hits `VZVirtualMachine.start failed: ... "A directory sharing device
configuration is invalid." ... "No such file or directory"` — a
Virtualization.framework-level race validating concurrent `VZVirtualMachine
.start()` calls, confirmed not caused by this crate's own directory
handling. Classified **non-blocking** for this Epic: the failure mode is a
loud, fail-closed refusal to boot (never a silent confinement bypass or
wrong-verdict read), reproduces only under near-simultaneous concurrent
guest boots, and does not manifest under the documented, serialized
invocation (`--test-threads=1`) every affected test file requires. Tracked
separately, not fixed in this pass. See AAASM-5870 for detail.

## Verdict

The qualified revision (`82aa690b`, current as of `main` HEAD `6fd573c7b`)
demonstrates the real host→guest confined execution path, descendant
containment, and truthful capability reporting on real Apple Silicon
hardware. This satisfies AAASM-5811's revised hardware-qualification AC for
the macOS/Apple-Silicon architecture. Intel/x86_64 remains unqualified and
unclaimed.
