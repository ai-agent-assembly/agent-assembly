# B3 feasibility note (AAASM-6273)

Status: analysis only. Nothing here is implemented, and no part of the Core ADR 0038
gate is claimed as met. J82 is deferred from the rc.8 release-blocking set; AAASM-6273
still owns the work.

## What Core ADR 0038 requires before any implementation is built or enabled

Section 30 (the B3 evidence gate) needs five properties shown, each with a positive and an
adversarial negative control, on a real Linux kernel whose capabilities were verified first:

1. Landlock cross-process restriction, ABI 3 or newer.
2. pidfs identity: a pidfd stays bound to its process across pid reuse.
3. Registry write isolation at the kernel, including through aliases.
4. Real multi-process ancestry observed from real processes.
5. Same-uid control denied (`ptrace`, `process_vm_writev`, `/proc/<pid>/mem`, `pidfd_getfd`).

Section 29 then requires registry write-protection, cross-tree impersonation, authority
escalation and transitive-revocation tests across real processes. A skipped test, or one
using a mock or fake kernel, counts as not run.

## What is known about the available host (observed, ADR 0038 current-state)

- The development host is macOS: no Landlock.
- Docker Desktop's VM kernel (`6.10.14-linuxkit`, aarch64) has `CONFIG_SECURITY_LANDLOCK` unset
  and no `landlock` in `CONFIG_LSM`. B3 cannot be established there.

## What can proceed without paid infrastructure (inferred, not verified)

- Design work that the ADR leaves open: the supervisor-side registry record format and the
  parent-resolution API shape (section 27 to 30 constraints; no child-held attestation).
- Pure-logic parts that do not depend on kernel behaviour: the registry data model, the
  refusal taxonomy, and unit tests for ancestry resolution against a supervisor-owned record.
  These would be recorded as design/unit evidence only; they cannot count toward B3.
- Writing the section 30 evidence harness itself, so it is ready to run, with its
  environment probe refusing (recording no evidence) on an unsuitable kernel.

## What cannot be done without a suitable kernel

Every B3 item, and every kernel-dependent section 29 test. A suitable kernel is a Linux
build with Landlock enabled and active, ABI 3 or newer, pidfd behaviour passing the section
30.2 runtime check, and Yama `ptrace_scope` of at least 1 or uid/PID namespace separation.
Whether a free option exists (for example a local Linux VM with such a kernel, or a CI runner
image that provides one) is not verified here and needs to be probed, not assumed.

## Proposed first slice

Do not implement the handoff. First deliver the section 30 evidence harness and an
environment probe that reports, from `/proc/config.gz`, `/sys/kernel/security/lsm`, the
Landlock ABI and `ptrace_scope`, whether B3 is even attemptable, and records no evidence
otherwise. That gives the owner a concrete, repeatable answer to "which host can run B3"
before any registry code exists, and keeps the evidence gate unbypassed.
