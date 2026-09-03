# AAASM-5532 — one bounded follow-up: is `/proc/self` under Landlock a kernel limitation, or a harness bug?

A single, targeted research pass on the one open question PR #2348 left behind:
`aa-isolation-native/tests/adversarial_boundary_native_linux.rs`'s
`a_detached_and_reparented_grandchild_is_confined_alike` is `#[ignore]`d with a
doc comment stating a real, CI-evidenced `Permission denied` reading a
re-parented grandchild's own `/proc/self/stat`, and *suspecting but not
verifying* that the cause is Landlock's magic-symlink resolution for
`/proc/self`. This pass tests that suspicion directly, cheaply, and
conclusively — and finds it is very likely **wrong**.

## Verdict

**Conditional-Go.** Landlock does **not** deny `/proc/self` reads for a
detached, re-parented process under the exact ruleset shape AASM installs. Four
independent, zero-cost GitHub-hosted CI runs, each built to close one gap in
the previous run's fidelity to the real product, all show `/proc/self/stat`
opening successfully. The `#[ignore]`d scenario's real denial was not
reproduced by any faithful reconstruction of the mechanism — which means the
mechanism is very likely not the blocker, and the bug is very likely in the
test harness itself, not the kernel. See
[Recommendation](#recommendation-and-follow-up) for what to do next, and why
this pass stops short of doing it.

## Method — four runs, each closing one fidelity gap, all zero-cost

Every run used a throwaway branch (`spike/AAASM-5532/landlock-proc-self-probe`)
and a scratch `on: push` workflow on a standard `ubuntu-24.04` GitHub-hosted
runner — no paid infrastructure, no new permanent CI, no PR opened. The branch
and workflow were deleted after the last run; nothing from this probe is
merged. Total cost: 4 runs × ~10s CI time.

| Run | What it added over the last one | `/proc/self/stat` |
|---|---|---|
| 1 | Minimal Landlock ruleset: `handled_access_fs` = `ReadFile\|ReadDir` only, one `PathBeneath` rule on `/proc` with the same rights. Direct process **and** `setsid --fork`. | **OK**, both cases |
| 2 | Faithful `handled_access_fs`: `AccessFs::from_all(ABI::V3)` — the *exact* value `aa-isolation-native/src/rules.rs::install` uses (`handled = AccessFs::from_all(REQUIRED_ABI)`), not just the read bits. Grants `AccessFs::from_read(ABI::V3)` (confirmed from the pinned `landlock` 0.4.7 crate source: `Execute \| ReadFile \| ReadDir`) on the exact `system_reads(include_proc: true)` path set (`/usr,/lib,/lib64,/bin,/sbin,/etc,/proc,/dev`, filtered to existing paths). | **OK**, both cases |
| 3 | Genuine re-parenting: a subshell backgrounds a leaf and exits, so the kernel actually re-parents the leaf to PID 1 (verified: `ppid=1` read from `/proc/self/stat` before *and* after — this runner's own container already parents everything at PID 1, so the reparent-to-subreaper path was exercised either way), instead of only `setsid --fork`'s session detachment. | **OK** |
| 4 | Launch-order fidelity: apply Landlock **once**, in a separate `installer` binary, then `execve` into `/bin/sh` — so every later fork (`setsid`, the backgrounding subshell) and the final `exec` into a **separate `reader` binary that itself never calls a Landlock syscall** inherits the restriction purely through the kernel's normal fork/exec ruleset inheritance, exactly matching how `aa-isolation-launch` applies Landlock to itself before `execve`-ing into the confined program (`aa-isolation-native/src/backend.rs` module doc: restriction happens on the launcher, before `execve`). | **OK** |

Run 4 is the closest a standalone reproduction gets to the real product's
actual order of operations, and it still succeeds. Full commands, source, and
raw CI output referenced below; not preserved as repo artifacts by design (see
[Why nothing here is committed as code](#why-nothing-here-is-committed-as-code)).

## What this settles about the kernel mechanism

- **Landlock's magic-symlink resolution for `/proc/self` is not the
  blocker.** All four runs read `/proc/self/stat` successfully under a
  directory-scoped `/proc` grant, matching the AASM ruleset's exact rights
  (`AccessFs::from_read(ABI::V3)` = `Execute|ReadFile|ReadDir`) and exact
  `handled_access_fs` (`AccessFs::from_all(ABI::V3)`). The doc comment landed
  in PR #2348 — *"`/proc/self` is a magic symlink whose target resolves
  per-reader, and Landlock's real-path resolution for it does not behave the
  same as for an ordinary symlink under a granted directory"* — is not
  supported by this evidence and should be treated as a disproven hypothesis,
  not a settled explanation.
- **Detachment and re-parenting to PID 1 make no observed difference.** Runs
  1–2 (not detached) and runs 3–4 (genuinely re-parented, confirmed via a real
  `ppid=1` read) behave identically.
- **Fork/exec inheritance of the ruleset works as documented.** Run 4's
  `reader` binary never calls a Landlock syscall itself and still inherits the
  exact restriction the `installer` process applied three fork/exec hops
  earlier — the standard, documented Landlock inheritance model, working
  as expected under the detached/re-parented shape this attack class needs.

## What this does *not* settle

- **Why the real CI run on PR #2348 actually failed.** This pass disproves the
  *mechanism* hypothesis; it does not identify the *actual* cause. The real
  scenario's exact shell chain, `DetachRecord` plumbing, and grant construction
  in `aa-isolation-native/tests/adversarial_boundary_native_linux.rs` were not
  reproduced line-for-line here — only the ruleset shape and the fork/exec/
  reparent order were. A harness-specific detail this probe didn't replicate
  (working directory, an inherited file descriptor, the exact multi-level `sh
  -c` nesting, a bug in the test's own grant list construction) remains the
  leading candidate and is not yet identified.
- **Whether some other kernel primitive is needed.** Given the mechanism
  itself is not the blocker, this question does not currently apply — no
  alternate primitive is needed if the existing one already works, which is
  what this pass found.

## Cost, and the implementation/maintenance trade

Closing this out for real is now a **debugging task against the existing test
harness**, not an unfixable kernel limitation and not a case for a new
enforcement mechanism. Estimated cost: small — a few real-CI iterations
comparing the actual failing scenario's exact grant construction and process
chain against this probe's proven-working shape, most likely in
`DetachRecord`'s helper or the exact `run()` call's grant list for that one
test. This is materially cheaper than the "Go" case looked like when the
scenario was `#[ignore]`d with a suspected-unfixable kernel cause.

## Recommendation and follow-up

**This pass does not re-open the `#[ignore]`d test or touch the harness.**
Per this task's own scope ("Do NOT reopen completed work or manufacture
implementation merely to close Jira" / "the goal is not make it pass at all
costs"), debugging the actual harness is implementation work belonging to a
dedicated follow-up pass with its own real-CI iteration budget, not folded
into this research spike.

1. **File one follow-up implementation ticket** (AAASM-6041) to debug the real
   harness against this probe's now-proven-working baseline, and supersede the
   disproven magic-symlink hypothesis in the `#[ignore]`d test's doc comment
   once a real cause is found (or the scenario is un-ignored).
2. **Correct the record**: the doc comment merged in PR #2348 states a
   suspected root cause this pass found no supporting evidence for. It is not
   fixed here (that is the follow-up ticket's job, alongside whatever the real
   fix turns out to be) but is flagged in this report and in Jira so nobody
   treats the magic-symlink explanation as settled.
3. **Do not build a new enforcement mechanism.** Nothing in this pass suggests
   Landlock is structurally incapable of this attack class — quite the
   opposite.

### Reconsideration triggers for AAASM-6041

- If a real-CI debugging pass against `adversarial_boundary_native_linux.rs`
  itself reproduces `Permission denied` under a setup that matches this
  probe's run 4 exactly (same grant set, same order, same inheritance shape)
  and still fails, that *would* be new evidence for a genuine kernel/harness
  interaction this probe missed, and should reopen the mechanism question.
- If AAASM-6041 is not picked up within a reasonable time and the attack class
  is needed for a real conformance claim, re-run this probe's run 4 against
  whatever kernel/landlock crate version is current at that time before
  assuming the finding still holds — kernel behavior in this exact area is not
  guaranteed stable across releases.

## Why nothing here is committed as code

The probe source (`installer.c`, `reader.c`, the throwaway workflow) lived only
on the deleted `spike/AAASM-5532/landlock-proc-self-probe` branch — it was
disposable-by-design (a mechanism probe, not product code) and keeping it
would either bit-rot unmaintained or need folding into the real test suite,
which is exactly the harness-debugging work item 1 above defers to AAASM-6041.
This document is the durable record of what was run and what it showed; the
raw CI run IDs (`33700240600`, `33700427742`, `33700533560`, `33700612332`,
all on `AI-agent-assembly/agent-assembly`) exist in GitHub's own run history
for as long as GitHub retains them, but are not treated as the durable record
themselves — this file is.
