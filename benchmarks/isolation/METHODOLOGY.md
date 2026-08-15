# Execution-isolation benchmark methodology (AAASM-5713)

Pre-registered measurement plan and decision thresholds for Epic AAASM-5702's
question: *does AASM need a native Linux isolation backend, or is the first
process-isolation substrate good enough?*

## Status of this document

This is a **pre-registration**. Every threshold, admissibility rule and decision
rule below was written and committed **before any backend measurement existed** —
the Sandlock backend is AAASM-5708 and is not implemented yet. The git commit
that introduces this file is the timestamp that proves it, and it is the reason
the thresholds cannot later be retrofitted to whatever the backend happens to
score.

Nothing in this document draws a conclusion. The decision matrix in
[Decision rule](#decision-rule) is a *template with an empty verdict*. It stays
empty until a real backend has been measured on a Linux host.

## Scope of the delivered work

AAASM-5708 (Sandlock backend) and AAASM-5711 (`aasm run --isolation`) have both
since landed on `main`. A real confined-arm measurement now exists — see
[Confined-arm measurement](#confined-arm-measurement-aaasm-5713) — captured on a
Linux + sandlock GitHub Actions runner, on the same host and session as its
unconfined control, per this file's own admissibility rules.

What AAASM-5713 does **not** close: the decision matrix is still blocked at
rule 0 (P2 and P3 have no admissible contributing family), for a specific,
already-diagnosed reason with a concrete follow-up fix (see the compatibility
catalogue), not an unknown one. Security dimensions S1/S2 remain explicitly
out of scope, per the ticket, this document, and standing instruction — this
is a compatibility/performance spike, not a security-evidence ticket, and no
prevention-level claim is made anywhere in this file or its evidence.

| Delivered | Blocked, with a known cause and fix |
| --- | --- |
| Methodology (this file) | P2 (general) and P3 (filesystem) decision-matrix cells — no admissible family; root cause is the `/dev/null` write-grant gap below |
| Pre-registered thresholds | Full decision-matrix verdict (rule 0 blocks it while P2/P3 are blocked) |
| Runnable harness, launcher-parameterised | |
| Unconfined baseline numbers, both macOS (harness-validation only) and a fresh Linux re-capture (the real control for this run) | |
| Negative-control evidence for the harness | |
| The confined-arm launcher (`launchers/sandlock.sh`) and policy (`policy/confined-arm.yaml.tmpl`), run for real against sandlock 0.8.6 on Linux | |
| P1, P4, P5, P6, P7 measured values and grades | |
| Compatibility catalogue: 5/8 families' failures root-caused via `sh -x` traces, all classified `policy-change` | |
| Explicitly out of scope: S1, S2 (security dimensions — not this ticket) | |

## Prohibition on borrowed numbers

No published Landlock, seccomp, Bubblewrap, gVisor, Sandlock or other upstream
benchmark may be cited as an AASM performance figure. Upstream numbers were
produced on other kernels, other filesystems, other hardware and other
workloads; reusing one as an AASM measurement is a fabricated result. Every
number that enters the decision matrix must come from a local run of this
harness, with its environment block attached. This rule is an acceptance
criterion of the ticket, and it is the single most likely way this spike goes
wrong.

## What gets measured

### Launcher abstraction

The unit under test is a **launcher**: an executable invoked as

```
<launcher> -- <argv...>
```

whose contract is to execute `argv` and exit with `argv`'s exit status. Anything
it does around that — setting up a sandbox, installing a seccomp filter,
applying a Landlock ruleset, or nothing at all — is the thing being measured.

Two launchers ship with the harness today:

- `launchers/unconfined.sh` — `exec "$@"`. The baseline arm.
- `launchers/throttled.sh` — the negative control (see
  [Negative control](#negative-control)). Never a data arm.

The confined arm is a third launcher, `launchers/sandlock.sh` (AAASM-5713),
wrapping `aasm run exec --isolation process --no-proxy --policy ...` — the
product's own confined-launch path. No harness change was required to add
it. It has been run for real, on a Linux GitHub Actions runner with sandlock
0.8.6 installed — see
[Confined-arm measurement](#confined-arm-measurement-aaasm-5713).

### Workload families

Coding agents are syscall-, process- and I/O-heavy, so microbenchmarks alone
would answer the wrong question. The families below are representative
operations. Every family is declared in `workloads/manifest.json`; a family
whose required tooling is absent is recorded as `skipped` **with a reason** and
counted in the run's `denominators` block, never silently dropped.

| Family | Exercises | Default |
| --- | --- | --- |
| `startup_nop` | Per-invocation fixed cost of the launcher itself | yes |
| `repo_traversal` | `rg --files`, `rg` content search, `git status`, `git diff` | yes |
| `many_small_files` | Create / stat / read / delete 2000 small files | yes |
| `process_spawn` | 200 sequential `execve` + reap cycles | yes |
| `python_pkg_test` | `python3` import cost, bytecode compile, `unittest` discovery and run | yes |
| `node_pkg_test` | `node` startup, `pnpm install` on a dependency-free package, `node --test` | yes |
| `rust_cargo_metadata` | `cargo metadata --no-deps` over the workspace | yes |
| `rust_cargo_check` | `cargo check -p aa-core` | no — `--heavy` |
| `https_loopback` | 200 sequential HTTPS requests against a harness-run TLS server | yes |

`https_loopback` deliberately targets a loopback TLS server the harness starts
itself, not a public endpoint. That isolates the TLS and socket syscall path
from WAN variance. It measures the *cost* of network traffic under confinement.
Whether a backend can express AASM's egress policy at all is a **functional**
question and is catalogued under compatibility, not here.

### Startup cost and steady-state cost are reported separately

This separation is an acceptance criterion, so the harness enforces it
structurally rather than by convention.

- `startup_ms` is the median wall time of the `startup_nop` family under a given
  launcher. It is the fixed per-invocation cost: sandbox construction plus
  teardown, paid once for every command an agent shells out to.
- For every other family, the harness reports **both**
  - `stats_ms` — total wall time including that fixed cost, and
  - `steady_state_ms` — the same distribution with the launcher's median
    `startup_ms` subtracted, i.e. the cost of the work itself.

They are classified against different thresholds because they fail differently.
Startup cost multiplies by the number of tool calls in a session and cannot be
tuned away by policy. Steady-state cost scales with the work and can sometimes
be mitigated by narrowing a ruleset.

### Per-invocation instrumentation

Each repetition is a `fork` + `execvp` + `wait4`, so `wait4`'s `rusage` is the
exact resource usage of that one child process tree, not a cumulative counter
shared with the harness's other children. Recorded per repetition:

- wall time, from `time.perf_counter_ns()` around the fork/wait pair;
- `ru_utime` and `ru_stime`;
- `ru_maxrss`, normalised to bytes — **BSD/macOS reports bytes, Linux reports
  KiB**, and the normalisation applied is recorded in the result file so the
  number is not silently off by 1024×;
- exit status.

Scratch directories are created fresh per repetition and removed outside the
timed region.

## Reproducibility rules

### Environment is part of the measurement

A number without its environment is not reproducible, so the harness refuses to
emit a result without one. Every result file carries: OS and kernel release,
full `uname`, CPU model and logical core count, total RAM, the filesystem type
and device backing the scratch directory, versions of every toolchain binary a
selected family uses, the repository commit and dirty flag, load average at
start, and the harness and schema versions.

From a subset of those the harness computes an **environment fingerprint**
(OS, kernel release, machine, CPU model, core count, scratch filesystem type,
and all toolchain versions).

### Variance, not a single sample

A single timing sample is not a measurement. Each family runs `--warmups`
repetitions that are discarded, then `--repetitions` that are kept. Default
2 warmups, 10 kept repetitions. The result file carries **every raw sample**
alongside min, median, mean, p95, max, stdev, IQR and relative IQR.

### Admissibility gate

A family's result is **admissible** only when

- at least 10 post-warmup repetitions completed, and
- every repetition exited 0, and
- relative IQR (IQR ÷ median) ≤ **0.15**.

An inadmissible family is reported `UNSTABLE` with the reason. It may not be
rounded into a verdict, and it blocks the verdict entirely — see
[Decision rule](#decision-rule). The fix is a quieter host and a re-run, never
a softer threshold.

### Cross-platform comparison is invalid

**This matters immediately: the baseline in this PR was captured on macOS
(darwin), and the eventual backend is Linux-only.**

A darwin unconfined baseline is **not** a valid control for a Linux confined
run. The two arms differ in kernel, syscall costs, filesystem, allocator and
toolchain builds, so any ratio between them measures the platform, not the
sandbox. The macOS numbers committed here are a *harness-validation artefact and
a shape reference* — they demonstrate the harness runs end to end and produces
the intended distributions. They are not the control arm for anything.

The harness enforces this rather than trusting a reader to remember it:
`aabench.py compare` refuses two result files whose environment fingerprints
differ. `--allow-cross-env` overrides the refusal but stamps the output
`"control_validity": "INVALID_CONTROL"` and forces `"verdict": null`. A
comparison stamped `INVALID_CONTROL` may not be quoted.

The operational consequence: **the baseline arm must be re-captured on the same
Linux host, kernel and filesystem as the confined arm**, in the same session.
The macOS baseline is not reusable for that purpose.

### Machine-readable output

Results are JSON with an explicit `schema_version`, so a later run can be diffed
against this one by `aabench.py compare` without re-parsing prose.

## Negative control

A harness that has never reported a regression has not been shown to be able to
report one. `aabench.py self-test` runs the harness against a deliberately
degraded launcher and **fails (exit 1) unless the harness detects the
degradation**.

`launchers/throttled.sh` has two modes:

- `delay` — sleeps `AABENCH_THROTTLE_MS` (default 150) once, then `exec "$@"`.
  This injects a known *fixed per-invocation* cost and nothing else.
- `repeat` — runs `"$@"` `AABENCH_THROTTLE_REPEAT` times (default 2). This
  injects a known *proportional steady-state* cost and almost no fixed cost.

The self-test asserts three properties, and each one can fail independently:

1. **Startup regressions are detected.** Under `delay`, the measured startup
   delta must land within ±40 % of the injected delay, and P1 must classify
   **RED**. The self-test injects **500 ms** rather than the launcher's 150 ms
   default, because 150 ms would land in P1's AMBER band and the assertion needs
   a degradation that is unambiguously past the RED threshold at both ends of
   the tolerance window. If the harness reports GREEN against 500 ms, it cannot
   detect a real regression.
2. **The startup/steady-state separation is real.** Under `delay`, the
   *startup-corrected* steady-state ratio of a real workload must stay GREEN.
   A fixed per-invocation cost must not leak into the steady-state number; if it
   does, the two costs are not actually separated and the acceptance criterion
   is unmet.
3. **Steady-state regressions are detected.** Under `repeat`, the steady-state
   ratio must be ≈2× (within ±40 %) and must classify **RED**.

Assertions 1 and 3 prove sensitivity; assertion 2 proves the two metrics are not
the same metric wearing two hats. The self-test's own output is committed as
evidence under `results/`.

### The self-test can fail for two very different reasons

Observed on a loaded host (load average ~9): assertion 3 failed not because the
harness missed the injected 2× slowdown, but because `startup_nop` in the repeat
arm recorded a relative IQR of 0.162 against the 0.15 gate. That made it
inadmissible, which left no startup correction available, which left P4 with no
comparable pair — so P4 came back **blocked**, and a blocked dimension fails the
assertion. The raw medians in that same run showed the slowdown plainly
(768.7 ms against 391.7 ms, ≈1.96×). The harness declined to score it rather
than score it on a number it had already judged unreliable.

So a red self-test means one of two things, and they are not interchangeable:

- **a blocked dimension** — the host was too noisy, nothing was measured, re-run
  somewhere quieter; or
- **a graded dimension that came back wrong** — the harness genuinely failed to
  detect a known degradation, which is a defect in the harness.

Read the `checks[].detail` and the `blocked` reason before concluding which.
`startup_nop` is the family most prone to the first case: its absolute duration
is a few milliseconds, so ordinary scheduler jitter is large *relative* to it,
and under `repeat` mode it is doubled while staying small. Loosening
`MAX_REL_IQR` to make this go away would defeat the gate it exists to be.

## Evidence committed alongside this pre-registration

| File | What it is | What it is not |
| --- | --- | --- |
| `results/baseline-unconfined-darwin.json` | Unconfined baseline, all eight default families, 10 repetitions after 2 warmups, every family admissible | A control arm for any Linux run |
| `results/selftest-evidence.json` | Negative-control result: the three assertions and the comparisons behind them | A backend measurement |
| `results/selftest-arm-*.json` | The three synthetic control arms, flagged `"control_experiment": true` | Data arms |

No performance conclusion is drawn from any of them. The baseline exists to
demonstrate the harness produces the intended distributions and to fix the shape
of the result schema; the self-test files exist to demonstrate the harness can
detect a regression at all.

## Pre-registered thresholds

All ratios are confined ÷ baseline, **median vs median**, both arms captured on
the same host in the same session. All absolute deltas are confined − baseline.

### Performance dimensions

| ID | Dimension | Metric | GREEN | AMBER | RED |
| --- | --- | --- | --- | --- | --- |
| P1 | Startup overhead | `startup_nop` median, added ms | ≤ 50 ms | ≤ 250 ms | > 250 ms |
| P2 | Steady state, general | ratio, families tagged `general` | ≤ 1.05 | ≤ 1.25 | > 1.25 |
| P3 | Steady state, filesystem | ratio, families tagged `fs` | ≤ 1.10 | ≤ 1.50 | > 1.50 |
| P4 | Steady state, process spawn | ratio, families tagged `process` | ≤ 1.10 | ≤ 1.50 | > 1.50 |
| P5 | Steady state, network | ratio, families tagged `network` | ≤ 1.10 | ≤ 1.50 | > 1.50 |
| P6 | Peak memory | `ru_maxrss` median, added bytes | ≤ 32 MiB | ≤ 128 MiB | > 128 MiB |
| P7 | CPU time | (`ru_utime` + `ru_stime`) ratio | ≤ 1.05 | ≤ 1.20 | > 1.20 |

Why these numbers, chosen before seeing any:

- **P1** — a coding agent shells out per tool call, often dozens of times per
  task. 50 ms is below the threshold at which a single call reads as slower;
  250 ms compounds into seconds of dead time across a session and is where a
  user starts blaming the tool. Startup cost is also the one dimension policy
  tuning cannot recover, which is why P1 alone can force a No-Go.
- **P2** — general compute should be nearly untouched by an LSM-style boundary.
  If it is not, the backend is doing something structurally expensive and 25 %
  is already an unreasonable tax on work the sandbox should not be interposing
  on at all.
- **P3, P4, P5** — path resolution, `execve` and socket setup are exactly where
  a Landlock/seccomp-style boundary does its work, so a real cost is expected
  and 10 % is tolerated as GREEN. 50 % is the point at which the sandbox, not
  the work, dominates a hot loop like repository traversal.
- **P6** — 32 MiB per confined process tree is noise on a developer machine;
  128 MiB × a handful of concurrent agents is not, and it changes the
  memory footprint AASM can be deployed into.
- **P7** — CPU overhead above 20 % means the boundary burns a fifth of the
  machine's capacity on enforcement, which is a poor trade against building a
  narrower native launcher.

### Aggregating a dimension over several families

P3 covers two families and P6 and P7 are computed across all of them, so a tag
with more than one contributing family needs an aggregation rule, pre-registered
like everything else: **the worst family in the tag wins**, not the mean.
Averaging would let a cheap family mask an expensive one, and the decision rule
resolves ambiguity toward the more conservative outcome. The result file records
every contributing family's individual figure alongside the aggregate, so the
spread is inspectable rather than collapsed.

A family contributes only if it is admissible in **both** arms. A family that
was stable on one arm and noisy on the other has not been compared; it has been
guessed at, and it is reported blocked.

### Compatibility dimensions

Measured functionally, not by timing. Any family that fails to complete, exits
non-zero, or produces wrong output under the backend with AASM's intended policy
is a compatibility failure. Every failure must be catalogued with a
classification, and the classification is what drives the decision — not the
count:

| Class | Meaning |
| --- | --- |
| `policy-change` | Fixable by changing AASM policy, without weakening any advertised control |
| `backend-change` | Fixable only by changing or patching the substrate |
| `unavoidable-upstream` | Not fixable without abandoning the substrate |

| ID | Dimension | GREEN | AMBER | RED |
| --- | --- | --- | --- | --- |
| C1 | Functional compatibility | No failures, no escape hatches beyond the documented policy surface | All failures classify `policy-change` | Any `backend-change` or `unavoidable-upstream` failure, or any escape hatch that disables an advertised control |

### Security dimensions

Evaluated **separately from performance**, and never traded against it. A fast
backend that cannot enforce a control AASM advertises is not a Conditional Go.

| ID | Dimension | GREEN | AMBER | RED |
| --- | --- | --- | --- | --- |
| S1 | Advertised-control coverage | Backend enforces every control AASM's capability model advertises | — | Any advertised control unenforceable |
| S2 | Kernel floor | Full coverage at the supported kernel floor | Full coverage only above the floor; floor must then be stated explicitly in the product docs | Coverage unattainable on any supported kernel |

### Sustainability evidence

Recorded as evidence rather than scored, because these are judgements, not
measurements: upstream release cadence and maintenance risk, packaging and
upgrade complexity, distribution and kernel version requirements, and an
engineering-cost estimate for the AASM-native alternative. They break ties and
they are the input to a Conditional Go's sequencing, not to its trigger.

## Decision rule

Evaluated in order; the first matching rule wins. Ambiguity resolves toward the
more conservative outcome.

0. **Blocked — no verdict.** Any dimension whose data is `UNSTABLE` or missing.
   A verdict may not be issued on an inadmissible measurement. Re-run on a quiet
   host.
1. **Build AASM-native Linux backend.** Any S RED, **or** C1 RED, **or** two or
   more P dimensions RED, **or** P1 RED on its own — per-invocation startup cost
   is not recoverable by policy tuning, so it decides alone.
2. **Add a second backend.** No S RED, and either two or more P dimensions
   AMBER, **or** exactly one P RED confined to a single workload family,
   **or** C1 AMBER.
3. **Continue with the substrate.** All P dimensions GREEN except at most one
   AMBER, C1 GREEN, no S RED.

### Decision matrix

**Verdict: blocked at rule 0 — no verdict may be issued.** P2 and P3 have no
comparable admissible family in the confined arm (see
[Confined-arm measurement](#confined-arm-measurement-aaasm-5713) below for
why, and for the specific, already-identified fix). Rule 0 pre-empts every
other rule regardless of what P1/P4/P5/P6/P7/C1 show, so none of the values
below — including the two REDs — currently produce a Build/Add/Continue
verdict on their own; they are recorded because they are real measurements
and because P4/P7's classification is informative for whoever re-runs this
after the fix.

| ID | Dimension | Baseline (Linux, unconfined) | Confined | Class |
| --- | --- | --- | --- | --- |
| P1 | Startup overhead | 3.05 ms | 244.18 ms | **AMBER** (+241.13 ms) |
| P2 | Steady state, general | n/a | n/a | **BLOCKED** — no admissible general family (`python_pkg_test`, `node_pkg_test` both inadmissible in the confined arm) |
| P3 | Steady state, filesystem | n/a | n/a | **BLOCKED** — no admissible fs family (`many_small_files`, `repo_traversal` both inadmissible in the confined arm) |
| P4 | Steady state, process spawn | 100.25 ms | 182.33 ms | **RED** (1.82x, family `process_spawn`) |
| P5 | Steady state, network | 593.02 ms | 641.86 ms | **GREEN** (1.08x, family `https_loopback`) |
| P6 | Peak memory | 17.30–20.54 MiB | 30.28–30.38 MiB | **GREEN** (+12.98 MiB worst case, family `startup_nop`) |
| P7 | CPU time | 2.7–336.7 ms | 246.2–631.0 ms | **RED** (89.90x worst case, family `startup_nop`; 1.87x–4.28x for the other two admissible families) |
| C1 | Functional compatibility | n/a | 3/8 admissible, 5/8 failed | **AMBER** — every failure classifies `policy-change` (see catalogue below) |
| S1 | Advertised-control coverage | n/a | not evaluated | out of scope — AAASM-5713 is a compatibility/performance spike, not a security-evidence ticket |
| S2 | Kernel floor | n/a | not evaluated | out of scope, same reason |

P7's 89.90x figure is driven almost entirely by `startup_nop`'s near-zero
unconfined CPU time (2.7 ms) — the same fixed per-invocation cost P1 already
reports as +241 ms in wall time shows up again here as a large *ratio* on a
tiny absolute baseline. `process_spawn` and `https_loopback`'s own CPU
ratios (4.28x and 1.87x) are the more representative figures for work that
isn't dominated by the launcher's fixed cost, but the pre-registered
aggregation rule is "worst family wins," not "worst-except-the-outlier," so
the worst figure is what is reported.

### Confined-arm measurement (AAASM-5713)

Measured 2026-08-15 on a GitHub Actions `ubuntu-latest` runner
(`.github/workflows/ci.yml`'s `isolation-benchmark-confined-arm` job,
`workflow_dispatch`-only), commit `4cb84077365cac957d518ccfdfc34fed0c32bef6`.
Environment fingerprint `sha256:0011f4f3974fa28b1398e3d65ad399da4e1d259e2b1990479479aff708d256a6`,
carried by all three result files below and matched between baseline and
confined (`control_validity: VALID`).

| | |
| --- | --- |
| Kernel | Linux 6.17.0-1022-azure, x86_64 |
| LSM stack | lockdown, capability, landlock (ABI v7), yama, apparmor, ima, evm |
| CPU / RAM | AMD EPYC 7763 64-Core Processor, 4 logical cores / 15.6 GiB |
| Scratch filesystem | ext4 on `/dev/sda1` |
| Backend | sandlock 0.8.6 (Apache-2.0, unmodified), digest-pinned per `metadata/isolation-backends.json` |
| Policy | `benchmarks/isolation/policy/confined-arm.yaml.tmpl` rendered against the run's scratch root (`policy/README.md`) |
| Repetitions | 2 warmups + 10 kept, all 8 default families, `--heavy` not run |

Result files: `results/confined-run-baseline-unconfined-linux.json`,
`results/confined-run-sandlock-linux.json`,
`results/confined-run-comparison-linux.json`. The baseline is a **fresh
re-capture on this same host and session** — the darwin baseline
(`results/baseline-unconfined-darwin.json`) was never used as a control for
it, per [Cross-platform comparison is invalid](#cross-platform-comparison-is-invalid).

`repo_traversal` is inadmissible in **both** arms (`git diff --stat HEAD~1
HEAD` fails on a shallow CI checkout with no `HEAD~1`) — a harness/CI
environment gap, unrelated to confinement, and not counted as a compatibility
finding.

#### Compatibility catalogue

Five of eight families fail under confinement, all `status: failed`, exit
code 2, `families_ok: 3, families_failed: 5`. Root-caused with `sh -x` traces
of the actual workload scripts under confinement (not reconstructed or
guessed — see the PR history on this file for the diagnostic path, including
two dead ends: a benchmark-harness launcher-path bug and a missing
governance-gateway registration step, both fixed before this data was
captured and neither a compatibility finding).

| Family | Failure | Root cause | Class |
| --- | --- | --- | --- |
| `rust_cargo_metadata` | exit 2 | `cargo metadata ... >/dev/null` — `sh: cannot create /dev/null: Permission denied` | `policy-change` |
| `many_small_files` | exit 2 | `wc -l < listing.txt >/dev/null` — same `/dev/null` write denial | `policy-change` |
| `python_pkg_test` | exit 2 | `python3 -m compileall -q ... >/dev/null` / `python3 -m unittest discover ... >/dev/null` — same | `policy-change` |
| `node_pkg_test` | exit 2 | `pnpm install ... >/dev/null` / `node --test ... >/dev/null` — same | `policy-change` |
| `repo_traversal` | exit 2 | `rg --files ... >/dev/null` (first command in the script) — same | `policy-change` |

**Every failure has the same root cause and the same classification.** The
confined-arm policy's filesystem-write grant (`policy/confined-arm.yaml.tmpl`)
scopes write access to the harness's scratch directory only; it does not
include `/dev/null`, and Sandlock's write confinement denies opening
`/dev/null` for writing exactly like any other ungranted path. Every default
workload family that redirects a noisy command's output to `/dev/null` — a
completely ordinary shell idiom, not a security-relevant write — fails at
that redirection, and `sh -eu` propagates the shell's own redirection-failure
exit status (2) before the family's actual measured work ever runs.

Classified `policy-change`, not `backend-change`: granting write access to
`/dev/null` specifically (or treating it as always-available, as several
other sandboxing tools do since it is a data sink with no persistence or
exfiltration surface) does not weaken any control AASM advertises. Re-running
the confined arm with that grant added to `policy/confined-arm.yaml.tmpl`
would very likely resolve P2 and P3's blocked status — this was not attempted
in this pass; see below.

A second, independent finding surfaced during bisection rather than in the
family runs themselves: a bare `git status` (not wrapped in `>/dev/null`)
also fails under confinement, exit 128 (git's own fatal-error convention,
`refusal_count=0` in the isolation report — sandlock did not refuse the
launch; git itself failed once running), consistent with `git status`
attempting to refresh `.git/index`, which lies outside the scratch-only
write grant. This was not the proximate cause of `repo_traversal`'s failure
(its first command, `rg --files ... >/dev/null`, already fails first), so it
is recorded as a latent, not-yet-triggered finding rather than a sixth
catalogue entry. Also `policy-change`-classifiable in principle, but whether
an AASM operator *should* grant a confined agent write access to its own
repository's `.git` directory is a real product/policy design question, not
a mechanical grant-widening — flagged as a follow-up rather than resolved
here.

#### Follow-up

- Add a `/dev/null` write grant (or equivalent) to
  `policy/confined-arm.yaml.tmpl` and re-run the confined arm. If P2 and P3
  become admissible, the decision matrix above can be re-evaluated against
  the pre-registered thresholds without any other change.
- Consider whether AASM's policy schema or Sandlock backend should treat
  `/dev/null` as always-writable regardless of the filesystem-write grant —
  every default workload family in this harness needed it, which suggests
  ordinary agent shell usage would hit the same wall immediately.
- The `git status` / `.git` write question above is a distinct, smaller
  follow-up: decide whether a confined launch's write grant should default
  to including the repository it was invoked against.

## Threshold changes

Thresholds live in exactly two places that must agree: the tables above and
`harness/thresholds.py`. Changing either after a backend measurement exists
defeats the pre-registration. If a threshold turns out to be wrong, change it in
a commit that states the reason and predates the next measurement run, and
report both the old and new classification.
