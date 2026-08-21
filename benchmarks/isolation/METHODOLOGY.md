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

**Verdict: BUILD AASM-NATIVE LINUX BACKEND (rule 1).** Two P dimensions —
P2 and P3 — are RED, which alone satisfies rule 1's "two or more P
dimensions RED" clause regardless of what C1/S1/S2 show. This is the actual,
concrete recommendation this ticket exists to produce, evaluated mechanically
against the pre-registered thresholds below — no threshold was changed
after this measurement existed.

An earlier pass (superseded by this one, kept in git history for the
diagnostic record) recorded "blocked at rule 0" because P2 and P3 had no
admissible confined-arm family at all — every contributing family failed on
a benchmark-artifact bug (see [Compatibility
catalogue](#compatibility-catalogue) below), not a backend limitation. That
bug is fixed; this is the re-measurement.

| ID | Dimension | Baseline (Linux, unconfined) | Confined | Class |
| --- | --- | --- | --- | --- |
| P1 | Startup overhead | 2.92 ms | 239.49 ms | **AMBER** (+236.57 ms) |
| P2 | Steady state, general | 30.86–467.31 ms | 55.69–508.53 ms | **RED** (1.80x worst case, family `rust_cargo_metadata`; `python_pkg_test` also over-amber at 1.52x) |
| P3 | Steady state, filesystem | 159.71 ms | 1029.74 ms | **RED** (6.45x, family `many_small_files`) |
| P4 | Steady state, process spawn | 99.14 ms | 176.68 ms | **RED** (1.78x, family `process_spawn`) |
| P5 | Steady state, network | 574.47 ms | 621.25 ms | **GREEN** (1.08x, family `https_loopback`) |
| P6 | Peak memory | 17.5–114.2 MiB | 30.3–114.2 MiB | **GREEN** (+12.88 MiB worst-case delta, family `startup_nop`) |
| P7 | CPU time | 2.6–544.6 ms | 241.1–1238.7 ms | **RED** (92.30x worst case, family `startup_nop`; 1.52x–8.81x for the other six admissible families) |
| C1 | Functional compatibility | n/a | 7/7 comparable families admissible, 0 failed | **GREEN** — no failures, no escape hatches (see catalogue below) |
| S1 | Advertised-control coverage | n/a | not evaluated | out of scope — AAASM-5713 is a compatibility/performance spike, not a security-evidence ticket; pre-declared before any measurement, not a runtime gap rule 0 is meant to catch |
| S2 | Kernel floor | n/a | not evaluated | out of scope, same reason |

**Rule 0 does not apply here** even though S1/S2 have no data: rule 0's
"any dimension whose data is UNSTABLE or missing" targets a dimension this
run *attempted* to measure and got an inadmissible/unstable result for —
exactly what happened to P2/P3 in the prior pass. S1/S2 were scoped out of
this ticket in the original pre-registration, before any backend
measurement existed (see the "Status of this document" section at the top
of this file and the Security dimensions' own "out of scope" note above) —
treating a pre-declared scope boundary as a rule-0-blocking gap would make
this decision matrix permanently unable to produce a verdict, which
contradicts the ticket's own acceptance criteria. P1/P4/P5/P6/P7/C1 are all
admissible and comparable; only S1/S2 (never in scope) are absent.

Rule 1 fires on P2 and P3 alone; C1's GREEN and P1/P4/P7's AMBER/RED do not
change the outcome, since rule 1's clauses are OR'd and any one is
sufficient. Reported for completeness, not because they were needed to
reach this verdict.

P7's 92.30x figure is driven almost entirely by `startup_nop`'s near-zero
unconfined CPU time (2.6 ms) — the same fixed per-invocation cost P1 already
reports as +237 ms in wall time shows up again here as a large *ratio* on a
tiny absolute baseline. The other six admissible families' own CPU ratios
(1.52x–8.81x) are the more representative figures for work that isn't
dominated by the launcher's fixed cost, but the pre-registered aggregation
rule is "worst family wins," not "worst-except-the-outlier," so the worst
figure is what is reported — same treatment as the prior pass.

### Confined-arm measurement (AAASM-5713)

Measured 2026-08-15 on a GitHub Actions `ubuntu-latest` runner
(`.github/workflows/ci.yml`'s `isolation-benchmark-confined-arm` job,
`workflow_dispatch`-only), commit `5f7de74f6677ca1f0fa5a2a9e639c7a01cd964e3`
(the `/dev/null` policy-grant fix). Environment fingerprint
`sha256:0011f4f3974fa28b1398e3d65ad399da4e1d259e2b1990479479aff708d256a6`,
matched between baseline and confined (`control_validity: VALID`,
`"environment fingerprints match"`).

| | |
| --- | --- |
| Kernel | Linux 6.17.0-1022-azure, x86_64 |
| CPU / RAM | AMD EPYC 7763 64-Core Processor, 4 logical cores / 15.6 GiB |
| Scratch filesystem | ext4 on `/dev/sda1` |
| Backend | sandlock 0.8.6 (Apache-2.0, unmodified), digest-pinned per `metadata/isolation-backends.json` |
| Policy | `benchmarks/isolation/policy/confined-arm.yaml.tmpl` (with the `/dev/null` write grant) rendered against the run's scratch root (`policy/README.md`) |
| Toolchains | cargo 1.97.1, git 2.54.0, node v22.23.2, pnpm 10.9.0, python3 3.12.3, ripgrep 14.1.0 |
| Repetitions | 2 warmups + 10 kept, all 8 default families, `--heavy` not run |
| Baseline run_id | `20260815T072654Z-993ba7be` |
| Confined run_id | `20260815T072736Z-0b628c85` |

Result files: `results/confined-run-baseline-unconfined-linux.json`,
`results/confined-run-sandlock-linux.json`,
`results/confined-run-comparison-linux.json`, updated to this measurement.
The baseline is a **fresh re-capture on this same host and session** — the
darwin baseline (`results/baseline-unconfined-darwin.json`) was never used
as a control for it, per [Cross-platform comparison is
invalid](#cross-platform-comparison-is-invalid).

`repo_traversal` is inadmissible in **both** arms (`git diff --stat HEAD~1
HEAD` fails on a shallow CI checkout with no `HEAD~1`) — a harness/CI
environment gap, unrelated to confinement, and not counted as a compatibility
finding, same as the prior pass. `families_ok: 7, families_failed: 1` in the
raw JSON reflects that one exclusion, not a compatibility regression.

#### Compatibility catalogue

**No compatibility failures this measurement.** All 7 families comparable
between arms (`repo_traversal` excluded as above) completed successfully
under confinement — `families_admissible: 7`, zero `policy-change`,
`backend-change`, or `unavoidable-upstream` findings. C1 grades **GREEN**.

The five failures from the prior pass (`rust_cargo_metadata`,
`many_small_files`, `python_pkg_test`, `node_pkg_test`, `repo_traversal`)
were a single root cause — the confined-arm policy's write grant did not
include `/dev/null`, and every one of those families redirects a noisy
command's stdout there, a completely ordinary shell idiom with no
persistence or exfiltration surface. Fixed by granting `/dev/null` write in
`policy/confined-arm.yaml.tmpl` (classified `policy-change`, verified not to
weaken any control this benchmark measures — see that file's comment and
`policy/README.md`). Root-caused via `sh -x` traces of the actual workload
scripts under confinement in the prior pass, not reconstructed or guessed;
see PR history on this file for that diagnostic path.

The latent `git status` / `.git`-write finding recorded in the prior pass
(exit 128, `.git/index` refresh landing outside the scratch-only write
grant) remains unresolved and untriggered by any of the 8 default families
— still a real, smaller follow-up (whether a confined launch's write grant
should default to including the repository it was invoked against), not a
sixth catalogue entry, and not required to reach this measurement's verdict.

#### Follow-up (non-blocking, not required by this verdict)

- Decide whether AASM's policy schema or Sandlock backend should treat
  `/dev/null` as always-writable regardless of the filesystem-write grant —
  every default workload family in this harness needed it, which suggests
  ordinary agent shell usage hits the same wall immediately outside this
  benchmark too. A product/policy question, not a benchmark task.
- The `git status` / `.git` write question above: decide whether a confined
  launch's write grant should default to including the repository it was
  invoked against.
- This verdict (BUILD AASM-NATIVE LINUX BACKEND) is itself the required
  next-phase trigger — scoping that work is future Epic/ticket planning, not
  part of AAASM-5713's own deliverable.

## Default-backend selection rule (AAASM-5805)

The decision rule and matrix above answer "should AASM build a native Linux
backend at all" — they do not answer AAASM-5805's question, which is which
of the two now-existing backends `aasm run --isolation auto` should prefer,
if either. Applying the matrix above "mechanically" to a native measurement
would produce two independent grade tables, not a comparison; this section
pre-registers the actual selection rule, **before any native-backend
benchmark number exists**, git-timestamping it the same way the rest of this
document pre-registers its own thresholds.

Applied only when both arms' `control_validity` is `VALID` against the same
same-host/same-session unconfined baseline (this document's own
admissibility gate — an inadmissible measurement gets no verdict here
either, same as rule 0 above). Evaluated in order; first match wins.

1. **Blocked.** Either arm's `control_validity` is not `VALID` — no default
   changes; `aasm run --isolation auto` keeps selecting Sandlock, and the
   reason is recorded rather than guessed around.
2. **Coverage decides before performance.** If one backend's
   `SupportLevel`-supported domain set (as reported by its own
   `IsolationBackend::capabilities()`, not asserted from memory) is a strict
   superset of the other's on the measured host, that backend is
   recommended regardless of what P1–P7 show — an advertised control that
   cannot be enforced at all is not tradeable against latency; this is the
   same rule the Security dimensions section above already applies within a
   single backend's own verdict.
3. **Neither domain set contains the other — performance decides,
   conservatively.** A backend is recommended only if it grades at least as
   well as the other on every P dimension **and** strictly better on at
   least one. Anything short of that is not a recommendation to switch.
4. **Otherwise: no default change.** `aasm run --isolation auto` continues
   to select Sandlock; backend choice stays reachable only via the explicit
   `--isolation-backend` flag until a later measurement separates the two.

**Prediction, recorded before the run:** rule 2 will not fire. As of this
pre-registration, the two backends' supported domains are:

| Domain | Sandlock | AASM-native |
| --- | --- | --- |
| `FilesystemRead` | supported | supported |
| `FilesystemWrite` | supported | supported |
| `NetworkEgress` | supported | **Unsupported** |
| `ProcessCreation` | supported/partial | **Unsupported** |
| `Resource` | supported/partial | **Unsupported** |
| `Ipc` | partial | **Unsupported** |
| `Credential` | supported/partial | **Unsupported** |
| `Syscall` | **Unsupported** | supported |

Neither set contains the other — Sandlock covers six domains native does
not, native covers one domain (`Syscall`) Sandlock does not — so rule 2 is
expected to be inapplicable and rule 3 or rule 4 is expected to decide. This
asymmetry is itself a finding, not prose: it is recorded from each
backend's own measured `CapabilityReport` in the same benchmark run that
produces the P-dimension numbers, not asserted ahead of it.

**Note for whoever runs this: rule 4 ("no default change") is a likely and
entirely honest outcome, not a failure of this ticket.** AAASM-5805's own
acceptance criteria ask which backend should be preferred "if either" —
plan around reporting the numbers and applying the rule mechanically, not
around switching the default. If rule 2 or rule 3 does fire for native, the
code change is `aa-cli/src/commands/run.rs`'s `isolation_backend` match
(currently defaulting to `aa_isolation_sandlock::BACKEND_ID`) plus its
adjacent refusal message, plus closing Core ADR 035's AAASM-5801 deferral
paragraph — small enough for the same PR, per the ticket's own scope note.

### Three-arm measurement (AAASM-5805)

_Recorded once the three-arm CI job (`isolation-benchmark-three-arm`) has
run and its results downloaded — not yet populated as of this
pre-registration._

## Threshold changes

Thresholds live in exactly two places that must agree: the tables above and
`harness/thresholds.py`. Changing either after a backend measurement exists
defeats the pre-registration. If a threshold turns out to be wrong, change it in
a commit that states the reason and predates the next measurement run, and
report both the old and new classification.
