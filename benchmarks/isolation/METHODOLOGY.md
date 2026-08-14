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
since landed on `main`. What AAASM-5713 could not deliver in this pass is a
**measurement**: every session that has worked on this directory so far ran on
a host with no Linux + sandlock execution access, and METHODOLOGY.md's own
rules (see [Cross-platform comparison is invalid](#cross-platform-comparison-is-invalid))
forbid substituting a macOS run, a CI-adjacent lane's numbers, or an upstream
figure for that measurement.

| Delivered now | Still deferred, pending a Linux + sandlock run |
| --- | --- |
| Methodology (this file) | Confined measurements |
| Pre-registered thresholds | Compatibility-failure catalogue |
| Runnable harness, launcher-parameterised | Security-limitation evaluation (S1/S2) |
| Unconfined baseline numbers (macOS, harness-validation only) | Decision-matrix verdict |
| Negative-control evidence for the harness | Follow-up tickets |
| The confined-arm launcher (`launchers/sandlock.sh`) and its policy artifact (`policy/allow-all.yaml`), built and confirmed against a real `aa-cli` build's CLI grammar | Confirmation that `policy/allow-all.yaml`'s lowering actually grants what each workload family needs (see `policy/README.md`) |

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
product's own confined-launch path, confirmed against a real `aa-cli` build.
No harness change was required to add it. It has not yet been *run*: doing so
needs a Linux host with the sandlock mechanism installed, which no session
working on this directory has had access to so far.

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

Verdict: **not yet determined — blocked at rule 0, no backend measurement
exists.** This table is populated by AAASM-5708's follow-up run.

| ID | Dimension | Baseline (Linux, unconfined) | Confined | Class |
| --- | --- | --- | --- | --- |
| P1 | Startup overhead | pending | pending | pending |
| P2 | Steady state, general | pending | pending | pending |
| P3 | Steady state, filesystem | pending | pending | pending |
| P4 | Steady state, process spawn | pending | pending | pending |
| P5 | Steady state, network | pending | pending | pending |
| P6 | Peak memory | pending | pending | pending |
| P7 | CPU time | pending | pending | pending |
| C1 | Functional compatibility | n/a | pending | pending |
| S1 | Advertised-control coverage | n/a | pending | pending |
| S2 | Kernel floor | n/a | pending | pending |

## Threshold changes

Thresholds live in exactly two places that must agree: the tables above and
`harness/thresholds.py`. Changing either after a backend measurement exists
defeats the pre-registration. If a threshold turns out to be wrong, change it in
a commit that states the reason and predates the next measurement run, and
report both the old and new classification.
