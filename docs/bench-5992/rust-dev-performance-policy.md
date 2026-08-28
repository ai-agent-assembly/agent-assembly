# Rust Development Performance Policy

Durable, evidence-backed policy for Rust development on the `agent-assembly` workspace,
covering the fast edit loop through release verification, multi-agent/multi-worktree
scheduling, and target-dir/cache lifecycle. Produced by the AAASM-5991 epic
("Reusable Rust development acceleration toolkit and performance profiles").
Consumed by: contributors (via `CONTRIBUTING.md` → "Faster builds"), and coding-agent
QA/dev skills that need a canonical answer to "what's the right Cargo/nextest
invocation for this situation."

**Source of truth.** This document summarizes and links to the underlying evidence
rather than restating it: [`docs/bench-5992/report.md`](report.md) (the
AAASM-5992 benchmark spike) has full methodology, raw numbers, and the adversarial
review that resolved its own findings. When this policy and that report disagree,
treat a discrepancy as a bug in this document and fix it — the report is the
primary evidence.

## Status

| Ticket | What it delivered | Status |
|---|---|---|
| AAASM-2551 | Dev/test/release/dist Cargo profile tuning, CI mold linker, dependency dedup | Done (pre-existing, verified live) |
| AAASM-5909/5910/5911 | Diagnosed the dyld/syspolicyd first-launch stall; shipped nextest targeted-scope convention | Done (pre-existing) |
| AAASM-5992 | Benchmark spike: reused/classified prior evidence, measured baseline + sccache + discovery overhead, NO_NEW_REPO decision | Done — [PR #2258](https://github.com/ai-agent-assembly/agent-assembly/pull/2258) |
| AAASM-5996 | Removed stale macOS `lld` suggestion (unsupported per current upstream Rust) | Done — [PR #2261](https://github.com/ai-agent-assembly/agent-assembly/pull/2261) |
| AAASM-5994 | sccache wired into 3 `CARGO_INCREMENTAL=0` CI jobs (build, commit-range-build, clippy) | Done — [PR #2262](https://github.com/ai-agent-assembly/agent-assembly/pull/2262) |
| AAASM-5995 | Confirmed discovery-overhead cost scales with target count, not a fixed workspace tax | Done (investigation only, no code) |
| AAASM-5981 | `scripts/rust-target-lifecycle.sh` — attribution + ownership-scoped automatic reclamation | Done — [PR #2263](https://github.com/ai-agent-assembly/agent-assembly/pull/2263) |
| AAASM-6003 | Baseline measurement of Build/Clippy/Test/commit-range-build CI job wall-clock, cache restore/save, and sccache stats from existing runs | Done (this section) |

## Profile guide

Five situations, five different right answers. Use the narrowest one that fits what
you're actually doing — the fast-edit profile is not a substitute for full QA, and
running full QA for a one-line check is real, measured time wasted (§ Evidence below).

### 1. Fast edit loop (check/build after a small change)

**Just build. No extra flags, no sccache, no linker override.**

- Dev profile tuning (`line-tables-only` debuginfo, `opt-level = 1` for deps) is
  already on by default in `Cargo.toml` — nothing to enable.
- **Do not set `RUSTC_WRAPPER=sccache` locally.** Measured: it's a no-op for this
  loop. Cargo's own incremental cache handles a warm single-file edit before
  `rustc`/`sccache` is ever invoked (report §5 Test B: 9s cold → 0s warm, zero
  sccache compile requests on the warm run).
- Measured warm rebuild after a 1-line change: **6s** (report §4), on the current
  dev profile, isolated target-dir, no contention.

### 2. Targeted test loop

**Scope every nextest invocation to what you're actually testing — `--lib` or
`--test <stem>`, or `-p <crate>` at minimum. Never invoke nextest unscoped
against a package/workspace "just to be safe."**

This isn't a style preference — it's the single largest lever measured in this
epic:

| Invocation | Wall-clock (nextest discovery/compile) |
|---|---|
| `--workspace --no-run` (~60 targets) | 376-563s, plateaus ~380s even on repeated launches of the same unrebuilt binaries |
| `-p aa-cli --lib` (1 target) | **54s** |
| `-p aa-cli` unscoped (34 targets, AAASM-5910's original finding) | discovers all 34 before filtering, same class of cost as the workspace case |

The cost is real and per-binary (macOS Gatekeeper/codesign first-launch validation
on every freshly-linked test binary nextest discovers), not something nextest can
skip or parallelize away (AAASM-5995 confirmed no such flag exists) — the only
lever is inviting fewer targets into the discovery pass in the first place.

```
cargo nextest run -p aa-gateway budget::types::tests::provider_variants_are_distinct
cargo nextest run -p aa-core --lib
cargo nextest run -p aa-cli --test cli_topology_test
```

### 3. Multi-agent / multi-worktree development

**Shared `CARGO_TARGET_DIR` across worktrees (already the machine-level default via
`~/.cargo/config.toml`), plus `scripts/rust-target-lifecycle.sh` for attribution
and reclamation. Do not switch to per-worktree isolated targets without re-reading
AAASM-5909/5910's evidence first — it trades one incident class for another.**

- The shared target-dir serializes concurrent debug builds against each other
  (Cargo's own `debug/.cargo-lock` is one exclusive lock for the whole debug tree,
  confirmed via `lsof`, AAASM-5910) — a real cost, but a self-limiting one (builds
  queue and finish).
- Full per-worktree isolation removes that lock contention but, without bounded
  reclamation, converts it into disk exhaustion — this machine hit 229 MiB free /
  100% capacity on 2026-08-26 running exactly that configuration (AAASM-5909 field
  evidence).
- `scripts/rust-target-lifecycle.sh status --root <parent-dir>` reports every
  worktree's effective target-dir, size, and orphan/candidate/active
  classification — run it before assuming disk pressure is a mystery.
- `scripts/rust-target-lifecycle.sh reclaim-one --worktree <path> --yes` is the
  safe reclamation primitive, ownership-scoped to exactly one worktree (never
  sweeps a shared root) — wire it into whatever step removes a worktree after a
  ticket closes (`post-merge-close`):
  ```
  git worktree remove <path>
  bash scripts/rust-target-lifecycle.sh reclaim-one --worktree <path> --yes
  ```
  It refuses (not an error, exit 0) rather than guesses on: an active worktree, a
  target-dir with a live process reference, the global shared target-dir itself,
  or anything it can't prove Cargo actually created (`CACHEDIR.TAG`). See
  `scripts/tests/rust-target-lifecycle-negative-control.sh` for the full safety
  contract, including the deletion-safety hardening (relative-path rejection,
  section-aware config parsing, canonicalization, TOCTOU mitigation) an
  independent adversarial review required before this shipped.
- **Heavy-lane concurrency**: no new empirical lane-count recommendation from this
  epic (report §6 — a 2/4/8-lane sweep was deliberately not re-run; the
  contention mechanism is architecture-level, not code-version-dependent, and
  re-measuring it would mostly re-derive AAASM-5910's own findings). Default to
  **at most 2 uncontrolled heavy Cargo lanes** running concurrently until real
  per-lane disk-quota data from `rust-target-lifecycle.sh status` usage
  justifies a different number.
- **sccache is CONDITIONAL, not for this profile either** — see § sccache below.

### 4. Full local QA verification

**Full-workspace build + full nextest run is the correct tool here — this is
exactly the situation the fast-edit/targeted-test profiles are *not* for.**

Expect the discovery-overhead cost described above; it is not a bug to route
around in this profile, it's the actual cost of full verification. If it becomes
a bottleneck, the fix is AAASM-5995's unimplemented follow-up (extending targeted
scoping to more of the *default* invocation surface, not skipping full QA).

### 5. Release / dist build

**Unchanged by this epic — out of scope by design.** `release`/`dist` profile
tuning (AAASM-2551, already merged) is a correctness/size boundary, not a
dev-speed lever; this epic's own instructions explicitly excluded touching it.

## sccache: CONDITIONAL

**Adopt for CI jobs that already pin `CARGO_INCREMENTAL=0` (AAASM-5994, merged).
Do not enable for any local dev profile.**

Measured (report §5, 3 reps each + no-sccache control + correctness check):

- Under `CARGO_INCREMENTAL=0` (CI's actual regime): **~25% median wall-clock
  reduction** on a clean rebuild, 100%+ cache-hit rate on repeat builds of an
  already-seen crate graph.
- Under default incremental (the local edit loop): **zero effect** — 0 sccache
  compile requests on a warm single-file rebuild. Cargo's incremental cache
  satisfies the request before `rustc`/sccache is ever invoked. The two are
  mutually exclusive configurations for a given profile, not additive.

CI wiring (`build`, `commit-range-build`, `clippy` jobs) uses
`mozilla-actions/sccache-action` with `SCCACHE_GHA_ENABLED=true`, so its cache
doesn't collide with `Swatinem/rust-cache`'s own key. `test`/`coverage` and the
rest of the `CARGO_INCREMENTAL=0` jobs are an explicit, not-yet-done follow-up —
see AAASM-5994's PR description for why they were deliberately excluded from the
first rollout (disk-constrained already; deserve their own look).

## Linker: no action needed on macOS, mold already active in CI on Linux

- **macOS**: Apple's own default linker (shipped since Xcode 15, superseding
  `ld_prime`/`ld_classic`) already is the fast option, at zero config. `lld`
  does not properly support macOS targets per current upstream Rust — do not
  reintroduce an `lld` suggestion for macOS (AAASM-5996 removed a stale one).
  `zld` is unmaintained; don't reach for it either.
- **Linux CI**: mold already wired in (`ci.yml`, AAASM-2581), local opt-in via
  `.cargo/config.toml`'s commented-out Linux block.
- **Cranelift, Wild linker**: evaluated and rejected for now (report §3) —
  Cranelift is nightly-only and forces `panic=abort` on macOS with no
  stabilization timeline; Wild is Linux-only with no incremental linking yet.
  Revisit if the ecosystem state changes; don't assume this classification is
  permanent.

## Progress-aware stall detection

A long-running Cargo/nextest command that appears stalled is not necessarily
hung. Before concluding a stall:

1. Check for live child processes: `ps -ef | grep -E "cargo|rustc|nextest"`.
2. If nextest discovery is running, `ps -ef | grep "/target/debug/deps/"` —
   dozens of freshly-linked test binaries in low-CPU sleep (`STAT SN`, near-0%
   CPU) is the expected shape of the dyld/Gatekeeper discovery cost described
   above, not a hang (report §4.1). It resolves on its own; killing it just
   means paying the cost again on retry.
3. If genuinely no process activity and no target-artifact mtime changes for an
   extended period, that's a real stall — investigate (lock contention via
   `lsof` on `debug/.cargo-lock`, disk exhaustion via `df`) rather than waiting
   indefinitely.

## Disk-pressure handling

- Check `/System/Volumes/Data` (not `/`, which reports the sealed system volume
  at ~5% forever and would show nothing during real pressure).
- `scripts/rust-target-lifecycle.sh status --root <parent> --max-total-gib N`
  exits non-zero when reclaimable-eligible size exceeds budget — treat as an
  alarm signal, not routine output.
- Reclaim via `reclaim-one` (single ownership-scoped worktree) or `reclaim`
  (broad `--root` sweep, dry-run by default, `--yes` to act) — never a bare
  `cargo clean` against ambiguous shared target state.
- `du` under-reports actual reclaimable space vs. `cargo clean`'s own accounting
  on very large trees (~25% observed on the largest lane in the 2026-08-26
  incident) — treat `status`'s size column as a floor, not an exact figure.

## Existing OSS reused (not reinvented)

Cargo native profiles/config, cargo-nextest, sccache (`mozilla-actions/sccache-action`
in CI), Swatinem/rust-cache, mold (Linux CI). `cargo-wizard`'s template logic was
reviewed as a pattern reference, not adopted as a dependency. `cargo-sweep` was
reviewed as a possible component for `rust-target-lifecycle.sh`'s TTL-based leaf
policy — not a substitute for its ownership-scoped safety gates. `cargo-accelerate`
does not exist as a real tool (confirmed, not assumed).

## GitHub repository decision: NO_NEW_REPO

Every concrete lever from this epic is either a native Cargo profile/config
setting already in this repo's own `Cargo.toml`/`.cargo/config.toml`, a
documented convention, or a conditional CI wrapper around an existing,
actively-maintained upstream tool. `rust-target-lifecycle.sh` is the one piece
with real implementation surface, and it's repo/machine-scoped (this
developer's worktree layout convention) rather than a generically portable
tool with demonstrated cross-repo reuse — AAASM-5991's own repo-decision
framework requires that before considering a shared or standalone repo. Full
reasoning: report §8.

## CI job baseline measurement (AAASM-6003)

Sibling of AAASM-6002 Phase 1: a real-evidence baseline for the `Build`, `Clippy lint`,
`Test`, and `Every commit in the range builds` (`commit-range-build`) CI jobs on
canonical `main`, before any tuning (Phases 2-4). Unlike the rest of this document,
**this section is primary evidence** — pulled directly from existing completed
GitHub Actions runs and their logs/API, not summarized from `report.md`. No new CI
run was triggered to produce it.

### Finding: the Swatinem/rust-cache restore misses on every sampled job — and the mechanism is known

Across every job (`Build`, `Clippy lint`, `Test`, `commit-range-build`) in every one
of the 5 runs sampled below, the `Swatinem/rust-cache` restore step logged `No cache
found.` and took under 1s (a miss lookup, not a real restore). This is not "the
cache is broken" — it's structural, and confirmed against the live GitHub Actions
cache list (`gh api repos/ai-agent-assembly/agent-assembly/actions/caches`,
2026-08-28):

- GitHub Actions scopes a cache to the branch that saved it, plus that branch's
  descendants; a cache saved on `main` is visible to every branch, but a cache saved
  on a feature branch is visible only to that branch.
- `Build`/`Clippy lint`/`Test` are gated by `needs.changes.outputs.rust == 'true'`
  (`.github/workflows/ci.yml:657,801,867`) and are skipped whenever a push doesn't
  touch a `rust`-filtered path. In the current run history, recent pushes to `main`
  did not touch Rust paths, so these three jobs have not run — and therefore not
  saved a cache — on `main` at all recently.
- The live cache list confirms this directly: querying for `v0-rust-build-*`,
  `v0-rust-test-*`, `v0-rust-clippy-*` keys returns **zero `refs/heads/main`
  entries** (all entries are `refs/pull/*/merge`). With no `main`-scoped cache to
  inherit, every feature-branch job is cold by construction, regardless of how
  recently a near-identical branch ran.
- `commit-range-build` has no `rust`-gate (deliberately, per the `AAASM-5675` comment
  in `ci.yml:717-723`) so it always runs, but its own cache key still requires a
  prior save on the exact branch/environment-hash combination, which a fresh
  worktree branch never has.

This is worth flagging as a real Phase 2+ candidate — restore is currently pure
overhead (a fast no-op) rather than the time-saving mechanism it's configured to be
— but no fix is proposed here; that's out of scope for a measurement-only ticket.

### Wall-clock and cache timings — 4 runs, pre-sccache (before AAASM-5994/PR #2262 merged)

All four are `main`-targeted PR branches that touched `.rs` files, sampled because
recent `main`-push runs skip these jobs entirely (no Rust changes in that diff).
Every "restore" row below is the "No cache found" miss described above; every "save"
row is the `Swatinem/rust-cache` Post-step upload, which is fast (GHA cache write
throughput, not compute) and not itself a bottleneck.

| Job | Run / job link | Wall time | Cache restore | Cache save (bytes, time) | Rust-compile+link (inferred) |
|---|---|---|---|---|---|
| Build | [33102805691](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33102805691/job/98626190717) | 10m1s | miss, <1s | 730,384,895 B (~697 MiB), ~2s | "Build workspace" step: 9m28s |
| Build | [33097734107](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33097734107/job/98612956967) | 10m4s | miss, <1s | 730,442,846 B, ~2s | 9m36s |
| Build | [33089465405](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33089465405/job/98606629549) | 12m49s | miss, <1s | 730,371,062 B, ~2m3s (slow tail — throughput dropped to single-digit MB/s partway through, vs. the other three runs' 200-300 MB/s) | 10m15s |
| Build | [33082085442](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33082085442/job/98602123721) | 10m23s | miss, <1s | 730,384,895 B, ~2s | 9m43s |
| Clippy lint | [33102805691](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33102805691/job/98626190677) | 8m29s | miss, <1s | not captured (log not pulled for this run) | "Run Clippy" 7m6s + feature-gate variant 44s |
| Clippy lint | [33097734107](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33097734107/job/98612956788) | 8m11s | miss, <1s | not captured | 7m0s + 43s |
| Clippy lint | [33089465405](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33089465405/job/98606629474) | 7m19s | miss, <1s | not captured | 6m6s + 38s |
| Clippy lint | [33082085442](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33082085442/job/98602123732) | 8m29s | miss, <1s | not captured | 7m13s + 44s |
| Test | [33102805691](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33102805691/job/98626190688) | 40m13s | miss, <1s | two caches: ~93.7 MB (Node.js native binding) + ~1.56 GB (main) | "Run tests" (nextest) 21m24s + "Run aa-gateway doctests" 2m40s; ~15m of the wall time is pre-test setup (disk cleanup, pre-building `aasm`/`aa-api-server` binaries the tests spawn) |
| Test | [33097734107](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33097734107/job/98612956780) | 34m25s | miss, <1s | same two-cache pattern | 17m47s + 1m59s |
| Test | [33089465405](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33089465405/job/98606629641) | 40m12s | miss, <1s | same | 21m31s + 2m41s |
| Test | [33082085442](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33082085442/job/98602123829) | 41m58s | miss, <1s | same | 22m52s + 2m46s |
| commit-range-build | [33102805691](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33102805691/job/98624749452) | 4m46s | miss, <1s | not captured | "Build every commit the merge introduces" 4m17s |
| commit-range-build | [33097734107](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33097734107/job/98610439240) | 12m26s | miss, <1s | not captured | 11m46s |
| commit-range-build | [33089465405](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33089465405/job/98578052817) | 11m15s | miss, <1s | not captured | 8m44s |
| commit-range-build | [33082085442](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33082085442/job/98558386277) | 11m40s | miss, <1s | 538,628,667 B, ~1s | 11m12s |

Summary ranges (n=4 each): **Build** 10m1s-12m49s; **Clippy lint** 7m19s-8m29s;
**Test** 34m25s-41m58s; **commit-range-build** 4m46s-12m26s (this job's wall time is
driven by how many commits are in the merge range, not a fixed workload — the
4m46s run had a short range; treat the spread as expected, not noise).

### sccache stats (n=1 — cold cache-namespace, pre-merge PR run — not a steady-state measurement)

The only sccache-instrumented run available in history is
[33075630033](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33075630033),
AAASM-5994/PR #2262's *own* CI run — i.e., the run that first turned sccache on, before
that config merged to `main`. Its `Swatinem/rust-cache` restore also missed ("No cache
found"), so these numbers reflect a cold GHA sccache namespace with zero cross-run
warm-up, not the tool's steady-state hit rate. **Per the AC, a warm-cache sccache hit
rate is not rerun — unavailable, needs a Phase 2/3 experiment run** once sccache has
had multiple runs to accumulate a warm object cache.

`sccache --show-stats` is emitted automatically by the `mozilla-actions/sccache-action`
Post-step (not an explicit workflow step) at the end of `Build`, `Clippy lint`, and
`commit-range-build` — the three jobs AAASM-5994 wired `RUSTC_WRAPPER=sccache` into.
`Test` has no `RUSTC_WRAPPER` set (`ci.yml:867-` carries no sccache block) — that is
by design (out of scope for AAASM-5994's first pass, per this doc's own Open
follow-ups below), not a measurement gap.

| Job | Run/job link | Wall time | Compile requests (executed) | Cache hits / misses | Cache hit rate | Cache write errors / writes |
|---|---|---|---|---|---|---|
| Build | [job 98702123359](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33075630033/job/98702123359) | 10m39s | 1263 (1084) | 33 / 1047 | 3.06% | 139 / 908 (~15.3%) |
| Clippy lint | [job 98702123228](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33075630033/job/98702123228) | 8m40s | 2036 (1340) | 494 / 842 | 36.98% | 110 / 732 (~15.0%) |
| commit-range-build | [job 98702150288](https://github.com/ai-agent-assembly/agent-assembly/actions/runs/33075630033/job/98702150288) | 10m27s | 1922 (1300) | 4 / 1292 | 0.31% | 37 / 1255 (~2.9%) |

Two things not in the table above, because they'd be misread as wall-clock if placed
next to the "Wall time" column: `sccache --show-stats` also reports
`cache_write_duration` and `compiler_write_duration` (Build: 149s / 1315s; Clippy:
359s / 489s; commit-range-build: 578s / 776s) — these are **cumulative across
parallel compilation processes**, not wall-clock, and routinely exceed the job's
actual wall time by design. They are not directly comparable to any column above.

The **cache write error rate (~15% on Build/Clippy, ~3% on commit-range-build)** is a
real, cited number independent of the cold-cache caveat and is worth carrying forward
as a Phase 2+ input even though this ticket doesn't diagnose its cause.

`Test`'s own cache save in this same run (job not sccache-instrumented, so no
`--show-stats` output) followed the same two-cache pattern as the pre-sccache Test
runs above — not re-tabulated since it adds no new information over the n=4 Test
rows.

### What is not directly measurable from existing logs

- **Per-phase (restore/compile/link/save) breakdown within "Build workspace" /
  "Run Clippy" / "Run tests" / "Build every commit the merge introduces"** — these
  are single opaque `cargo`/`cargo nextest` invocations in the workflow; the logs
  don't emit a restore-vs-compile-vs-link split inside that one step. `cargo build
  --timings` HTML output (referenced in this doc's Open follow-ups below) would give
  this, but isn't currently collected in CI.
- **Warm-cache sccache hit rate** (steady-state, after the object cache has
  accumulated more than one run's worth of history) — not rerun; needs a Phase 2/3
  experiment run per the AC's explicit allowance for this case.
- **sccache stats for `Test`/`commit-range-build` as they exist today** — `Test` has
  no sccache instrumentation by design (noted above); `commit-range-build` *is*
  instrumented (table above) so this gap applies to `Test` only.

## Test-job sccache experiment — REJECTED (AAASM-6004)

AAASM-5994 deliberately excluded `test` from its initial sccache rollout,
pending dedicated measurement. AAASM-6004 ran that measurement: a controlled
two-run A/B on branch `v0.0.1/AAASM-6004/config/test_sccache_ab_experiment`
(PR #2281, closed without merging).

| Run | Cache state | Wall time | Compile reqs | Cache hits | Overall hit rate | Rust hit rate |
|---|---|---|---|---|---|---|
| 1 | cold | 39m22s | 2719 | 763 | 37.83% | 22.69% |
| 2 | warm | 35m43s | 2719 | 967 | 47.94% | 35.87% |

Baseline control (AAASM-6003, no sccache, n=4): **34m25s–41m58s**.

**Verdict: rejected.** Both experiment-arm wall times fall inside the
existing no-sccache baseline range — the warm run's 35m43s is not below what
un-cached runs already achieve at their fast end (34m25s). A real and
growing Rust cache-hit rate (22.69%→35.87%) did not translate into a
wall-time reduction beyond the baseline's own run-to-run variance, per this
doc's decision rule (total wall time is the primary metric, not hit-rate
alone). Unlike Build/Clippy (AAASM-5994, adopted), Test's dominant cost
includes non-rustc-cacheable work — nextest binary linking/archiving,
dashboard/node build steps, DB-backed integration tests — that sccache
cannot touch, so real object-cache reuse doesn't move the job's total time.

Do not re-attempt sccache on `test` without new evidence that changes this
ratio (e.g. a materially different Test-job shape, or workspace-wide
compile-time growth that shifts more of the job into cacheable rustc work).

## Coverage sccache experiment — REJECTED (AAASM-6006)

AAASM-5994 deliberately excluded `coverage` from its initial sccache
rollout — `llvm-cov` compiles with different rustflags/codegen than the
plain-compile jobs, so its object cache must never share a namespace with
`build`/`clippy`/`commit-range-build`/`test`. AAASM-6006 gave it a
genuinely isolated `SCCACHE_GHA_VERSION=coverage-llvmcov-v1` namespace and
ran a controlled two-run A/B (cold/warm, same methodology as AAASM-6004/6005):

| Run | Wall time | Overall hit rate | Rust hit rate | Cache write errors | rust-cache restore |
|---|---|---|---|---|---|
| cold | 54m22s | 16.91% | 19.62% | 126 | No cache found (expected, 1st push) |
| warm | **56m06s** | 9.47% | **10.91%** | **188** | Cache hit, full match (registry/git only) |

**Verdict: rejected.** Unlike every other job in this campaign, Coverage's
warm run is not faster — it's slightly slower — and the sccache Rust hit
rate *dropped* cold→warm (19.62%→10.91%) instead of climbing, with cache
write errors growing (126→188). The isolated namespace worked correctly
(no cross-contamination with the other jobs' caches), but the sccache
object cache itself doesn't provide durable cross-run benefit here, likely
because `llvm-cov`'s per-build coverage-instrumentation flags fragment the
effective hit population differently than plain compiles do. Both runs
completed successfully with no indication of a correctness regression
(same compile-request count in both, upload steps succeeded in both).

Do not re-attempt sccache on `coverage` without new evidence — e.g. a
different sccache version, a different llvm-cov invocation shape, or GHA
cache-write reliability improving generally.

## rust-cache + sccache overlap on Build — ADOPT verdict recorded, merge pending (AAASM-6005)

AAASM-6005 measured `Swatinem/rust-cache`'s `cache-targets: false` +
sccache on `build` and found a clear win (config B warm run 4m14s vs.
config A's 9m58s — see PR #2284 for the full evidence once merged). The
code change is implemented and reviewed but **not yet merged**: canonical
`main`'s required `CI Success` check is independently red due to
AAASM-6009 (an unrelated `.ci/isolation-lane-scenarios.txt` drift that
fails whenever a PR actually runs Rust-path jobs). Never bypass a real
required-check failure via the admin-merge exception — waiting for
AAASM-6009 to clear before merging PR #2284. This section will be replaced
with the full evidence table once that lands.

## Open follow-ups (not yet implemented)

- **AAASM-5995's own recommendation**, unimplemented: extend targeted nextest
  scoping to more of the *default* invocation surface (not just incident
  response) — needs its own measurement before scoping as a real ticket.
- **AAASM-6009** (High, filed): `Isolation backend confinement (Linux)`
  fails the required `CI Success` check due to a scenario-coverage-drift
  bug, unrelated to this campaign but currently blocking PR #2284's merge
  (AAASM-6005's adopted Build cache-config change). Not this campaign's
  scope to fix.
- **Extend `cache-targets: false` to `clippy`/`commit-range-build`**: AAASM-6005
  measured this only on `build`; the same target-cache-save-unreliability
  mechanism likely applies to the other sccache-enabled jobs but needs its
  own measurement before changing them.
- **A hard-enforced disk quota** (AAASM-5981 AC2): `rust-target-lifecycle.sh
  status --max-total-gib` currently only *signals* (non-zero exit) when a
  budget is exceeded — it does not evict anything to enforce it, since doing
  so would mean touching non-orphaned (active) worktrees, which this tool
  deliberately never does. Needs its own design decision if a harder
  enforcement mechanism is wanted.
- **`docs/bench-5992/build-baseline.sh` harness gap**: its `--timings` HTML
  archival silently no-ops when `CARGO_TARGET_DIR` is overridden (hardcoded
  `target/cargo-timings/` glob) — cosmetic, not filed as a ticket.
- **Affected-test selection for PR CI** (AAASM-6007 spike, unimplemented):
  changed-crate → dependency-closure → required-test selection is the
  largest remaining wall-clock lever, but it changes required-gate
  semantics rather than just build caching, so it needed its own
  viability/risk spike before any implementation ticket. See
  [`docs/bench-5992/affected-test-selection-spike.md`](affected-test-selection-spike.md)
  for the dependency-graph shape, the false-green risk catalog, and the
  falsification-test plan a future ticket would need to clear.
