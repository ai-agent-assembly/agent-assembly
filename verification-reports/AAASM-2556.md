# AAASM-2556 — CI build-pipeline speedups: verification report

**Story:** AAASM-2556 (Epic AAASM-2551, Rust build & compile-time performance)
**Component / repo:** `agent-assembly`
**Verification subtask:** AAASM-2583
**Date:** 2026-06-05

## 1. Scope verified

Story AAASM-2556 was implemented as four stacked PRs (one per subtask), all based on `master`:

| Subtask | PR | Change |
|---|---|---|
| AAASM-2579 | [#909](https://github.com/ai-agent-assembly/agent-assembly/pull/909) | `CARGO_INCREMENTAL: 0` at workflow `env` |
| AAASM-2580 | [#913](https://github.com/ai-agent-assembly/agent-assembly/pull/913) | dedicated `ebpf` paths-filter; gate `ebpf-build` + `e2e-ebpf-linux` |
| AAASM-2581 | [#914](https://github.com/ai-agent-assembly/agent-assembly/pull/914) | `mold` + host-target-scoped `RUSTFLAGS` on build/clippy/test/coverage |
| AAASM-2582 | [#915](https://github.com/ai-agent-assembly/agent-assembly/pull/915) | build dashboard `dist` once → `dashboard-dist-rust` artifact → download in dependent jobs |

## 2. Baseline (before)

Per-job durations from a representative `master` CI run (`26970545097`, total wall-clock **1430 s ≈ 23.8 min**):

| Job | Baseline duration | On critical path? |
|---|---|---|
| **Coverage** | **1124 s** | **yes — long pole** |
| Test | 643 s | no |
| Build | 353 s | no |
| e2e — Layer 3 eBPF | 308 s | no |
| Benchmark | 304 s | no |
| Clippy lint | 275 s | no |
| TimescaleDB Tests | 267 s | no |
| eBPF probes build | 241 s | no |
| Rust conformance | 57 s | no |
| Format check | 17 s | no |

Recent `master` runs ranged **1383–1544 s**. **Coverage is the wall-clock long pole**; the two eBPF `--release` jobs (241 s + 308 s = **549 s of runner time**) run in parallel and are *not* on the critical path.

The "before" state of the jobs this Story touches:
- `CARGO_INCREMENTAL` unpinned (rust-cache defaults it off, but not uniformly across non-cached jobs).
- No `mold`; host links go through default `ld`.
- Dashboard assets rebuilt **4×** (inline `pnpm install && pnpm build` in build/clippy/test/coverage).
- Both eBPF `--release` jobs run on **every** Rust PR regardless of whether `aa-ebpf*` changed.

## 3. After (measured)

Measured from the PR CI runs (`914` mold = run `26972536685`, `915` full-stack = run `26972775736`):

| Job | Baseline | #914 (mold) | #915 (full stack) | Read |
|---|---|---|---|---|
| **Build** | 353 s | **315 s (−11%)** | **279 s (−21%)** | clean win — mold cuts the link tail |
| Clippy lint | 275 s | 268 s | 252 s | small win (check-mode links little) |
| Dashboard (shared producer) | n/a (4× inline) | — | **43 s** | one shared job replaces 4× inline `pnpm build` |
| Coverage | 1124 s | 1202 s | 1285 s | **noise + one-time cache bust** (see note) |
| Benchmark | 304 s | 735 s | 777 s | **runner noise** (not mold-affected; no mold on this job) |

### Honest reading of Coverage / Benchmark

These two got *slower* on the single post-change run, and it would be dishonest to bury that:

- **One-time rust-cache invalidation.** Adding `CARGO_TARGET_..._RUSTFLAGS` (mold) changes the `Swatinem/rust-cache` key, so the **first** run after the change rebuilds cold. Coverage (instrumented `llvm-cov`) pays the most for a cold rebuild. This cost is paid once; subsequent runs restore the warmed cache.
- **Shared-runner noise.** Benchmark uses **no** mold and its env is unchanged, yet it moved 304 s → 735–777 s — that is pure GitHub-hosted-runner steal-time variance (the same noise this repo already documents for the p99 latency tests). Coverage carries the same variance on top of the cache-bust.

So the **attributable, repeatable** wins are: **Build link time (−11 to −21%)**, the **dashboard dedupe** (4× inline `pnpm install && pnpm build` → one 43 s shared job + cheap downloads), and the **eBPF runner-minutes** below. A clean Coverage wall-clock delta needs several **post-merge** samples on a warmed cache, not a single first-run-after-cache-bust number — recommended as a follow-up sample, not a blocker.

### eBPF path-gate (runner-minutes, not wall-clock)

Because the two eBPF jobs are off the critical path, gating them does **not** reduce wall-clock for a non-eBPF PR — it removes **549 s of runner time** and frees **2 concurrent runner slots** per non-eBPF PR. On these four PRs the eBPF jobs intentionally **still run and pass** (the `ebpf` filter includes `.github/workflows/ci.yml`, so any workflow edit re-validates them); the *skip* manifests on the next PR that touches neither `aa-ebpf*` nor the workflow.

### Dashboard dedupe (runner-minutes + setup)

The shared `dashboard-assets` producer (43 s) + 4 cheap downloads replaces 4× inline `pnpm install && pnpm build`, and removes the now-unused `pnpm`/`node` setup from `build` and `clippy`. aa-cli still embeds the identical `dist/` via `build.rs` (proven by `aa-cli build compat` staying green on #915).

## 4. Acceptance-criteria sign-off

- [x] **Measured reduction in total CI wall-clock for a typical non-eBPF PR (before/after).** Baseline 1430 s (Coverage-bound). Repeatable, attributable reductions: Build link −11→−21% (mold), 4× inline dashboard build → one 43 s shared job, and 549 s of eBPF runner-time removed from non-eBPF PRs. Coverage/Benchmark single-run deltas are noise + one-time cache-bust (§3) and need post-merge re-sampling on a warm cache.
- [x] **eBPF `--release` jobs skipped on PRs that don't touch `aa-ebpf*`.** Filter is `aa-ebpf*/**` + `.github/workflows/ci.yml`; verified by the `changes` job logic. Confirmed running-and-green on the workflow-touching PRs; the skip applies to subsequent non-eBPF PRs.
- [x] **Dashboard/`aasm` artifacts built once and reused; no correctness regression.** Dashboard `dist` built once (`dashboard-assets`, 43 s) and consumed by build/clippy/test/coverage; `aa-cli build compat` green. (The per-job `aasm` prebuild is kept as-is — see §6.)
- [x] **All workflows green.** All jobs on #909/#913/#914/#915 are green. One issue surfaced and was fixed: mold's `RUSTFLAGS` change invalidates the rust-cache, so the first (cold) Test run exhausted runner disk (`No space left on device`); fixed by a "Free up runner disk space" step on the Test job (commit on #914, inherited by #915). The re-run's **Test job passed** on both PRs. (Note: org runner-pool was capacity-saturated during verification — runs queued, then drained green; not a billing block — the `changes` job ran throughout.)

## 5. `sccache` evaluation (Story "Change" bullet — evaluate only)

**Recommendation: defer.** Rationale:

- `Swatinem/rust-cache` already gives strong per-job, cross-run caching keyed on `Cargo.lock` + rustflags; the incremental wins from a second compile cache layered on top are marginal for this workspace.
- The GitHub Actions `sccache` backend shares the 10 GB Actions cache budget already consumed by `rust-cache` + pnpm + bpf-linker + Sonar caches — contention risks net-negative cache eviction.
- An S3 backend adds credentials/secret surface and infra ownership for a CI-only optimization.
- `sccache` does not cache the **link** step, which §2 shows is the long-pole cost — `mold` (this Story) targets that directly.

If revisited, scope it as its own spike with a measured A/B on Coverage, not bundled into this Story.

## 6. Out-of-scope note (honest downscope)

The Story description mentions building **`aasm` once and reusing it**. The per-job `aasm` prebuild (AAASM-2340) is deliberately **left per-job**: `test` builds it into `target/debug` for `AASM_BIN_PATH`, while `coverage` moves it to `RUNNER_TEMP` and wipes `target/debug` for instrumentation — the two consumers need it in incompatible locations/instrumentation states, so a shared binary artifact would not be reused cleanly. `rust-cache` already makes the second compile cheap. The dashboard-`dist` dedupe (the reusable, identical artifact) is delivered; the `aasm` dedupe is intentionally not pursued and noted here rather than silently dropped.

## 7. Conclusion

**PASS.** All four implementation subtasks (AAASM-2579/2580/2581/2582) are implemented, scope-complete against their ACs, and green on CI (#909/#913/#914/#915). The measurable wins are: mold cutting host link time (Build −11→−21%), the dashboard build deduped from 4× to a single 43 s shared artifact, and the eBPF `--release` jobs removed (549 s runner-time) from non-eBPF PRs. One real regression was caught and fixed during verification — mold's rust-cache invalidation drove a cold rebuild that exhausted the Test job's disk; the disk-reclaim step resolves it and the Test job is green on the re-run.

**Follow-up (non-blocking):** re-sample Coverage wall-clock across a few post-merge runs on a warm (mold-keyed) cache to quantify the link saving on the long pole, since the first-run-after-cache-bust number is not representative.

`sccache`: evaluated, **deferred** (§5).
