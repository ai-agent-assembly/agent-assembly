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

## Open follow-ups (not yet implemented)

- **AAASM-5995's own recommendation**, unimplemented: extend targeted nextest
  scoping to more of the *default* invocation surface (not just incident
  response) — needs its own measurement before scoping as a real ticket.
- **sccache CI rollout to `test`/`coverage`**: deliberately excluded from
  AAASM-5994's first pass; disk-constrained jobs, deserve dedicated
  measurement before adding a second cache.
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
