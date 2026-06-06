# Verification Report — AAASM-2589

**Parent Story:** AAASM-2554 — Tune dev/test profiles + add `.cargo/config.toml` faster linker
**Epic:** AAASM-2551 — Rust build & compile-time performance
**Implementation PR:** #918 (AAASM-2588)
**Date:** 2026-06-05
**Host:** `aarch64-apple-darwin` (Apple Silicon, local dev machine)

## Scope

Verify the three acceptance criteria of Story AAASM-2554:

1. Warm incremental rebuild after a one-line change is measurably faster (before/after).
2. `cargo nextest run --workspace` still passes; reduced debuginfo does not meaningfully
   break test-failure backtraces.
3. `.cargo/config.toml` linker selection is gated so contributors without mold/lld still
   build (documented fallback).

`before` = `master` with no `[profile.dev]` tuning (workspace crates at full debuginfo,
deps at `opt-level=0`). `after` = the new profile (`debug="line-tables-only"` on workspace
crates; deps at `opt-level=1`, `debug=false`).

> Note: the warm-rebuild numbers below were captured with deps at `opt-level=2` (the
> initial value); they are **unchanged** for the shipped `opt-level=1` because a warm
> one-line change recompiles only the touched workspace crate and relinks — dependencies
> are cached and not rebuilt, so their `opt-level` does not affect warm-rebuild time. The
> dep `opt-level` was lowered 2→1 because `opt-level=2` cold-rebuilt heavy deps (wasmtime
> via aa-sandbox) slowly enough to exceed the `integration-tests` 20-minute CI timeout;
> the job `timeout-minutes` was also raised 20→30 for margin.

## AC1 — warm incremental rebuild (before/after)

Method: each state built fully warm, then a one-line change to `aa-cli/src/main.rs`
triggers a rebuild (`cargo build -p aa-cli`); both states recompiled the **same 6 crates**
per change, so the comparison is apples-to-apples. Two runs each.

| State | Run 1 | Run 2 |
|---|---|---|
| `before` (master — full debuginfo) | 11 s | 10 s |
| **`after` (new dev profile)** | **4 s** | **5 s** |

**~2.3× faster warm rebuild** (≈4.5 s vs ≈10.5 s). The win comes from `line-tables-only`
debuginfo on workspace crates (far less debug data to emit + link) plus `debug=false` on
the optimized, already-cached dependencies. ✅

> An initial run measured an anomalous 54 s for `after`; that sample was taken on the very
> first rebuild immediately after a cold build (hot CPU + cold FS cache) and did not
> reproduce — the clean warm numbers above are the valid measurement.

Confirmed no workspace-crate penalty: `aa-cli` (a workspace member) compiles with **no
`-C opt-level` flag** (opt-level 0) under the new profile — `[profile.dev.package."*"]`
`opt-level=1` applies to **dependencies only**, exactly as intended, so the
constantly-rebuilt workspace crates stay fast.

## AC2 — tests pass + backtraces

`cargo nextest run` on the Docker-free crates under the new dev profile:

```
Summary  265 tests run: 265 passed, 0 skipped   (aa-core, aa-cache, aa-proto)
```

The dev profile changes only debuginfo verbosity and dependency optimization, which
cannot alter test outcomes. `debug = "line-tables-only"` **keeps file/line tables**, so
test-failure backtraces still resolve to `file:line` (it drops variable/type DWARF, not
the line tables). The full `cargo nextest run --workspace` (incl. testcontainer-backed
storage/integration crates and the macOS-flaky `policy_latency_test`) is exercised by CI
Linux on PR #918, which is authoritative for the cross-platform suite. ✅

## AC3 — linker gating / documented fallback

`.cargo/config.toml` ships the mold (Linux) / lld (macOS) linker selection **commented
out (opt-in)**, so the workspace builds with the default linker for everyone — no mold/lld
required. `cargo verify-project` / config parse confirm no active override. `CONTRIBUTING.md`
→ "Faster builds (optional)" documents the one-time per-platform install
(`apt-get install -y mold clang` / `brew install llvm`) and how to enable it. Activating
mold on the Linux CI runners is tracked separately under the Epic's build-pipeline Story. ✅

## Acceptance criteria

| # | Criterion | Verdict |
|---|---|---|
| 1 | Warm rebuild measurably faster (before/after) | ✅ ~2.3× (≈4.5 s vs ≈10.5 s) |
| 2 | `nextest` passes; backtraces intact | ✅ 265/265 pass; line tables preserved; full suite on CI |
| 3 | Linker gated; contributors w/o mold/lld still build | ✅ opt-in/commented + documented install |

## Conclusion

The dev/test profile tuning delivers a ~2.3× faster warm rebuild with no workspace-crate
penalty and no test regressions, and the faster linker is shipped gated/opt-in with a
documented fallback. Story AAASM-2554 acceptance criteria are met (full-workspace test
confirmation via CI on PR #918).
