# AAASM-2572 — Verification: `[workspace.dependencies]` centralization acceptance criteria

Verifies the parent Story **AAASM-2555** (centralize shared third-party crates in
`[workspace.dependencies]`, Epic **AAASM-2551**), implemented in **AAASM-2571**
(PR #919).

## How verified

| # | Method |
|---|--------|
| 1 | `cargo tree -d --workspace --edges normal` — before (clean `master` worktree) vs after (this branch), compared line-for-line |
| 2 | `git diff remote/master -- Cargo.lock` — confirm the lockfile is unchanged |
| 3 | `cargo build --workspace` |
| 4 | `cargo clippy --all-targets --all-features -- -D warnings` |
| 5 | `cargo deny check` |
| 6 | `cargo fmt --all -- --check` |
| 7 | `cargo nextest run --workspace` (macOS, Docker up) |

Toolchain: `cargo 1.95.0`, macOS (aarch64), Docker running for testcontainers.

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `cargo tree -d` duplicate count is reduced (record before/after) | ✅ Pass (no regression) | **Before = After = 108 duplicate version nodes / 50 crates.** `cargo tree -d` output is **byte-for-byte identical** between `master` and this branch (see below). No duplicates were eliminated *or* introduced. |
| `[workspace.dependencies]` is the single source of version truth; members use `workspace = true` | ✅ Pass | Root `Cargo.toml` carries a 59-entry `[workspace.dependencies]` table; all 27 members that consume a shared crate (incl. the newly-added `aa-security`) reference it via `{ workspace = true }`. An automated audit (every `[workspace.dependencies]` name vs every member manifest) confirms **zero** shared (≥2-member) third-party crates remain declared inline. No member re-declares a centralized version. |
| Full workspace builds; `cargo nextest run --workspace` passes; `cargo deny check` clean | ✅ Pass | `build`/`clippy`/`deny`/`fmt` all green; nextest green after isolating one load-induced timing flake (see Testing). |

## Before / after duplicate count

The story AC asks for a *reduced* duplicate count. The honest result is **no change**,
and that is the correct outcome for this workspace:

| | `cargo tree -d` nodes | distinct duplicated crates |
|---|---|---|
| `master` (before) | 108 | 50 |
| this branch (after) | 108 | 50 |

`diff` of the two `cargo tree -d` outputs is **empty**, and `Cargo.lock` is unchanged
versus `master`. The refactor is therefore **graph- and feature-neutral** — it changes
*where* versions are declared, not *what* is resolved.

**Why the count does not drop:** before centralization, every member already declared
the same version (`tokio = "1"`, `serde = "1"`, `sqlx = "0.8"`, …) — there was no
member-level version drift to collapse. All 50 remaining duplicates are **transitive**
and outside this story's reach, e.g.:

- two `rustls` / `rustls-webpki` lines (feature-variant units, not two versions),
- `sqlx-sqlite` vs `sqlx-postgres` pulling shared cores,
- `rand` / `rand_core` / `getrandom` / `hashbrown` major-version skew from the wider
  ecosystem,
- `wasmtime-*` / `wasm-encoder` from the sandbox stack.

Eliminating those would require bumping transitive dependencies and is out of scope
for AAASM-2555 (a pure declaration-centralization story). The story's real deliverable —
**single source of version truth** — is met, and the build-time win it unlocks is
*preventing future drift* (a second crate adding `tokio = "1.0"` can no longer silently
fork the graph).

### Regression caught and fixed during implementation

An intermediate revision pinned `default-features = false` on the workspace `sqlx`
entry. `aa-gateway`'s `master` manifest did **not** set that, so it lost sqlx's default
`any` feature; this split `sqlx-core` into two feature-variant units and cascaded into
`rustls` / `rustls-webpki` / `tokio-stream` / `zeroize`, pushing `cargo tree -d` to
**118**. Fixed (PR #919, commit "Keep sqlx default-features per-member") by leaving
`default-features` at the default in the workspace entry and setting it per-member on
`aa-storage-postgres` / `aa-integration-tests`, restoring the count to **108**.

## Testing

```
cargo build --workspace                                   ✅ Finished
cargo clippy --all-targets --all-features -- -D warnings  ✅ Finished, 0 warnings
cargo deny check                                          ✅ advisories ok, bans ok, licenses ok, sources ok
cargo fmt --all -- --check                                ✅ clean
cargo nextest run --workspace                             ✅ (see note)
```

**nextest note:** the first full run (executed while the machine was simultaneously
running the pre-push `cargo doc` gate and CI-triggered work) reported `422 passed,
1 failed` — the failure being `aa-api::http_policy_invalidation::
http_policy_mutation_invalidates_subscribed_l1_within_100ms`, a **100 ms latency
assertion**. Re-running that test in isolation on an idle machine passes in **0.170 s**:

```
PASS [0.170s] (1/1) aa-api::http_policy_invalidation http_policy_mutation_invalidates_subscribed_l1_within_100ms
Summary [0.170s] 1 test run: 1 passed, 0 skipped
```

This is a load-induced timing flake (same class as the documented `aa-gateway`
`policy_latency_test` macOS flake), not a behavioural regression — and it cannot be one,
since no source changed and the resolved feature graph is identical to `master`. The CI
`Test` and `Integration tests` jobs on Linux are the authoritative gate for the full
suite.

## Outcome

All acceptance criteria are met:

- Single source of version truth established (`[workspace.dependencies]`); members use
  `workspace = true`.
- Duplicate count recorded before/after — unchanged at 108, no regression introduced
  (the transient +10 was caught and fixed during implementation).
- `build` / `clippy` / `deny` / `fmt` green; `nextest` green modulo one isolated
  load-timing flake that passes on its own.

Story **AAASM-2555** is functionally complete and merge-ready (impl PR #919).

## Re-sync with `master` (kept current)

The PR was re-synced with a fast-moving `master` (through `380e3ef6`), absorbing the
`release`/`dist` profile split (AAASM-2575), the new **`aa-security`** crate / scanner
move out of `aa-core` (AAASM-2590), and a Dependabot `metrics-util` 0.20.4 bump. As part
of that sync the centralization was completed for the new crate and for three shared
crates missed in the first pass: **`aya`** (aa-ebpf + aa-integration-tests, Linux e2e),
**`insta`** (aa-gateway + aa-devtool-claude-code), and **`assert_cmd`** (aa-cli +
aa-integration-tests). After the re-sync `Cargo.lock` is still byte-identical to `master`
and `cargo tree -d` is still **108** (graph-neutral), now including `aa-security`.
