# AAASM-3186 — Verification: SDK↔core git-SHA consistency guards

**Story:** AAASM-3181 (per ADR 0003) · **Date:** 2026-06-18 · **Verdict:** ✅ all pass — no bugs found

> Read-only / local verification (no Actions minutes). The per-SDK guard workflows trigger on `pull_request` filtered to `native/aa-ffi-*/Cargo.toml`, so they intentionally do **not** run on their own workflow-only PRs — the check logic is verified directly here against fixtures.

## Baseline (audit)

All three SDKs are intra-repo consistent **and** cross-repo identical:

| Repo | aa-* deps | rev |
|---|---|---|
| python-sdk | aa-core, aa-proto, aa-sdk-client | `4f9eea19…` |
| node-sdk | aa-sdk-client, aa-proto | `4f9eea19…` |
| go-sdk | aa-sdk-client, aa-proto | `4f9eea19…` |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Per-SDK guard **passes** on a consistent manifest | ✅ | Real `aa-ffi-python/Cargo.toml` → 1 distinct rev → exit 0 |
| Per-SDK guard **fails** on injected drift | ✅ | aa-proto line bumped to a different SHA → 2 distinct revs → exit 1 (annotated) |
| Cross-repo detector passes when consistent | ✅ | `.ci/check-sdk-sha-consistency.sh` → exit 0; report renders the table + "Lockstep holds" |
| Cross-repo detector flags drift | ✅ (by construction) | same distinct-rev logic as the guard, proven above; opens/updates the `sdk-sha-drift` issue on non-zero |
| Script portability / lint | ✅ | shellcheck `-S error` clean; bash-3.2 compatible (no associative arrays); smoke-run on macOS |

## Delivered

- Per-SDK guards: python-sdk #142 (AAASM-3182), node-sdk #155 (AAASM-3183), go-sdk #72 (AAASM-3184).
- Cross-repo nightly detector: agent-assembly #1103 (AAASM-3185) — `.ci/check-sdk-sha-consistency.sh` + `sdk-sha-drift.yml`.
- `agent-assembly-enterprise` excluded by design (independent cadence, ADR 0003).

No bug subtasks warranted.
