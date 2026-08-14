# AAASM-3190 — Verification: full-coverage SHA-consistency (enterprise + config-driven registry)

**Story:** AAASM-3187 (follow-up to AAASM-3181 / ADR 0003) · **Date:** 2026-06-18 · **Verdict:** ✅ all pass — no bugs found

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `.ci/core-consumers.json` is the single source of truth; detector reads it (no hard-coded list) | ✅ | PR #1105; confirmatory run loads 4 consumers from the registry and iterates them |
| Detector includes `agent-assembly-enterprise` (report-only; differing rev ≠ drift); lockstep only among the 3 SDKs; unreadable private repos skipped gracefully | ✅ | Run shows SDKs `4f9eea19…` / lockstep ✅ and enterprise `6ba36f3d…` / `ℹ️ independent`; verdict "Lockstep holds", exit 0 — the differing enterprise rev does **not** trip drift |
| `agent-assembly-enterprise` fails CI when its root `Cargo.toml` `aa-*` revs diverge | ✅ | PR #60 guard logic: real root `Cargo.toml` (8 deps on `6ba36f3d…`) → 1 rev → exit 0; `aa-proto` line doctored to a different SHA → 2 revs → exit 1 |
| Detector passes on the current baseline | ✅ | exit 0 (table above) |
| Lint / portability | ✅ | `jq` valid registry; `shellcheck -S error` clean; bash-3.2 portable |

## Confirmatory run (config-driven detector, PR #1105 branch)

```
| Repo | policy | rev | intra | status |
| python-sdk                | lockstep    | 4f9eea19… | ✅ | ✅ lockstep |
| node-sdk                  | lockstep    | 4f9eea19… | ✅ | ✅ lockstep |
| go-sdk                    | lockstep    | 4f9eea19… | ✅ | ✅ lockstep |
| agent-assembly-enterprise | independent | 6ba36f3d… | ✅ | ℹ️ independent |
✅ Lockstep holds — exit 0
```

## Operational note (not a defect)

In the **scheduled CI** run, the default `github.token` is scoped to `agent-assembly` and **cannot read the private `agent-assembly-enterprise` repo** — so without a `CROSS_REPO_TOKEN` secret the detector reports enterprise as `skipped (no access)` (still exit 0; gracefully degraded). Enterprise's own guard (PR #60) enforces its intra-consistency regardless of the detector. The above run read enterprise because the local token has org-wide `repo` scope. To have the central detector actively read enterprise, an org admin can add a read-only `CROSS_REPO_TOKEN` secret (the workflow already prefers it: `${{ secrets.CROSS_REPO_TOKEN || github.token }}`).

## Delivered

- Config-driven registry + refactored detector: agent-assembly **#1105** (AAASM-3188).
- Enterprise root-`Cargo.toml` guard: agent-assembly-enterprise **#60** (AAASM-3189).

No bug subtasks warranted.
