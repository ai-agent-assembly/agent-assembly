# Synthetic QA sign-off fixture — v0.0.0-test-header-reorder (AAASM-5898)

Test-only. Not a real release sign-off. Columns are deliberately reordered
(Result before Priority) to prove the emitter locates the Result column by
its header text, not by a hardcoded cell index.

## Selected journeys

| Journey ID | Result | Priority | Evidence |
|---|---|---|---|
| J96 | **BLOCKED** | P1 | synthetic fixture evidence — a hardcoded cells[2] reader would see "P1" here instead |

## Verdict

Verdict: BLOCK
