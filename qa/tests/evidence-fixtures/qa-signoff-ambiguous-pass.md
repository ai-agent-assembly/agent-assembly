# Synthetic QA sign-off fixture — v0.0.0-test-ambiguous-pass (AAASM-5898)

Test-only. Not a real release sign-off. J95's Result cell deliberately
contains a real status token (FAILS) alongside the unrelated substring
"PASS" in free-text prose, to prove the emitter resolves to the real
non-PASS status instead of being fooled by the substring.

## Selected journeys

| Journey ID | Priority | Result | Evidence |
|---|---|---|---|
| J95 | P1 | **FAILS** — the **PASS** criteria were not met | synthetic fixture evidence |

## Verdict

Verdict: BLOCK
