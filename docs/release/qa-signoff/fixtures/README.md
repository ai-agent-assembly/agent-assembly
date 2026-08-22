# QA sign-off grep fixtures

Minimal fixtures proving the `Verdict: PASS` token is consumed
**deterministically** by `scripts/release-readiness.sh`'s QA check
(AAASM-5823) — the same `^Verdict:[[:space:]]*PASS[[:space:]]*$` pattern the
existing security-signoff check (readiness check 11) already uses. These are
not real releases; `release-readiness.sh` only ever looks at
`docs/release/qa-signoff/v<version>.md`, so these fixture files are inert for
any real readiness run.

| Fixture | Expected grep result |
|---|---|
| `pass.md` | matches `Verdict: PASS` — readiness QA check would pass |
| `block.md` | does not match PASS — readiness QA check would fail |
| `malformed.md` | does not match PASS (ambiguous/free-text verdict) — readiness QA check would fail |

AAASM-5823's negative-control tests point `release-readiness.sh` at a version
whose sign-off path resolves to each of these in turn (via a temp copy to
`docs/release/qa-signoff/v<fixture-version>.md`) to prove the QA check
genuinely goes red on BLOCK/malformed/missing and green only on exact PASS.
