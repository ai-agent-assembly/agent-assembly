# Example — targeted loop, then Full Gate

Scenario: fixing a bug in a Python service where `parse_retry_after()`
mishandles a `Retry-After` header given as an HTTP-date instead of an
integer seconds count.

## 1. Explore

```
$ codegraph explore "parse_retry_after"
```

Returns the function's source (`app/http/backoff.py:41-58`) and its two
callers (`app/http/client.py:112`, `tests/http/test_backoff.py:20`).
CodeGraph is available in this repo (`.codegraph/` exists), so this
replaces a grep + Read round trip.

## 2. Narrow

Write the missing test case, then run only that test file — not the full
suite — while iterating:

```
$ pytest tests/http/test_backoff.py -q
F                                                                    [100%]
FAILED tests/http/test_backoff.py::test_parse_retry_after_http_date
1 failed, 4 passed in 0.31s
```

This is L0: PASS/FAIL + counts. One failure, as expected — the test
exists specifically to prove the bug.

## 3. Validate / fix

Escalate briefly to L1 to confirm the failure is the one intended (not a
typo in the test):

```
tests/http/test_backoff.py:24: AssertionError: expected 120, got None
```

Confirmed — `parse_retry_after` returns `None` on an HTTP-date string.
Fix `backoff.py` to handle both formats, then re-run the same narrow
check:

```
$ pytest tests/http/test_backoff.py -q
.....                                                                [100%]
5 passed in 0.28s
```

L0 PASS is sufficient here — the fix targets exactly the case the new
test exercises, and the result matches expectation.

## 4. Full Gate

The narrow check proves the fix works; it does not prove nothing else
broke, and it is not the repo's authoritative release signal. Before
calling this done, run the full gate:

```
$ pytest -q
....................................................................  [100%]
312 passed in 41.2s
$ ruff check .
All checks passed!
$ mypy app/
Success: no issues found in 58 source files
```

Only after the full suite, linter, and type-checker all pass is the
change considered validated. If the targeted test had been the only check
run before opening a PR, a regression in an unrelated caller of
`parse_retry_after` (e.g. one relying on the old `None`-on-failure
behavior) would have shipped unnoticed.

## Why this ordering matters

Running the full suite on every single iteration during the fix would
have wasted ~40s per edit for no benefit while the fix was still being
worked out. Skipping the full suite entirely at the end would have traded
that saved time for a real risk of shipping a regression. The loop
front-loads the fast, targeted signal and reserves the expensive,
comprehensive signal for the point where it actually gates the decision to
call the work done — this is what "minimum waste under correctness"
means, not "cheapest single check that also happens to pass."
