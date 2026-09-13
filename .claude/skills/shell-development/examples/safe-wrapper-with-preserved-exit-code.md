# Example — a compact wrapper that preserves exit-code propagation

## Scenario

A CI step runs a noisy test command. We want a wrapper that tees the full
output to a log file (raw evidence stays recoverable — `engineering-loop`'s
L3) while printing a compact PASS/FAIL line (L0), without losing the
underlying command's real exit status.

## The trap: exit-code loss through a pipeline

```sh
#!/usr/bin/env bash
set -euo pipefail

run_noisy_tests | tee test-output.log | grep -q "PASS"
echo "exit status seen by the script: $?"
```

This looks reasonable but is broken. In a plain pipeline (`a | b | c`),
`$?` after the pipeline reflects only the **last** command's exit status —
here, `grep -q "PASS"`'s status, not `run_noisy_tests`'s. If
`run_noisy_tests` actually fails (non-zero exit, or crashes outright) but
its output happens to still contain the literal string `PASS` somewhere
(a partial run, a misleading log line, a test named `test_should_not_pass`),
`grep -q "PASS"` exits 0 and the pipeline reports success. `set -e` does
not save this either — the pipeline's *own* exit status (from `grep`) is
zero, so `-e` sees nothing to trigger on. The real failure is silently
swallowed.

## The fix: `set -o pipefail` + explicit status capture

```sh
#!/usr/bin/env bash
set -euo pipefail

log="test-output.log"
: > "$log"

# Run the real command, capture its own exit status separately from the
# pipeline's, and keep the full raw output on disk regardless of outcome.
if run_noisy_tests | tee "$log"; then
    real_status=0
else
    real_status="${PIPESTATUS[0]}"
fi

if [ "$real_status" -eq 0 ]; then
    echo "PASS (full output: $log)"
else
    echo "FAIL (exit $real_status) — see $log for full output" >&2
    exit "$real_status"
fi
```

What changed and why:

- **`set -o pipefail`** makes the pipeline's own exit status the last
  non-zero component rather than always the last command's — this alone
  would have fixed the original example if it had been the only pipeline
  stage that mattered. It's included here as the baseline even though the
  script also captures `PIPESTATUS[0]` explicitly, because a later edit to
  the pipeline (adding another stage) stays safe under `pipefail` without
  needing to re-derive which array index is "the real command."
- **`PIPESTATUS[0]`** (Bash-only — see `references/safe-shell-patterns.md`'s
  shell-detection section; POSIX `sh` has no equivalent array) captures
  `run_noisy_tests`'s own exit status directly, independent of what `tee`
  or a later `grep` would have reported — this is the ground-truth status
  per `engineering-loop`'s diagnostic contract rule 2 (exit status is
  always preserved and reported alongside any summary).
- **No `grep -q "PASS"` gate on the test command's own output.** Deciding
  pass/fail by scanning captured text for a string is fragile in exactly
  the way that bit the broken version — use the tool's actual exit code as
  the source of truth, and reserve text-scanning for building the L1/L2
  summary (which failure, where), never for the L0 PASS/FAIL verdict
  itself.
- **Full output stays on disk (`$log`) regardless of outcome** — this
  satisfies the "raw evidence is always recoverable" rule: the compact
  summary line is what's normally read, but dropping to L3 (the complete
  raw output) is a file read, not a re-run.
- **No blind `tail -N` on `$log`.** If a caller wants a short excerpt on
  failure, grep for the test framework's own failure markers rather than
  taking the last N lines — the same reasoning as
  `references/safe-shell-patterns.md`'s truncation section: the real error
  in `run_noisy_tests`'s output is not guaranteed to be near the end.

## POSIX `sh` note

`PIPESTATUS` and `pipefail` are both Bash/ksh/zsh extensions with no POSIX
`sh` equivalent. A `#!/bin/sh` script needing this guarantee must avoid the
pipe entirely — write the command's output to a file first, check its exit
status directly, and only then process the file:

```sh
#!/bin/sh
set -eu

log="test-output.log"
if run_noisy_tests > "$log" 2>&1; then
    echo "PASS (full output: $log)"
else
    status=$?
    echo "FAIL (exit $status) — see $log for full output" >&2
    exit "$status"
fi
```
