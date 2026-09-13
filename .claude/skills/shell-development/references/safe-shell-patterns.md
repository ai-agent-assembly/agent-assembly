# Reference — safe shell patterns

## Shell/interpreter detection

State the target interpreter explicitly before writing anything — Bash and
POSIX `sh` diverge in ways that fail silently rather than loudly:

- A script's shebang is the contract: `#!/usr/bin/env bash` commits to
  Bash-only features (arrays, `[[ ]]`, `local -n`, `${var,,}`,
  `mapfile`/`readarray`, process substitution `<(...)`). `#!/bin/sh` (or
  `#!/usr/bin/env sh`) commits to POSIX `sh` — none of the above are
  guaranteed, and on some systems `/bin/sh` is `dash`, which enforces this
  strictly rather than tolerating Bash-isms the way some `sh` builds do.
- Never mix the two: a `#!/bin/sh` script using `[[ ]]` or arrays works by
  accident on a machine where `sh` happens to be Bash, and breaks on one
  where it's `dash`. If Bash features are needed, say so in the shebang and
  require Bash explicitly, rather than hoping.
- CI runners and containers frequently default `sh` to `dash` or `busybox
  ash` even on a Debian/Ubuntu base with `bash` installed elsewhere — do
  not assume the interactive dev shell's behavior carries over.

## Quoting

- Double-quote every variable expansion and command substitution
  (`"$var"`, `"$(cmd)"`) unless intentionally relying on word-splitting —
  and if so, say why in a comment. Unquoted expansion is the single most
  common source of a script working on one input and breaking on the next
  (a path with a space, a glob character, an empty variable).
- Prefer `"$@"` over `$*` when forwarding all positional arguments — `"$@"`
  preserves argument boundaries, `$*` collapses them into one word.

## Arrays (Bash only)

- Use a real Bash array (`args=(--flag "$value")`) instead of a
  space-joined string when building a variable-length argument list —
  string-splitting a joined command line reintroduces the quoting bug
  above. Expand with `"${args[@]}"`, always quoted.
- POSIX `sh` has no arrays — build argument lists positionally (`set --`)
  or restructure the script to avoid needing one.

## Pipeline exit-status preservation

- `set -euo pipefail` at the top of a Bash script is the standard
  baseline: `-e` exits on an unhandled non-zero status, `-u` errors on an
  unset variable reference, `-o pipefail` makes a pipeline's exit status
  the last non-zero component instead of always the last command's.
  `pipefail` is Bash/zsh/ksh only — POSIX `sh` has no equivalent, so a
  `sh` script must check `${PIPESTATUS[@]}`-equivalent logic manually (it
  can't — `PIPESTATUS` is also Bash-only; restructure to avoid the pipe,
  or write intermediate results to a file and check each step's status
  directly).
- **Real limitations of `set -e` that surprise people:**
  - It does **not** catch a failing command substitution used inside an
    assignment: `result=$(false)` does not trigger `-e` — the assignment
    itself "succeeds" (it always exits 0 regardless of the substitution's
    exit code), silently absorbing the failure. Check `$?` explicitly
    after the assignment, or split into `cmd; result=$?` form, or use
    `result=$(false) || exit 1` right after.
  - It does not fire inside a condition (`if cmd; then`, `while cmd; do`,
    `cmd && x` / `cmd || x`) — that's by design (the failure is being
    tested, not left unhandled), but it means wrapping a real check in
    `if` silently opts out of `-e` for that one command, which is easy to
    forget when refactoring.
  - It does not propagate into a function called as part of a condition,
    and behavior around subshells/command substitutions historically
    varies by Bash version — when in doubt, check `$?` directly rather
    than trusting `-e` to catch everything.
  - It is disabled by default inside `$(...)` run in a context that
    ignores its result, and is not inherited into a subshell that
    explicitly unsets it.

## Temp-file cleanup (trap)

- Any script creating a temp file/directory must remove it on every exit
  path, including failure and signal interruption:
  `tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT` (or `trap '...' EXIT INT TERM`
  if signal-specific behavior matters). Register the trap immediately
  after creating the resource, not at the end of the script — an early
  failure before the trap is set leaks the file.
- Use `mktemp` (never a hardcoded `/tmp/foo` path) to avoid predictable
  temp-file races and collisions between concurrent runs.

## ShellCheck / shfmt

- Run `shellcheck` on every script before treating it as done — it catches
  the unquoted-expansion, unused-variable, and `set -e` gotcha classes
  above mechanically, faster than manual review. Treat a ShellCheck
  warning as something to fix or explicitly suppress with a reasoned
  inline `# shellcheck disable=SCxxxx` comment, never silently ignore.
- Run `shfmt` (or the project's configured formatter) for consistent
  indentation/quoting style so diffs stay reviewable.
- If neither tool is installed, that is the `engineering-loop` optional-
  tool fallback case (`agents/skills/engineering-loop/references/optional-tool-fallback.md`):
  fall back to careful manual review against this document's checklist —
  never skip the check because the accelerator is missing.

## Avoiding blind `tail -N` truncation

Piping a script's or CI step's output through `tail -N` to keep logs
compact is exactly the failure mode `engineering-loop`'s diagnostic
contract forbids
(`agents/skills/engineering-loop/references/diagnostic-contract.md` rule 4): the real error is frequently mid-log, under a long
successful setup phase, or above a misleading final "cleanup" line, and a
fixed-line-count tail can drop it entirely. Prefer:

- Capturing full output to a file (or CI's own log store) and reporting a
  short PASS/FAIL summary (L0) with the full capture always reachable (L3)
  — summarize by selection of what matters, not by discarding everything
  past a line count.
- Grepping for the actual failure markers (test framework's own FAIL/ERROR
  lines, non-zero exit reporting) to build the L1/L2 summary, rather than
  assuming the error is near the end.
