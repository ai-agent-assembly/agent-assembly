<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/shell-development/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — shell-development

## Purpose

Safe, portable, low-noise Bash/sh automation. Company-common per
`governance/engineering/agent-skill-architecture.md` (HORO-969) §1 — it
owns shell scripting technique and the process/filesystem safety
non-negotiables; it does not own any other language's build/test tooling.

## Type

Auto-used, no `manifest.yaml` — deliberately, matching the five original
company-process skills (`governance-doctor`, `jira-delivery`,
`public-release-reconcile`, `release-assurance`, `repo-bootstrap`).
`agents/common/project_skills.py`'s `resolve_applicable_skills()` treats a
skill with no manifest as always applicable, which is correct here: every
repo has shell scripts somewhere (CI glue, dev scripts, hooks), so there is
no single stack-evidence file that could gate this the way `Cargo.toml`
gates `rust-development`.

## When to use

Writing, editing, or debugging any Bash or POSIX `sh` script or inline
shell snippet — CI steps, dev/build scripts, git hooks, wrapper commands
around a noisy tool.

## When NOT to use

- As a substitute for a language skill's own build/test commands invoked
  *from* a shell script — the script glue is this skill's concern, the
  underlying `cargo`/`pytest`/etc. invocation is the relevant
  `*-development` skill's.
- For non-shell scripting languages (Python, Node) even when they replace
  a shell script — use the matching language skill instead.

## Composes with `engineering-loop`

Use `engineering-loop`'s Explore → Narrow → Validate → Escalate → Full Gate
loop for iterating on a script. `references/safe-shell-patterns.md`'s
guidance on avoiding blind `tail -N` truncation is a shell-specific
instance of `engineering-loop`'s L0–L3 diagnostic contract
(`agents/skills/engineering-loop/references/diagnostic-contract.md` rule
4): a wrapper that truncates a failing pipeline's output can hide the
actual error the same way a naive test summarizer can.

## Non-negotiables (see `references/process-and-filesystem-safety.md`)

These mirror `governance/engineering/security.md`'s non-waivable
invariants and must never be relaxed by a script, wrapper, or one-off
command:

- **Never** use raw `env`, `printenv`, `set` (no args), `export -p`, or
  `cat .env*` for credential discovery — these dump every variable in
  scope, secret or not, straight into command output.
- **Never** run `set -x` (or `bash -x`) around a command that constructs
  or passes a credential — xtrace echoes literal argv, including secret
  values, to stderr.
- **Never** put a secret value in argv or debug output when a safer
  channel (stdin, a file descriptor, an env var passed by reference) is
  available — argv is visible via `ps` and shell history.
- **Never** use `pkill <generic-name>` or `killall <generic-name>` —
  identify the exact PID and confirm its owning process/worktree/session
  before terminating anything.
- **Never** recursively delete an ambiguous or unowned directory — confirm
  the target's contents match what the script expects before `rm -rf`.

## Routing decision

1. Detect target interpreter (Bash-only features vs. POSIX `sh`) — see
   `references/safe-shell-patterns.md`'s shell-detection section — before
   writing anything, since the two have materially different safe-quoting
   and array semantics.
2. Apply quoting/array/pipeline-exit-status patterns from
   `references/safe-shell-patterns.md`.
3. Before deleting, killing, or reading credentials, check
   `references/process-and-filesystem-safety.md`'s prohibited-pattern list
   and its "what to do instead" for the safe replacement.
4. Run ShellCheck/shfmt (see `references/safe-shell-patterns.md`) as the
   Narrow-stage check before considering a script done.

## Worked example

- `examples/safe-wrapper-with-preserved-exit-code.md` — wrapping a noisy
  command for compact output without losing `$?` through a pipeline.
