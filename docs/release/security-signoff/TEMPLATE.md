# Security sign-off — v<version>

> Per-release security-review sign-off artifact. Produced by the
> [`/security-review`](../../../.claude/skills/security-review/SKILL.md) SKILL
> and enforced by `scripts/release-readiness.sh` (the readiness run fails unless
> this file exists for `<version>` and contains `Verdict: PASS`).
>
> **Copy this file to `v<version>.md`** (e.g. `v0.0.1-beta.4.md`) and fill it in.
> This `TEMPLATE.md` is the template only — it is never the sign-off for a real
> release and is ignored by the readiness check.

- **Version:** v<version>
- **Release type:** patch | minor | major
- **Previous tag:** v<prev-version>
- **Reviewer:** <name>
- **Date:** <YYYY-MM-DD>

## Inputs reviewed

- `cargo deny check advisories` — <result>
- Open CodeQL alerts — <count / none>
- Open Dependabot alerts — <count / none>
- Release diff — `git log v<prev-version>..HEAD` (<N> commits)

## Findings

| Severity | Finding | Status (fixed / accepted-with-justification / open) |
|---|---|---|
| <Critical/High/Medium/Low/Info> | <description> | <status> |

> An **unaddressed Critical or High** finding forces `Verdict: BLOCK`.

## Trust-boundary review checklist (minor + major)

Paste the completed
[trust-boundary review checklist](../../src/security/trust-boundary-review-checklist.md)
table here. Row 2 ("wire-level trust marker") MUST stay **N** — a **Y** is an
automatic BLOCK.

| # | Trust boundary | Changed? (Y/N) | Commit / PR | Reviewer note |
|---|---|---|---|---|
| 1 | Authoritative enforcement point moved? | | | |
| 2 | Field gained a wire trust marker? (must stay N) | | | |
| ... | (remaining rows from the checklist) | | | |

## Threat-model refresh (major only)

- Release threat-model version advanced: <old> → <new>
- Revision-table row added: <yes/no>
- Pen-test checklist completed: <yes — see REFERENCE.md / n/a for non-major>

## Verdict

<!-- The token `Verdict: PASS` is what release-readiness.sh greps for. -->

Verdict: PASS
