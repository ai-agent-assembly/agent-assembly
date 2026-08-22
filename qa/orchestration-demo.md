# Orchestration demonstration (AAASM-5826 AC)

Real run, not a hypothetical: two independent QA-role-shaped sub-agents were
launched concurrently in the same wave (2026-08-22), simulating a
`qa-functional` + `qa-reliability-docs` pairing against this repo.

## Setup

- **Agent A** (`qa-functional`-shaped): inspect `aa-cli`'s subcommand
  structure. Explicitly scoped to `aa-cli/` only.
- **Agent B** (`qa-reliability-docs`-shaped): inspect `docs/src/SUMMARY.md`'s
  top-level sections. Explicitly scoped to that one file only.

Both launched in the same message (genuinely concurrent, not sequential).

## Result

| | Agent A | Agent B |
|---|---|---|
| Scope | `aa-cli/src/commands/mod.rs` | `docs/src/SUMMARY.md` |
| Duration | 10.7s | 6.7s (overlapped with A, not queued after it) |
| Files touched | 1 (`aa-cli/src/commands/mod.rs`) | 1 (`docs/src/SUMMARY.md`) |
| Overlap with the other agent's scope | none | none |
| Output | 27 top-level `aasm` subcommands, each with `file:line` | 20 top-level SUMMARY.md sections, each with line number |

Both returned a compact, cited result — no chain-of-thought, no full-file
dumps — consistent with the AAASM-5828 worker result contract this Epic's
real `qa-*` roles must also follow.

## What this demonstrates

- **Independent tasks execute in parallel** — both agents ran concurrently
  (overlapping wall-clock, not one blocking the other) and returned
  independently.
- **No overlapping file edits** — this was a read-only demo (both roles here
  are read-only investigation, matching `qa-functional`'s and
  `qa-reliability-docs`' actual tool scopes), and critically, no overlapping
  *investigation scope* either: Agent A never touched `docs/`, Agent B never
  touched `aa-cli/`.
- **No duplicated investigation** — each agent was given a distinct,
  non-overlapping task; neither re-derived what the other already covered.
- **The demo used 2 of the 5-slot ceiling**, leaving 3 free — consistent with
  AAASM-5826's "does not always saturate all five slots" requirement.

This is a structural demonstration of the orchestration contract (distinct
scopes, genuine concurrency, compact output), not a full `/release-qa-gate`
run — the full gate is exercised end-to-end in AAASM-5831's dogfood.
