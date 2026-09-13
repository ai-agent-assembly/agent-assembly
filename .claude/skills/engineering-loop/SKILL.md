<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/engineering-loop/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — engineering-loop

## Purpose

Give every stack-specific development skill a shared execution model for
iterating on code changes at minimum waste without ever trading away
correctness. This is the company-common capability referenced by
`governance/engineering/agent-skill-architecture.md` (HORO-969) §1 — it
owns the execution loop and the progressive diagnostic contract; it does
not own any language's actual build/test/lint commands.

## Type

Auto-used. Invoke whenever iterating on a code change — writing, running,
or debugging a test/build/lint/check — regardless of which language skill
also applies. Language skills (`rust-development`, `python-development`,
etc.) compose with this one; they supply the concrete commands, this skill
supplies the loop and diagnostic discipline around them.

## The five-stage execution model

1. **Explore** — locate the relevant code/tests before changing anything;
   prefer a fast accelerator (RTK/CodeGraph) over cold grep, per §
   Optional-tool fallback below.
2. **Narrow** — run the smallest check that can prove or disprove the
   specific change (one test, one file, one lint target) — not the whole
   suite.
3. **Validate** — confirm the narrow check passed for the reason you
   expect, at the lowest diagnostic level (L0) that actually settles it.
4. **Escalate** — when L0 is ambiguous or contradicts expectation, step up
   the L0→L3 ladder (see `references/diagnostic-contract.md`) only as far
   as needed to find the true root cause.
5. **Full Gate** — before calling the change done, run the repo's
   authoritative full check (full test suite, full lint, full build) —
   a narrow check that passed is evidence the fix works, never proof the
   repo is releasable.

## When to use

- Any iterative code/test/lint/build loop, in any language, on any repo
  that has adopted this skill.
- Debugging a failure that a narrow check surfaced, before deciding it's
  fixed.

## When NOT to use

- As a substitute for a language skill's actual commands — this skill
  never hardcodes `cargo test`/`pytest`/etc.; see the relevant
  `*-development` skill for that.
- As an excuse to skip the Full Gate stage — a fast targeted check passing
  is never sufficient release/PR/merge evidence on its own.
- As a bypass to make a real failure look green — the diagnostic contract
  is non-negotiable (see below); a parser/wrapper bug must never be used
  to reinterpret a FAIL as a PASS.

## The L0–L3 diagnostic contract

Every check this loop runs must be reportable at four progressive levels
of detail — PASS/FAIL counts, then file/line, then relevant traceback,
then complete raw output — with raw evidence always recoverable and exit
status always preserved. Full ladder, non-negotiable rules, and collapsing
guidance: `references/diagnostic-contract.md`.

## Optional-tool preferred→fallback semantics

RTK and CodeGraph accelerate Explore/Narrow but are never mandatory and
must never let a check silently become a no-op when absent, nor let
static/navigation evidence substitute for a real compiler/test/runtime
gate. Full semantics: `references/optional-tool-fallback.md`.

## Worked examples

- `examples/targeted-loop-then-full-gate.md` — narrow iteration followed
  by the Full Gate before declaring a change done.
- `examples/escalation-from-compact-to-raw.md` — escalating L0 → L1 → L2 →
  L3 to find a root cause a compact result hid.
