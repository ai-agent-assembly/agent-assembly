# references/validation-tracks.md — product-validation

The four tracks this skill owns, in concrete operational terms, plus the
canonical scenario schema and the fresh-context/independence principle
every track runs under.

## The fresh-context/independence principle — read this before running any track

Prefer a **fresh session, clean checkout, or deployed artifact** over the
implementation session's own dev-server or in-memory state. A scenario
run from inside the same session that wrote the code inherits that
session's assumptions about what "should" work — it is prone to
confirming its own mental model rather than testing the product.

Concretely, in priority order:

1. **Best**: an independent evaluator (a fresh subagent with no access to
   the implementation session's context, or a human) working only from
   committed docs, `--help` output, and observable product behavior —
   never from memory of writing the code.
2. **Good**: the same session, but deliberately restricted to public
   docs/CLI output rather than implementation memory, run against a
   genuinely fresh `git clone` into a throwaway directory (not the
   working tree the change was made in) or a freshly deployed artifact.
3. **Acceptable, weakest**: the implementation session's own dev
   server/build, used only when a fresh checkout or deployed artifact is
   not available — call this out explicitly in the quality report as a
   weaker independence grade, never silently.

A real worked instance of tier 1/2 in practice: circinus's HORO-406
fresh-user dogfood campaign ran 9 independent journeys — 4 via delegated
evaluator subagents with no access to the implementation session's
context, 5 by the orchestrating session deliberately restricted to
committed docs/CLI output — each starting from a genuine fresh `git
clone` into a throwaway `/tmp` directory at a pinned commit
(`docs/hardening/HORO-406-fresh-user-dogfood-report.md` in the circinus
repo). That report is real, dogfooded evidence, not a hypothetical — see
its own "Disclaimer" section for exactly what it does and does not claim
(no external-user/willingness-to-pay claim; evaluator-agent findings
only).

## Canonical scenario schema

Every scenario — in any of the four tracks — is recorded in this shape.
A scenario missing a required field is not yet ready to run.

| Field | Required | Meaning |
|---|---|---|
| `scenario_id` | yes | Stable identifier (e.g. `smoke-001-fresh-install`). Never reused for a different scenario. |
| `persona` | yes | Who is running this — "new user following the quickstart", "operator restarting a crashed daemon", "adversarial input tester". |
| `problem` | yes | What real problem this scenario proves the product solves, in one line. |
| `preconditions` | yes | State that must exist before the scenario starts (a fresh clone, a running relay, a specific config). |
| `environment` | yes | OS, runtime versions, deployment shape (local dev, packaged artifact, two-environment/two-machine setup). |
| `starting_point` | yes | The literal first state/command — a fresh `git clone`, a fresh install, a deployed release artifact. |
| `surface` | yes | What's being exercised — CLI, API, rendered UI, config file, installed hook. |
| `actions` | yes | The literal ordered steps taken, verbatim commands/clicks where possible — not paraphrased. |
| `expected_states` | yes | What must be true after each meaningful step, not only at the end. |
| `expected_outcome` | yes | The scenario's overall pass condition. |
| `evidence` | yes | What was captured to prove the outcome — command output, log excerpt, screenshot/video reference, exit code. Bounded artifact, not this record itself (see `quality-report-template.md`). |
| `cleanup` | yes | How the scenario's side effects are reverted (uninstall, drop test data, tear down a throwaway clone). |
| `mapped_features_jira_docs` | yes | The Feature/Story/Epic this scenario proves, and the docs page it exercises if the track is docs-driven. |

## Track 1 — Smoke / install

Proves the product can be installed/started/verified/torn down cleanly by
someone who has never touched this checkout before.

Operational shape: discover → install/configure → run → verify health →
exercise one trivial real action → clean up. Run this from the
independence tiers above, not from an already-running dev environment
that's accumulated state across many implementation sessions.

Real pattern: ophiuchus's `docs/dogfood-tester-guide.md` §2 ("Clean-machine
install/quickstart checklist") is exactly this track's checklist shape —
runtime prerequisites, install command, and a version/status smoke check,
each verified against a real checkout rather than written from memory.

## Track 2 — Golden user journey

Proves the product's single most important end-to-end path — the thing
the product exists to do — works for a real user, start to finish, in one
continuous session (not a sequence of isolated unit checks stitched
together after the fact).

Operational shape: pick the one journey that, if broken, means the
product doesn't work regardless of what else passes (e.g. capture →
send → receive for Ophiuchus; a full policy decision round-trip for
Circinus). Run it as a single scenario per the schema above, evidence
captured at each expected-state checkpoint, not only at the end.

## Track 3 — QA / adversarial product behavior

Proves the product fails safely and behaves correctly under conditions a
real user or attacker will eventually hit, not just the happy path:
malformed input, killed processes, concurrent access, stale/expired
state, config drift, permission denial.

Real pattern: circinus's HORO-406 report explicitly names "direct
adversarial testing (deliberately broken hooks, hard-killed daemons,
conflicting env vars, malformed installs)" in its "What worked well"
section, and its findings table includes a genuinely adversarial one
(`CIRCINUS_ANALYSIS_SEND_CONTENT=yesplease`, a malformed boolean, verified
to fail safe rather than open — filed as HORO-438, not silently accepted
because it "worked out"). This track owns exactly that shape of probing.

## Track 4 — Documentation-driven journey

Proves the product's own published docs are sufficient, on their own, to
get a real user from zero to a working outcome — the evaluator follows
*only* what the docs say, and every gap between "what the docs claim" and
"what actually happens" is itself a finding, whether it's a product bug
or a docs bug.

Operational shape: restrict the evaluator to `README.md`/`docs/`/`--help`
output only — no implementation memory, no reading source to figure out
the real behavior. If the docs are wrong, that's a genuine finding (route
docs-content fixes through `documentation-experience`, but the *defect
that the docs claim doesn't hold* still goes through this skill's
defect lifecycle — see `references/defect-lifecycle.md`).

Real pattern: circinus's HORO-406 method section states evaluators "rely
only on `README.md`, `docs/`, and CLI `--help` output — not on
implementation memory" and one of its findings (`c22e5cd`, a stale
`docs/adr/` claim) is exactly a documentation-driven-journey defect: the
docs said something false about the product's own state.
