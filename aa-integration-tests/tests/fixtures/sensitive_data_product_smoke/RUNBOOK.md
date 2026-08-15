# Sensitive-data product smoke — LLM QA runbook

Read this before touching `aa-security`/`aa-gateway` source. It tells you
how to run this suite as a black-box product tester and how to react to
what you find.

## What you are testing

Whether Agent Assembly's shipped sensitive-data protection does what it
claims from a **user's** entry point, not whether the detector's own unit
tests pass — those are `conformance/vectors/` and already exist.

## How to run it

```bash
cargo nextest run -p aa-integration-tests --test sensitive_data_product_smoke
```

Two tests run:

- `sensitive_data_product_smoke_scenarios_pass` — walks every scenario in
  `scenarios.json` through the real `PolicyEngine::evaluate()` pre-action
  path and checks each against its declared `expect`. A failure names the
  scenario id and exactly what mismatched.
- `sensitive_data_product_smoke_scenarios_are_falsifiable` — proves the
  checker above can actually fail. If this one is red, the suite itself is
  broken; fix it before trusting the other test's green.

For the parts this file does not cover, run these alongside it:

```bash
# Real-destination non-transmission evidence (credential_action: block)
cargo nextest run -p aa-proxy --test mitm_execution_evidence --test refusal_evidence

# Dashboard / Design QA against the real API (AAASM-5694 real-backend lane)
cd dashboard && pnpm exec playwright test --config=playwright.realbackend.config.ts verify-aaasm-5360
```

## The contract, in one page

Open `scenarios.json`. Each entry is:

| Field | Meaning |
|---|---|
| `id` | Stable scenario name |
| `class` | `credential` / `pii` / `zh_tw` / `custom` / `negative_control` / `semantic_pii` |
| `support` | `supported` — v1 ships a detector, expect a finding. `negative_control` — benign, expect nothing to change. `unsupported` — v1 has no detector for this, expect `EXPECTED_UNSUPPORTED`. |
| `vector_ref` | Path under `conformance/vectors/` this scenario's payload is loaded from — **do not** duplicate the payload inline; read it from there. |
| `payload` | Only present when no conformance vector exists (the unsupported-semantic-class scenarios, and the operator-defined-pattern one). |
| `expect` | The full outcome contract — decision, expected finding kind, whether redaction must have occurred, whether the content must stay clean. |
| `notes` | Why an `unsupported` scenario is unsupported, with what was checked to establish that. |

**You do not need to read `aa-security` or `aa-gateway` source to know what
"correct" means for a scenario** — the `expect` block is the whole
contract. If you find yourself opening `scanner.rs` to figure out what a
scenario *should* produce so you can write an assertion that matches
whatever the code currently does, stop — that is constructing a test that
can only pass, which is exactly what this runbook exists to prevent.

## What to do with what you find

- **A `supported` or `negative_control` scenario fails**: this is a
  candidate product defect. Reproduce it once more with
  `cargo nextest run -p aa-integration-tests --test sensitive_data_product_smoke -- --nocapture`,
  confirm it against current `main` (not a stale build), then search Jira
  for an existing issue before filing a new one — see the governance rules
  in AAASM-5791's description. Link any new issue to AAASM-5791 and to
  AAASM-5270 (the implementation Epic).
- **An `unsupported` scenario suddenly produces a finding**: the product
  gained capability the scenario pack doesn't know about yet — good news,
  but the scenario's `support` and `expect` fields are now stale and need
  updating to `supported`, not silently left as `unsupported`.
- **A scenario itself looks wrong** (payload doesn't match its stated
  class, `expect` looks miscalibrated): this is a test-harness defect, not
  a product defect. Fix the scenario, and say in the PR why the old
  `expect` was wrong — don't just widen it to make the suite pass.
- **The suite won't compile or the fixture files are missing**: this is an
  infrastructure failure, not a product finding. Report it as such rather
  than as a sensitive-data defect.

## Non-goals

This suite does not exercise Presidio, Gitleaks, or any out-of-process
provider — those are deferred post-v1 under ADR 0032 D-1 and out of scope
for AAASM-5791. If a scenario "fails" because it expected NLP/NER-grade
semantic PII detection, that is not a defect; check the scenario's
`support` field before filing anything.
