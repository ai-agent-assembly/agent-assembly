# Runtime verification recipes (AAASM-5830)

Persistent per-repo recipes so `/release-qa-gate` (AAASM-5821) and the
`qa-*` roles (AAASM-5826) don't rediscover install/build/start/verify/
cleanup commands every run. Each recipe states: canonical working directory,
build/start command, non-secret prerequisites, readiness observation,
minimal behavior probe, cleanup, and platform constraints — and is labeled
**public-artifact** (satisfies an outside-in golden-journey check) or
**source-development** (does not — see AAASM-5830's outside-in constraint:
a source-dev recipe must never be silently substituted for an unavailable
public path to manufacture a PASS).

No secrets, tokens, or machine-specific absolute paths are baked into any
recipe here — every recipe uses an isolated temp directory it creates and
(where relevant) removes, and reads ports dynamically rather than hard-coding
one.

## Recipes in this set

| Recipe | Label | Covers |
|---|---|---|
| [`aasm-cli-dev.md`](aasm-cli-dev.md) | source-development | `aa-cli` build + basic CLI smoke |
| [`docs-site-build.md`](docs-site-build.md) | n/a (docs are the artifact) | mdBook local build/preview for doc-integrity + docs-design checks |
| [`python-sdk-dev-install.md`](python-sdk-dev-install.md) | source-development | Python SDK dev install + import/entrypoint sanity |

Every recipe above was executed from a fresh precondition (isolated temp
build dir / idempotent `uv sync`), reached its stated ready condition,
performed its minimal behavior probe, and (where a throwaway artifact was
created) ran cleanup — see each recipe's "Verified" section for the exact
run record.

## Deliberately left out this round (AC: explicit rationale, not brittle automation)

- **Node SDK, Go SDK public/dev install** — `node-sdk`/`go-sdk` sibling
  checkouts exist, but this run's time/token budget did not extend to
  exercising `npm install`/`go build` end-to-end with real registry/module-
  proxy network calls and recording a verified result. Left out rather than
  documented-but-untested, per this Epic's "don't manufacture false
  confidence" principle. A follow-up run should add these once budgeted.
- **Published-artifact SDK install paths** (`pip install agent-assembly`,
  `npm install`, `go get`) — genuinely the *public* golden-journey path
  (J05-J10), but verifying it live against PyPI/npm/the Go module proxy is a
  real network operation with its own flakiness/rate-limit surface that this
  recipe-authoring pass did not execute. Documented as a gap, not silently
  answered by the source-dev recipe above (which is explicitly labeled to
  NOT satisfy this).
- **`aa-gateway` published container image** (J53) — requires GHCR pull
  access this session did not attempt; the container-based golden path is
  correspondingly `UNTESTED_OR_BLOCKED` wherever it's referenced, not
  silently assumed working.
- **Dashboard local startup** (for `qa-design`'s J18) — requires bringing up
  a live gateway plus the dashboard dev server; genuinely valuable but a
  larger recipe than the budget for this ticket covered honestly. Left out
  rather than given a half-verified recipe.
- **Docker Compose limited-OSS stack** (J16) — multi-container startup with
  its own readiness/health-check surface; same reasoning as the dashboard —
  left out rather than asserted-but-unverified.

These gaps are real and should be recorded as `UNTESTED_OR_BLOCKED` by any
QA run that would otherwise need them (see AAASM-5828's evidence contract),
not silently treated as covered.
