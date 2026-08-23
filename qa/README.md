# `qa/golden-journeys.yaml` — machine-readable journey catalog

Selection/index layer over [AAASM-4522](https://lightning-dust-mite.atlassian.net/browse/AAASM-4522),
which remains the durable human-readable requirement source. This file exists
so `/release-qa-gate` (AAASM-5821) and the risk mapper (AAASM-5829) can select
journeys deterministically from changed surfaces without re-reading 60 Jira
Stories every release.

**Do not copy Jira description prose into this file.** Each row is a thin
index: stable ID, Jira reference, priority (per
[the release QA policy](../docs/src/qa/release-qa-policy.md)'s P0/P1/P2
definitions), persona/track, affected surfaces (path prefixes, not exact
files), entry point, verification lanes, browser requirement, and a one-line
pointer back to the Jira Story for the actual acceptance contract.

## Fields

| Field | Meaning |
|---|---|
| `id` | Stable ID (`J01`-`J60`), matches the `[Journey NN ...]` numbering already used in AAASM-4522 Story titles — survives title wording changes. |
| `jira` | The AAASM-4522 child Story key. |
| `name` | Concise name (not the full Story description). |
| `priority` | `P0` \| `P1` \| `P2`, per the release QA policy. |
| `persona_track` | The journey's category/persona (Discovery, Install, Policy, Function, Golden Path, ...). |
| `surfaces` | Path prefixes this journey's outcome depends on — used for risk-mapper selection. |
| `entry_point` | How a user reaches this journey (`cli`, `sdk`, `docs`, `dashboard`, `gateway`, `container`, ...). |
| `lanes` | Which evidence-contract lane(s) (AAASM-5828) this journey exercises. |
| `browser_required` | Whether real-browser verification is needed (per this repo's user-smoke convention — no `page.route`/mocked substitutes). |
| `outcome` | One line pointing back to the Jira Story for the real acceptance contract — never a copy of it. |

## The P0 set (10 journeys — within AAASM-5820's 8-15 bound)

`J04` (install CLI), `J08` (Python SDK Quick Start), `J17` (gateway from
published artifact), `J19` (author/apply policy), `J21` (doc/command
integrity), `J24` (allow/deny enforcement), `J41` (three-layer interception
model), `J53` (gateway container image), `J56` (Golden Path — Python Dev),
`J59` (Golden Path — Operator). Covers primary install, primary SDK smoke,
gateway startup, policy authoring + enforcement, core architecture, primary
deployment, docs integrity, and one golden-journey walkthrough per major
entry point (CLI/SDK, container, operator).

## Validation

```bash
python3 scripts/qa/validate-golden-journeys.py qa/golden-journeys.yaml
```

Catches duplicate `id`/`jira` values, invalid `priority`, missing required
fields, and a P0 set outside the 8-15 bound.

## Selection demonstration

```bash
python3 scripts/qa/select-journeys-demo.py aa-gateway/src/policy
```

Given a changed-surface list, prints the P0 set plus every P1/P2 journey whose
`surfaces` prefix-matches — without reading any Jira Story. This script is a
demonstration of selectability, not the real risk mapper; AAASM-5829 owns the
production mapping logic (which also assigns/refines `risk_tier`, which this
catalog does not carry — risk is per-surface, not per-journey).
