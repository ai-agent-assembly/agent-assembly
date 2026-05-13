# AAASM-1341 — Topology AC Verification Report

**Story**: [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95) (S22 — Security engineer trace + violation highlights)
**Sub-task**: [AAASM-1341](https://lightning-dust-mite.atlassian.net/browse/AAASM-1341) — functional verification of the **topology half**
**Pairs with**: AAASM-1152 (trace functional, done) · AAASM-1383 (trace design-fidelity, done) · AAASM-1384 (topology design-fidelity, pending)
**Verified at master HEAD**: `d541897f` (Merge PR #406 — AAASM-1340 View trace drawer wiring, 2026-05-14)
**Evidence captured by**: `dashboard/tests/e2e/verify-aaasm-1341.spec.ts` (5 tests, all passing in 4.5 s)

## Scope note

This sub-task covers the topology-side AC bullets from parent Story AAASM-95
plus the cross-cutting "View trace pivot" rule from the design reference
(implementation rule #3: *the trace is a global overlay drawer triggered
from the topology node panel "View trace" action*). The trace-content
bullets (timeline, severity highlights, payload modal, filter, export)
were verified in [AAASM-1152](https://lightning-dust-mite.atlassian.net/browse/AAASM-1152).

## Cross-cutting health checks

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Unit + component tests | `pnpm test` | ✅ 93 files / 781 tests pass |
| Topology E2E (this spec) | `pnpm test:e2e tests/e2e/verify-aaasm-1341.spec.ts` | ✅ 5 tests pass (4.5 s) |

## Fixture used by the spec

Deterministic graph injected via Playwright route mocks on `/api/v1/topology`,
`/api/v1/topology/nodes/*/events`, `/api/v1/agents/{id}`, and
`/api/v1/agents/{id}/sessions/sess-aaasm-1341/trace`:

- **4 nodes** across **2 teams** (`support` × 2, `analytics` × 2)
- Statuses: `active` × 2, `idle` × 1, `error` × 1
- Budget ratios: `0.92` (large→warn), `0.55` (medium), `0.10` (small) × 2
- `agent-support-1.latestSessionId = "sess-aaasm-1341"` — enables the
  View-trace pivot test
- **2 edges**: `delegation` and `call`

## AC bullet-by-bullet verification

Each row maps a parent-story AC bullet to the captured evidence file and a
short observation. The "Implementation ticket" column points to where each
behaviour was originally built so reviewers can cross-reference the diff.

| # | AC bullet (from AAASM-95) | Implementation ticket | Evidence | Observation | Status |
|---|---|---|---|---|---|
| 1 | Topology page renders agent call graph with correct hierarchy from API | AAASM-1333 (API) + AAASM-1335 (graph render) | `aaasm-1341/01-graph-overview.png` | Header reads `4 agents · 2 teams`; the SVG renders `[data-testid=topology-node]` × 4 (one per fixture node). Force layout converges to a stable position after one tick. | ✅ |
| 2 | Nodes are color-coded by status; size encodes budget spend | AAASM-1335 | `aaasm-1341/02-status-and-size-encoding.png` | Every documented status surfaces in the graph via `data-status` on `<g.topology-node>` (CSS rules in `TopologyGraph.css` bind these to the status colour tokens — `--ok`, `--ink-4`, `--danger`). The spec asserts `active=2`, `idle=1`, `error=1`. Size encoding: `data-size-bucket` is `small` for ratio `<0.5`, `medium` for `0.5–0.8`, `large` for `>0.8`. Fixture yields one `large` (support-1 at 0.92), one `medium` (analytics-1 at 0.55), and two `small` nodes. | ✅ |
| 3 | Clicking a node opens detail panel: agent info, permissions, recent events, budget | AAASM-1337 (panel) + AAASM-1340 (View-trace) | `aaasm-1341/03-node-detail-panel.png` | Click on support-1 opens `node-detail-panel`. Identity section shows the agent id, owner (`alice`), team (`support`), and framework (`langgraph`). The "permissions" AC bullet is implemented as the **Policies** section — `node-detail-policy-count` reads `3 policies`. Recent events list is populated from `/api/v1/topology/nodes/{id}/events` (2 rows: `tool_call` + `policy_violation`). Budget section shows the progressbar at `aria-valuenow="92"` with `data-ratio-bucket="warn"` (warn at `0.80–0.95`, danger at `≥0.95`). | ✅ |
| 4 | Team grouping visually separates agents by team with team-level budget bar | AAASM-1339 | `aaasm-1341/04-team-grouping-budget.png` | Two `[data-testid=team-cluster]` outlines render — one per team (`support`, `analytics`). Each cluster has its own `[data-testid=team-budget-bar]`. Aggregate spends: support = `9.2 + 1.0 = 10.2` of `20` → `0.51` → `ok`; analytics = `5.5 + 0.5 = 6.0` of `20` → `0.30` → `ok`. Threshold buckets resolve via `bucketForBudget` — shared with the node-detail progress bar. | ✅ |
| Cross-cut | Trace drawer is the global overlay triggered from the topology node panel "View trace" — implementation rule #3 in the parent Story | AAASM-1340 | `aaasm-1341/05-view-trace-drawer.png` | The *View trace* button is **enabled** when `node.latestSessionId` is set. Clicking it mounts `[data-testid=trace-drawer]` at the shell level (not inside the topology page). The drawer body loads `<TraceViewPage agentId sessionId>` and renders the trace timeline (mocked `policy_violation` + `llm_call`). `trace-agent-label` resolves to the agent's name (`support-bot`). Esc closes the drawer. | ✅ |

## Bug sub-tasks opened

None. All 4 topology-related AC bullets + the cross-cutting trace-pivot rule pass.

## Spec correction log

| Commit | Reason |
|---|---|
| `🚨 Match impl's budget threshold (0.92 ratio → warn, not danger)` | Initial draft asserted that the `9.2 / 10` fixture would land in the `danger` bucket. The shared `bucketForBudget` helper uses `≥ 0.95` for `danger`; `0.92` is `warn`. Corrected to align with the documented threshold contract — not a behaviour change, just a test-side typo. |

## Sign-off

- [x] All 4 topology-half AC bullets satisfied
- [x] Cross-cutting "View trace pivot" rule from AAASM-95's implementation
      rules satisfied (AAASM-1340 integration verified end-to-end)
- [x] Evidence captured and committed
- [x] Type check + full vitest suite + topology E2E green at verification time
- [x] No bugs opened

AAASM-1341 can be transitioned to **Done** once this PR merges. The remaining
sub-task under AAASM-95 is:

- **AAASM-1384** — topology design-fidelity verification (visual side, pending)

Parent Story AAASM-95 can be closed once AAASM-1384 signs off, since
AAASM-1152 (trace functional), AAASM-1383 (trace design-fidelity), and
AAASM-1341 (this report — topology functional) are all complete.
