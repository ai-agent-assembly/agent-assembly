# AAASM-1384 — Topology UI Design Fidelity Report

**Story**: [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95) (S22 — Security engineer trace + violation highlights)
**Sub-task**: [AAASM-1384](https://lightning-dust-mite.atlassian.net/browse/AAASM-1384) — design fidelity verification of the **topology half**
**Pairs with**: AAASM-1341 (topology functional, done) · AAASM-1383 (trace design-fidelity, done) · AAASM-1152 (trace functional, done)
**Verified at master HEAD**: `477ca41c` (Merge PR #412 — dependabot metrics-0.24.6, 2026-05-14)
**Evidence captured by**: `dashboard/tests/e2e/topology-design-fidelity.spec.ts` (6 tests, all passing in 3.7 s)

## Scope note

This sub-task is the visual counterpart to [AAASM-1341](https://lightning-dust-mite.atlassian.net/browse/AAASM-1341) (which verified topology *behavior* against the parent-story AC). Here we verify that the rendered output matches the design source — colour tokens, threshold transitions, panel layout, cluster outlines, hover highlight — against `agent-assembly/design/v1/hi-fi/topology.jsx` and the impl's own CSS contracts.

## Token-naming caveat (AC vs impl)

The sub-task AC names tokens `--success-bg / --neutral-bg / --danger-bg` for node status. Those tokens **do not exist** in `dashboard/src/styles.css` — they're not defined anywhere in the codebase. The impl uses the foreground tokens `--ok / --ink-4 / --danger`, which is correct for SVG `fill` (the `*-bg` tokens are for backgrounds, e.g., the trace-row backgrounds). The verification asserts the **actual** tokens used by the impl. This is identical in shape to the AC-vs-impl mismatch documented in AAASM-1383's report.

## Cross-cutting health checks

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Unit + component tests | `pnpm test` | ✅ 96 files / 809 tests pass |
| Topology design-fidelity E2E | `pnpm test:e2e tests/e2e/topology-design-fidelity.spec.ts` | ✅ 6 tests pass (3.7 s) |

## Fixture used by the spec

Deterministic graph injected via Playwright `page.route` mocks on `/api/v1/topology`,
`/api/v1/topology/nodes/*/events`, `/api/v1/approvals*`, and `/api/v1/ws/events*`:

- **5 nodes** across **2 teams** (`support × 3`, `analytics × 2`) — satisfies the ticket's "≥ 5 nodes / 2 teams" requirement.
- Statuses: `active × 2`, `idle × 2`, `error × 1`.
- Per-node budget ratios: `0.92` (large), `0.55` × 2 (medium), `0.10` (small), `0.05` (small).
- The budget-bar threshold test rebuilds the fixture three times with uniform per-node ratios `0.30 → ok`, `0.85 → warn`, `0.97 → danger`.
- `latestSessionId` set on `router` (mid-budget) — kept available for cross-cutting checks (used in AAASM-1341, not exercised here).

## AC-by-AC verification

| # | AC requirement | Evidence | Observation | Status |
|---|---|---|---|---|
| 1 | Node colours resolve to the exact tokens for `active / idle / error` | `aaasm-1384/01-status-stripe-tokens.png` | Computed `fill` on `.topology-node__stripe` resolves to `rgb(34, 89, 42)` (`--ok`), `rgb(138, 138, 138)` (`--ink-4`), and `rgb(184, 41, 30)` (`--danger`). AC's `--success-bg / --neutral-bg / --danger-bg` token names do not exist; impl correctly uses the foreground tokens for SVG fills (see token-naming caveat). | ✅ |
| 2 | Node radius bucketing matches `< 0.5 small`, `0.5–0.8 medium`, `> 0.8 large` | `aaasm-1384/02-node-size-buckets.png` | `data-size-bucket` distribution matches the fixture: 2 small, 2 medium, 1 large. Geometric check confirms a `large` card's `<rect width>` is greater than a `small` card's (`SIZE_VARIANT { small: 76, medium: 96, large: 116 }`). | ✅ |
| 3 | NodeDetailPanel layout (header / status badge / sections / View trace button) matches hi-fi proportions | `aaasm-1384/03-node-detail-panel-layout.png` | All five sections — `identity`, `policies`, `budget`, `recent`, `actions` — are present, visible, and ordered strictly top-down by bounding-box `y`. Status badge (`node-detail-status`) sits in the header. `View trace` button carries `node-detail-panel__action--primary` modifier — locked in as the primary action. | ✅ |
| 4 | Team cluster outlines render with team-name labels positioned at cluster top | `aaasm-1384/04-team-cluster-labels.png` | 2 clusters render (one per team). Outline uses the documented dashed stroke (`stroke-dasharray: 4 3`). The team label's bounding-box `y` is less than the first node card's `y`, confirming it sits at the cluster top, and the label's `text-transform` resolves to `uppercase` per the design rule. | ✅ |
| 5 | Team budget bar crosses ok→warn at 0.80 and warn→danger at 0.95 | `aaasm-1384/05a-budget-bar-ok.png` · `05b-budget-bar-warn.png` · `05c-budget-bar-danger.png` | Three separate fixtures verify the contract: at uniform 0.30 the fill resolves to `rgb(34, 89, 42)` (`--ok`); at 0.85 it resolves to `rgb(138, 90, 0)` (`--warn`); at 0.97 it resolves to `rgb(184, 41, 30)` (`--danger`). Each bar also carries the matching `data-threshold-bucket` attribute. | ✅ |
| 6 | Topology with a node hovered (highlight visible) | `aaasm-1384/06-node-hover-highlight.png` | On hover, `.topology-node__card`'s computed `stroke` resolves to `rgb(42, 42, 42)` (`--ink-2`) per the documented CSS rule `.topology-node:hover .topology-node__card { stroke: var(--ink-2); }`. | ✅ |

## Documented accepted divergences (not bugs)

These are *intentional* differences between the impl and the hi-fi prototype. Each was merged with explicit sign-off in the originating ticket and the user's chosen preference at design-fidelity time. They are recorded here so reviewers can distinguish "design decision" from "regression":

| Divergence | Origin | Why it's accepted |
|---|---|---|
| Status enum uses `error` where hi-fi uses `suspended` | AAASM-1335 | Data-model concern, not visual; both render the same `--danger` red. |
| Idle stripe colour is `--ink-4` (mid grey); hi-fi paints idle in `--warn` orange | AAASM-1335 | Merged choice — idle is a *non-actionable* state and grey reads as "off / paused"; orange in the hi-fi reads as "warning" which would confuse with the team budget bar's warn state. |
| Nodes are size-bucketed by budget spend; hi-fi uses fixed `TL_NW × TL_NH` | AAASM-1335 | Parent Story AC explicitly says "size encodes budget spend"; the variable-size impl matches the AC, not the static hi-fi. |
| Hi-fi extras (depth badge, mode/trust line, cycle warning, live-update pulse) not yet wired | Sprint 3 backlog | The required data (depth, mode, trust, cycle membership) is not yet on the `/api/v1/topology` payload. Separate tickets will add as data lands. |

## Spec correction log

| Commit | Reason |
|---|---|
| `🚨 Match computed strokeDasharray format (4px, 3px not 4 3)` | Initial draft asserted the raw SVG attribute string `"4 3"`. `getComputedStyle().strokeDasharray` returns the value with `px` units and comma separators (`"4px, 3px"`); only the raw attribute (via `getAttribute`) is the unitless form. Corrected to read the computed form. Not a behaviour change. |

## Bug sub-tasks opened

None. All six visual-contract bullets pass. The documented divergences above are *not* bugs — they are deliberate, signed-off decisions captured in earlier implementation tickets.

## Sign-off

- [x] All six topology UI design-fidelity bullets satisfied
- [x] Evidence captured and committed (8 PNGs — one per test, plus 3 for the budget-bar threshold sweep)
- [x] Type check + full vitest suite + this fidelity E2E green at verification time
- [x] No bugs opened; accepted divergences documented

AAASM-1384 can be transitioned to **Done** once this PR merges. With this closed, the parent Story AAASM-95 has all four verification sub-tasks complete (AAASM-1152 + AAASM-1383 trace; AAASM-1341 + AAASM-1384 topology) and can itself be closed. AAASM-1391 (trace step-card layout polish) stays open as a Sprint 3 nice-to-have.
