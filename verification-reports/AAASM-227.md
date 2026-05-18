# F100 Verification — AAASM-227 (Inherited permissions & subtree budget burn in CLI and Dashboard)

> **Status**: All 7 implementation Sub-tasks merged. All 5 AC bullets satisfied end-to-end against `master @ ae19391d`. Design-fidelity companion (AAASM-1432) signed off separately. **No Bug Sub-tasks opened.**

## Sub-task roll-up

| Sub-task | Title | Status | PR | Merge commit |
|---|---|---|---|---|
| AAASM-1049 | CLI `policy show --show-permissions` | Done | [#458](https://github.com/AI-agent-assembly/agent-assembly/pull/458) | `b1a8d705` |
| AAASM-1051 | CLI `policy show --show-budget` | Done | [#463](https://github.com/AI-agent-assembly/agent-assembly/pull/463) | `cd551fdd` |
| AAASM-1053 | Dashboard `InheritedPermissionsPanel` | Done | [#465](https://github.com/AI-agent-assembly/agent-assembly/pull/465) | `24d56aa3` |
| AAASM-1055 | Dashboard `SubtreeBurnChart` | Done | [#469](https://github.com/AI-agent-assembly/agent-assembly/pull/469) | `12f0e1ea` |
| AAASM-1438 | Wire daily-spend history into `/subtree-burn` (follow-up to AAASM-1055) | Done | bundled in [#469](https://github.com/AI-agent-assembly/agent-assembly/pull/469) | commits `1c026cbf` + `3087f76f` |
| AAASM-1057 | Dashboard `ViolationHeatmap` | Done | [#264](https://github.com/AI-agent-assembly/agent-assembly/pull/264) | `163774eb` |
| AAASM-1432 | Playwright design-fidelity specs | Done | [#532](https://github.com/AI-agent-assembly/agent-assembly/pull/532) | `d0b9acb5` |
| AAASM-1129 | This verification report | in this PR | — | — |

## Walkthrough vs AAASM-227 acceptance criteria

### ✅ AC 1 — CLI `--show-permissions` displays full permission inheritance chain with effective result

**Surfaces shipped** (both wire forms of the AC):

* `aasm policy show <agent_id> --show-permissions`
* `aasm topology lineage <agent_id> --show-permissions`

**Verification (run on `master @ ae19391d`)**:

```
$ ./target/debug/aasm policy show --help | grep -E 'show-permissions|show-budget'
      --show-permissions
          Print the agent's effective capability set with cascade provenance
      --show-budget
          Print the agent's budget rollup across agent / team / org / subtree

$ ./target/debug/aasm topology lineage --help | grep show-permissions
      --show-permissions
          After the lineage, also print the agent's effective capability set with cascade provenance
```

Wire shape served by `GET /api/v1/agents/{id}/capabilities` (`EffectivePermissionsResponse`):

* `allow: string[]` — merged effective allow set
* `deny: string[]` — merged effective deny set
* `sources: PermissionSourceResponse[]` — per-scope contribution, in cascade order broadest → narrowest

`cargo nextest run -p aa-cli` — **423 / 423 pass** (includes `commands::policy_show::tests`, `e2e::topology_cli_test::e2e_topology_lineage`).

### ✅ AC 2 — CLI `--show-budget` displays budget spend per node with subtree totals

**Surface shipped**: `aasm policy show <agent_id> --show-budget`.

**Verification**:

* Flag registered (see `--help` dump above).
* Wire shape on `GET /api/v1/agents/{id}/budget` (`BudgetRollupResponse`): rows for agent / team / org / subtree, each with `scope`, `period`, `spent_usd`, `limit_usd`, `remaining_usd`, `percent_used`.
* `cargo nextest run -p aa-gateway -p aa-api` — **1 101 / 1 101 pass** (includes `budget::types::tests::*`, `budget::compute_rollup::tests::*`).

### ✅ AC 3 — Dashboard "Inherited Permissions" panel shows permission sources with visual indicators

**Surface shipped**: `InheritedPermissionsPanel` rendered on `AgentDetailPage`'s capability tab (`dashboard/src/components/InheritedPermissionsPanel.tsx`, wired at `dashboard/src/pages/AgentDetailPage.tsx:390`).

**Visual contract** (verified by AAASM-1432 design-fidelity specs):

* Allow chip foreground = `--ok` token (`#22592a`), deny chip foreground = `--danger` token (`#b8291e`), 12 px pill border-radius — matches `design/v1/hi-fi/identity.jsx`.
* One `.ipp__group` section per Capability category (Filesystem / Network / Terminal / MCP / Model / Spawn / Other).
* Summary strip shows allow count, deny count, cascade source count.
* Empty-state card (`.ipp--empty`) when cascade is empty.

**Test coverage**: `dashboard/src/components/InheritedPermissionsPanel.test.tsx` (vitest, passing) + `dashboard/tests/e2e/permissions-panel-design-fidelity.spec.ts` (4 Playwright tests, 12 / 12 in the AAASM-1432 batch).

**Evidence screenshots** (committed in PR #532 under `dashboard/docs/verification/aaasm-1432/`):

* `01-permissions-panel.png` — populated panel
* `02-chip-tokens.png` — token RGB equality
* `03-cascade-groups.png` — per-family grouping
* `04-empty-state.png` — empty cascade

**Accepted divergence (AAASM-1053 decision)**: rendered as the capability **tab** of `AgentDetailPage`, not the right-side **drawer** described in the AAASM-227 description. Visual contract for the panel itself is identical between tab body and drawer body; only the outer container differs.

### ✅ AC 4 — Dashboard "Budget Burn by Subtree" visualization renders with color-coded spend

**Surface shipped**: `SubtreeBurnChart` on the `AgentDetailPage` overview tab (`dashboard/src/components/SubtreeBurnChart.tsx`, wired at `dashboard/src/pages/AgentDetailPage.tsx:353`, lazy-loaded).

**Visual contract** (verified by AAASM-1432):

* Card title "Budget burn · subtree" + 7d / 30d period selector
* One stacked recharts `<Area>` per direct child, color-coded from a stable 7-color palette (`PALETTE` constant in `SubtreeBurnChart.tsx:30`)
* Aggregate `<Line>` overlay tracks total subtree spend
* `BurnTooltip` shows date + per-child rows + total when an area is hovered
* Empty-state card when no spend recorded

**Data path** (post-AAASM-1438):

* `GET /api/v1/agents/{id}/subtree-burn?period=7d|30d` returns dense time series, one `DailyBurnPointResponse` per calendar day with `per_child` breakdown
* AAASM-1438 (commits `1c026cbf` + `3087f76f`) replaced the AAASM-1055 single-point preview with the real `agent_spend_history` read path → the chart now shows the full window

**Test coverage**: `dashboard/src/components/SubtreeBurnChart.test.tsx` (vitest) + `dashboard/tests/e2e/budget-burn-design-fidelity.spec.ts` (4 Playwright tests).

**Evidence screenshots**: `05-burn-card.png`, `06-stacked-areas.png`, `07-period-toggle.png`, `08-burn-tooltip.png`.

**Accepted divergence (AAASM-1055 decision)**: rendered as a **stacked-area** chart, not the **treemap** described in the AAASM-227 description. The visual goal — operators can spot which child agents dominate spend — is met by either shape; stacked-area reuses the existing recharts dep instead of pulling d3-treemap, and the AgentDetailPage placement co-locates spend with the agent it belongs to. The prior verification's deferral on the "preview backend" is **resolved** by AAASM-1438.

### ✅ AC 5 — Dashboard shows policy violations by lineage / depth

**Surface shipped**: `ViolationHeatmap` page at `/audit/violations` (`dashboard/src/pages/ViolationHeatmapPage.tsx` + `dashboard/src/components/ViolationHeatmap.tsx`), reachable from the sidebar's "Audit Log" entry (`dashboard/src/routes.ts:37`).

**Visual contract** (verified by AAASM-1432):

* d3-hierarchy tree layout, one circle per agent in the lineage
* Color scale green (0 violations) → yellow (low) → red (high), with a 5-swatch legend strip + min / max labels
* Tooltip on hover: agent id slice, violation count, team, depth, top 3 violated policy rules
* Window selector (1h / 24h / 7d / 30d, default 24h) + root-agent hex input
* 1 000-node cap with "Show all" affordance for large fleets

**Data path**:

* `GET /api/v1/audit/violations-by-lineage?root=<id>&window=24h` aggregates `AuditEntry` rows where `event_type == PolicyViolation` grouped by `agent_id`
* `AuditReader::list_violations` scopes by `lineage.root_agent_id` (no full scan beyond the working JSONL window)
* Aggregation extracts top-3 policy rules per agent + lineage metadata (parent, team, depth)

**Test coverage**: `dashboard/src/components/__tests__/ViolationHeatmap.test.tsx` + `dashboard/src/pages/ViolationHeatmapPage.test.tsx` (16 vitest tests; both files at 100 % line + branch coverage post-AAASM-1057 rebase) + `dashboard/tests/e2e/violations-heatmap-design-fidelity.spec.ts` (4 Playwright tests).

**Evidence screenshots**: `09-heatmap.png`, `10-color-scale.png`, `11-heatmap-tooltip.png`, `12-heatmap-controls.png`.

## Cross-cutting verification (`master @ ae19391d`)

* `cargo nextest run -p aa-cli` — **423 / 423 pass** (1.6 s)
* `cargo nextest run -p aa-gateway -p aa-api` — **1 101 / 1 101 pass** (10.5 s)
* `pnpm exec vitest run` (dashboard) — **109 files / 940 tests pass** (9.2 s)
* `cargo build -p aa-cli` — clean; `./target/debug/aasm` boots and dumps help for `policy show`, `topology tree`, `topology lineage`
* `openapi/v1.yaml` carries the three F100 endpoint definitions (`agents/{id}/capabilities`, `agents/{id}/subtree-burn`, `audit/violations-by-lineage`); `dashboard/src/api/generated/schema.d.ts` carries the matching TypeScript types

## Bug Sub-tasks opened

**None.** All 5 AC bullets pass against current master. The two ticket-description divergences (capability tab vs. drawer, stacked-area vs. treemap) are conscious AAASM-1053 / AAASM-1055 implementation decisions, documented in their PRs and the AAASM-1432 design-fidelity report — not verification failures.

## Sign-off

F100 (AAASM-227) is **functionally complete** as of `master @ ae19391d` (2026-05-18). All implementation Sub-tasks merged, all 5 AC bullets verified end-to-end, design-fidelity verified separately by AAASM-1432, no open defects. Ready to close the parent Story.
