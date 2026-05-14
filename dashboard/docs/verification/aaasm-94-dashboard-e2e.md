# AAASM-94 — Dashboard Story-level e2e Verification Report

**Epic**: [AAASM-11](https://lightning-dust-mite.atlassian.net/browse/AAASM-11) (Community Dashboard)
**Story**: [AAASM-94](https://lightning-dust-mite.atlassian.net/browse/AAASM-94) — S21: web-based governance dashboard
**Verified at master HEAD**: `92bcd046` (Merge PR #442 — file-op + policy-violation latency schema, 2026-05-14)
**Evidence captured by**: `dashboard/tests/e2e/verify-aaasm-94.spec.ts` (8 tests, all passing in 7.2 s)
**Sub-task closure state**: all 10 of AAASM-94's children are Done (token migration, overlay mount points, visual-regression coverage, page implementations).

## Scope

End-to-end verification of the dashboard Story as a coherent whole — confirms that all 12 canonical routes wire correctly, the shell remains mounted across navigations, global overlay surfaces are in place, login flows through to `/`, and the major cross-cut user journeys complete without regressions. Does not duplicate per-feature coverage; references existing specs where they already enforce the same contract.

## Cross-cutting health checks

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Unit + component tests | `pnpm test` | ✅ 97 files / 843 tests pass |
| Story-level e2e spec (this report) | `pnpm test:e2e tests/e2e/verify-aaasm-94.spec.ts` | ✅ 8 / 8 pass in 7.2 s |
| Inline hex audit | `grep -rE '#[0-9a-fA-F]{3,8}' src/ --include="*.ts*" --include="*.css" \| grep -v 'styles.css:'` | ✅ 0 hits — AC8 satisfied |

## AC bullet-by-bullet verification

Each AC bullet from AAASM-94 maps to either this spec, an existing per-feature spec, or a build-time / file-system check.

| # | AC bullet | Where verified | Status |
|---|---|---|---|
| AC1 | `pnpm dev` / `pnpm start` start dev server at `http://localhost:3000` | `package.json` scripts + `vite.config.ts` `server.port = 3000` (manual smoke; not in Playwright scope) | ✅ |
| AC2 | `pnpm serve` serves production build locally at `http://localhost:3000` | `package.json` `serve` script defines `--port 3000 --strictPort` (file-system check) | ✅ |
| AC3 | `pnpm build` produces optimised bundle with relative asset paths | Vite config + CI's "Dashboard build" job; bundles emit to `dist/` with `base: './'` | ✅ |
| AC4 | Dev server proxies `/api/*` to gateway (no CORS) | `vite.config.ts` `server.proxy['/api']` (manual smoke; not in Playwright scope) | ✅ |
| AC5 | Shell renders at `/` with sidebar, top nav, all 12 routes wired | This spec — test 1 `AC5: AppShell renders…` · evidence `01-shell-nav.png` | ✅ |
| AC6 | All 12 route stubs return `<ComingSoon>` (no 404s) | This spec — test 2 `AC6: every one of the 12 routes…` · evidence `02-all-routes-no-404.png` | ✅ |
| AC7 | Global overlay mount points at shell level | This spec — test 3 `AC7: global overlay mount points…` · evidence `03-overlay-mounts.png`. AAASM-1321 originally fixed this; spec now regression-guards it. | ✅ |
| AC8 | Design tokens fully extracted — no hard-coded colours / spacing / type sizes | `grep` audit (0 hits outside `styles.css`). AAASM-1322 / 1323 / 1407 / 1410 / 1411 / 1412 / 1413 / 1414 all Done. | ✅ |
| AC9 | Dashboard updates in real-time via WebSocket | `useLiveOpsStream` hook + Live Ops page (unit-tested in `src/features/liveOps/`); a Story-level WS smoke would need a richer mock — out of scope for this spec. | ✅ (covered elsewhere) |
| AC10 | Layout holds at 1280 px and 1920 px viewport widths | Covered by AAASM-1324 → `tests/e2e/responsive-viewport-visual.spec.ts` + the committed snapshots under `tests/e2e/responsive-viewport-visual.spec.ts-snapshots/`. | ✅ (existing coverage) |
| AC11 | `pnpm typecheck` and `pnpm lint` pass with zero errors | CI's "Dashboard (type-check + lint)" job. | ✅ |
| AC12 | `dashboard/README.md` documents `pnpm dev`, `pnpm serve`, and `aasm dashboard start` | File-system check — README enumerates the three entry points. | ✅ |

## Cross-cut integration flows

| Flow | Test | Evidence | Status |
|---|---|---|---|
| Login → `/` landing inside AppShell | `login flow: API key form → /approvals landing renders inside AppShell` | `04-login-landing.png` | ✅ |
| Topology → click node → "View trace" → shell-level trace drawer | `cross-cut: Topology → click node → "View trace" opens shell-level trace drawer` | `05-topology-to-trace-drawer.png` | ✅ |
| Fleet → click agent → AgentDetailDrawer overlays Fleet (nested route under `/agents`) | `cross-cut: Fleet → click agent → AgentDetail drawer opens over Fleet page` | `06-fleet-to-agent-detail.png` | ✅ |
| Teams → click team link → TeamDetail page | `cross-cut: Teams → click team link → TeamDetail page` | `07-teams-to-team-detail.png` | ✅ |
| Sidebar nav swap between two routes without remounting AppShell | `cross-cut: sidebar swaps Outlet between two routes without remounting AppShell` | `08-sidebar-route-swap.png` | ✅ |

## Existing per-feature e2e coverage (referenced, not re-tested)

The following specs already enforce per-feature contracts. The Story-level spec doesn't re-run them — CI's `Dashboard tests + coverage` job covers them collectively.

| Spec | What it covers |
|---|---|
| `governance-dashboard.spec.ts` | Login flow + canonical 12-nav rendering + per-section grouping |
| `verify-aaasm-1152.spec.ts` | S22 trace AC bullets (timeline, severity colours, payload modal, filter, export) |
| `verify-aaasm-1341.spec.ts` | S22 topology AC bullets (graph render, status colours, team grouping, view-trace pivot) |
| `trace-design-fidelity.spec.ts` | Trace UI hi-fi parity (step-card structure, severity tokens, modal proportions) |
| `topology-design-fidelity.spec.ts` | Topology UI hi-fi parity (status stripe tokens, size buckets, cluster outlines, budget bar thresholds) |
| `responsive-viewport-visual.spec.ts` | 1280 / 1920 viewport visual regression (AC10) |
| `alerts.spec.ts` / `analytics.spec.ts` / `capability.spec.ts` / `fleet.spec.ts` / `iam.spec.ts` / `onboarding-design-fidelity.spec.ts` / `policies.spec.ts` / `scrub-design-fidelity.spec.ts` / `teams.spec.ts` / `trace.spec.ts` | Per-page functional + design-fidelity coverage |

## Bug sub-tasks opened

None. All eight Story-level checks pass cleanly; the AC bullets that aren't directly observable in Playwright (AC1–4, AC11–12) are satisfied by build / config / file-system evidence.

## ComingSoon vs implemented breakdown

| # | Route | Path | Page | State |
|---|---|---|---|---|
| 01 | Overview | `/overview` | `<ComingSoon name="Overview" />` | stub (per AC6) |
| 02 | Fleet | `/agents` | `FleetPage` (with nested `:id` `AgentDetailPage` drawer) | implemented |
| 03 | Topology | `/topology` | `TopologyPage` | implemented |
| 04 | Live Ops | `/live` | `LiveOpsPage` | implemented |
| 05 | Alerts | `/alerts` | `AlertsPage` | implemented |
| 06 | Audit Log | `/audit` | `<ComingSoon name="Audit Log" />` | stub |
| 07 | Capability | `/capability` | `CapabilityPage` | implemented |
| 08 | Policy | `/policies` | `PoliciesPage` | implemented |
| 09 | Secret Scrubbing | `/scrub` | `ScrubPage` | implemented |
| 10 | Cost & Budget | `/costs` | `<ComingSoon name="Cost & Budget" />` | stub |
| 11 | Agent Groups | `/teams` | `TeamsPage` (with nested `:teamId` `TeamDetailPage`) | implemented |
| 12 | Members & Access | `/identity` | `IdentityPage` | implemented |

Three ComingSoon stubs (`Overview`, `Audit Log`, `Cost & Budget`) by design — covered by AC6 ("All 12 route stubs return a `<ComingSoon>` placeholder — no 404s") with the explicit understanding that the underlying pages ship in later Stories.

## Sign-off

- [x] AC5, AC6, AC7 directly tested by this spec
- [x] AC8 (design tokens) confirmed via `grep` (0 hex hits outside `styles.css`)
- [x] AC1–4, AC11–12 verified via build / config / file-system / CI evidence
- [x] AC9 covered by existing `useLiveOpsStream` unit tests + Live Ops spec
- [x] AC10 covered by AAASM-1324's `responsive-viewport-visual.spec.ts`
- [x] Five cross-cut integration flows all green
- [x] Eight evidence PNGs committed
- [x] Type check + full vitest suite + this spec all green at verification time
- [x] No bugs opened

**AAASM-94 is ready to transition to Done after this PR merges.**
