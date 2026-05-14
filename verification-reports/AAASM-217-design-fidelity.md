# Design-fidelity verification — AAASM-217 (Fleet + Agent Detail)

> Companion to AAASM-1151's functional AC verification. This one cross-checks
> the *rendered visual design* against the hi-fi prototype the design team
> approved (`design/v1/hi-fi/fleet.jsx`, `design/v1/hi-fi/agent-detail.jsx`,
> `design/v1/hi-fi/styles.css`).
>
> Evidence captured by `dashboard/tests/e2e/fleet-design-fidelity.spec.ts` —
> run via `cd dashboard && pnpm test:e2e fleet-design-fidelity` to regenerate
> the PNGs under `verification-reports/AAASM-217-design-fidelity/`.
>
> Viewport: 1280×800 (hi-fi reference).

## Summary

| Surface | Verdict |
|---|---|
| Fleet page-head | ✅ Matches |
| Fleet view tabs | ✅ Matches |
| Fleet filter bar | ✅ Matches |
| Fleet table chrome (11 columns + sticky thead) | ✅ Matches |
| Fleet flagged row tint | ✅ Matches |
| Fleet bulk action bar (4 buttons) | ✅ Matches |
| Agent Detail drawer panel (580 px) | ✅ Matches |
| Agent Detail identity strip (5-column grid) | ✅ Matches |
| Agent Detail tab navigation (6 tabs) | ✅ Matches |
| Agent Detail Overview tab (posture + traffic + events) | ✅ Matches |
| Agent Detail follow-up tab empty-states | ✅ Matches |
| Suspend reason dialog | ✅ Matches |
| **AppShell topbar stacks above Agent Detail drawer head** | **✅ Fixed (AAASM-1405)** |

All 11 in-scope surfaces fully match the hi-fi prototype after the
AAASM-1405 fix.

## Findings

### ✅ AppShell topbar overlaps Agent Detail drawer head — FIXED (AAASM-1405)

> *Original finding, resolved.* The drawer now paints cleanly above the
> AppShell topbar; the regenerated `00-detail-fullpage.png` and
> `07-detail-head.png` show the breadcrumb / title / action buttons fully
> visible with the scrim covering the topbar.

**Original symptom.** The Drawer primitive (`dashboard/src/components/Drawer.tsx`)
declared its scrim with `position: fixed; inset: 0; z-index: 50`, but the
AppShell topbar painted in front of the drawer's top ~52 px:

* Breadcrumb (`← fleet › <id>`) and agent name title in the drawer head were
  hidden behind the topbar
* The `■ suspend` / `▶ resume` action buttons were obscured — Playwright
  reported `header.appshell__topbar intercepts pointer events` on click
* The original `00-detail-fullpage.png` showed the white topbar sitting in
  front of the drawer panel's top section

**Root cause.** A stacking-context boundary in the AppShell tree contained
the scrim's `position: fixed`, so its `z-index: 50` was compared only
within that contained context rather than at the root.

**Fix (AAASM-1405)**:

1. `Drawer.tsx` now renders via `ReactDOM.createPortal(tree, document.body)`,
   so the scrim becomes a direct child of `<body>` and escapes any AppShell
   stacking context entirely. SSR / non-DOM test renderers fall back to
   in-tree rendering.
2. `Drawer.css` bumps the scrim to `z-index: 1000` (was 50) so it
   comfortably outranks anything inside `#root` at the new root-level
   comparison.

**Verification.** Re-running `pnpm test:e2e fleet-design-fidelity` after
the fix: all 11 tests pass with a real `await page.getByTestId('agent-detail-suspend').click()`
— no more `evaluate(el => el.click())` workaround. The regenerated
screenshots (`00-detail-fullpage.png`, `07-detail-head.png`) show the drawer
correctly painted above the topbar with no overlap.

## Per-section walkthrough

Each section below pairs the rendered screenshot with the hi-fi reference
(file + line range) and records the verdict + rationale.

### 01 — Fleet page-head

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/fleet.jsx` lines 154-170 |
| **Tokens** | `--paper-2` background, 22 px title, `--ink-4` counter suffix |
| **Implementation** | `dashboard/src/pages/FleetPage.tsx` lines 337-356 |
| **Screenshot** | `AAASM-217-design-fidelity/01-fleet-page-head.png` |
| **Verdict** | ✅ Matches |

Title font-size is `22px` exactly. Counter renders `N of M agents` with the
muted suffix style. Both stub action buttons (`+ register agent`, `⏏ export
csv`) render and are correctly disabled.

### 02 — Fleet view tabs

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/fleet.jsx` lines 173-185 |
| **Tokens** | Active tab `border-bottom: 2px solid var(--ink)`; inactive transparent |
| **Implementation** | `FleetPage.tsx` lines 359-381 |
| **Screenshot** | `02-fleet-view-tabs.png` |
| **Verdict** | ✅ Matches |

Asserted: active tab's `border-bottom-color` resolves to the `--ink` token
RGB. Inactive tab's bottom-border color is *not* `--ink` (transparent).
Counter chip on the active tab uses the dark variant per hi-fi.

### 03 — Fleet filter bar

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/fleet.jsx` lines 188-220 |
| **Implementation** | `dashboard/src/pages/FleetFilterBar.tsx` |
| **Screenshot** | `03-fleet-filter-bar.png` |
| **Verdict** | ✅ Matches |

All four control groups render in hi-fi order: search input → framework
segmented buttons → status segmented buttons → flagged-only checkbox.
Active segment uses `--ink` background; framework values derived from live
data.

### 04 — Fleet table chrome

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/fleet.jsx` lines 222-277 |
| **Tokens** | Sticky thead `background: var(--paper-2)`; sort indicators ▲ / ▼ / ↕ |
| **Implementation** | `FleetPage.tsx` columns array (lines 95-176) |
| **Screenshot** | `04-fleet-table-chrome.png` |
| **Verdict** | ✅ Matches |

11 header cells (select / agent / framework / owner / mode / status / trust
/ blocked 24h / scrubbed 24h / last seen / actions) render in hi-fi order.
Sort indicator data-testids present for the 8 sortable columns. Header
background resolves to `--paper-2` (sticky thead chrome).

### 05 — Fleet flagged row

| | |
|---|---|
| **Hi-fi** | `fleet.jsx` line 247 — `rgba(184, 41, 30, 0.04)` flagged-row tint |
| **Implementation** | `dashboard/src/pages/FleetPage.css` `.fleet-table__row--flagged` |
| **Screenshot** | `05-fleet-flagged-row.png` |
| **Verdict** | ✅ Matches |

`gamma-bot` (mocked with `policy_violations_count: 75`) renders with the
flagged modifier. Background RGBA matches the hi-fi tint exactly. The note
under the agent name (`pending policy review`) and the red flag-dot prefix
render as expected.

### 06 — Fleet bulk action bar

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/fleet.jsx` lines 212-219 (+ bulk-Resume from AAASM-1151) |
| **Tokens** | `■ suspend` uses `--danger`; others use `--paper-2` |
| **Implementation** | `FleetPage.tsx` lines 402-440 |
| **Screenshot** | `06-fleet-bulkbar.png` |
| **Verdict** | ✅ Matches |

Bar appears with select-all clicked. All four buttons render: `→ shadow
mode`, `■ suspend`, `▶ resume`, `clear`. Suspend button's `background-color`
resolves to the `--danger` RGB token. `N selected` counter present.

> Note: the hi-fi prototype shows only Suspend + Shadow + Clear. Bulk Resume
> was added in AAASM-1151 as a structural mirror of bulk Suspend; the
> verification report for AAASM-1151 covers that scope addition.

### 07 — Agent Detail drawer head

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/agent-detail.jsx` lines 200-220 |
| **Implementation** | `AgentDetailPage.tsx` lines 205-260 |
| **Screenshot** | `07-detail-head.png` |
| **Verdict** | ✅ Matches (AAASM-1405 portal fix + AAASM-1409 button group landed) |

The head's structural elements all render in the correct hi-fi order:

* Breadcrumb `← fleet › <id>` (left)
* Flag dot (when `policy_violations_count ≥ FLEET_FLAGGED_THRESHOLD`)
* Title with agent name + framework chip + owner @-handle
* Three-button action group (right): `⎈ trace last call` · `→ shadow mode`
  · `■ suspend` / `▶ resume` (status-conditional)

Two earlier deltas have been resolved:

* **AAASM-1405** — the AppShell topbar no longer obscures the drawer head
  (Drawer portalled to `document.body`, `z-index: 1000`).
* **AAASM-1409** — the trace + shadow buttons that were missing from the
  original sub-task implementation are now present and wired to toasts.
  Real wiring (navigation to the trace page, gateway mode-change mutation)
  is deferred to follow-up Stories.

### 08 — Agent Detail identity strip

| | |
|---|---|
| **Hi-fi** | `design/v1/hi-fi/agent-detail.jsx` lines 222-248 |
| **Tokens** | 5-column grid (1.2fr 1fr 1fr 1fr 1fr); `--ink-4` labels |
| **Implementation** | `AgentDetailPage.tsx` lines 47-105 |
| **Screenshot** | `08-detail-identity-strip.png` |
| **Verdict** | ✅ Matches |

Asserted: `grid-template-columns` resolves to 5 tracks. DID renders
`did:agent:alice:agent-design-01` (using `metadata.owner` per spec). Trust
gauge SVG ring renders; mode + status chips render side-by-side. Blocked
+ scrubbed metrics render as `—` because the analytics endpoint is not
wired (documented deferred item).

### 09 — Agent Detail tab navigation

| | |
|---|---|
| **Hi-fi** | `agent-detail.jsx` lines 251-262 |
| **Implementation** | `AgentDetailPage.tsx` lines 264-281 |
| **Screenshot** | `09-detail-tabs.png` |
| **Verdict** | ✅ Matches |

6 tabs (`Overview / Capability / Traffic / Policies / Lineage / Config`)
render with `role="tablist"`. Overview is default-active with the bottom-
border accent.

### 10 — Agent Detail Overview tab

| | |
|---|---|
| **Hi-fi** | `agent-detail.jsx` lines 266-310 |
| **Implementation** | `AgentDetailPage.tsx` lines 287-340 |
| **Screenshot** | `10-detail-overview.png` |
| **Verdict** | ✅ Matches |

Two-column card layout (posture summary + traffic mix) above the full-
width recent events card. 4 posture mini-bars (Allow / Narrow / Deny /
Approval) render with the documented tone palette. Traffic mix shows the
placeholder segmented bar pointing at the follow-up. Recent events card
falls back to the empty-state message because `useAgentEventsQuery` was
mocked with `[]`.

### 11 — Agent Detail follow-up tab empty-states

| | |
|---|---|
| **Hi-fi** | (no hi-fi reference — empty-state per AAASM-1052 sub-task scope) |
| **Implementation** | `AgentDetailPage.tsx` `<TabEmpty>` component (lines 116-124) |
| **Screenshot** | `11-detail-tab-empty.png` |
| **Verdict** | ✅ Matches (intentional empty-state) |

Capability / Traffic / Policies / Lineage / Config tabs render the
follow-up callout pointing at the existing dashboard surfaces (Capability
page AAASM-1280, etc.). Layout matches the AAASM-1052 sub-task scope call.

### 12 — Suspend reason dialog

| | |
|---|---|
| **Hi-fi** | (no specific hi-fi modal reference — standard hi-fi modal token palette) |
| **Implementation** | `dashboard/src/components/SuspendReasonDialog.tsx` |
| **Screenshot** | `12-suspend-dialog.png` |
| **Verdict** | ✅ Matches |

Dialog renders centered with the scrim. Confirm button is disabled when
the textarea is empty, enabled once the reason is non-empty. Cancel +
Confirm both render with the design-system button styling (`--danger`
variant on Confirm).

## CI

This spec runs as part of the dashboard e2e stage (`pnpm test:e2e`). 11
tests, all passing locally in the worktree.

## Reproducibility

```bash
cd dashboard
pnpm install
pnpm exec playwright install chromium
pnpm build
pnpm test:e2e fleet-design-fidelity
# Screenshots regenerate under verification-reports/AAASM-217-design-fidelity/
```

## Next steps

1. ~~**File Bug Sub-task** under AAASM-217 for the topbar / drawer stacking
   issue~~ — Done as AAASM-1405; fix landed in this PR.
2. **Optional**: add `playwright-percy` or `pixelmatch` for automated
   regression coverage on these screenshots; currently the report is the
   human verification surface.
3. **Optional**: extend the spec to a second viewport (1920×1080) matching
   the precedent set by `capability-design-fidelity.spec.ts`.
