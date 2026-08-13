# AAASM-4817 — Explicit `type` on `<button>` (SonarCloud S9011)

Behaviour-preservation validation for the fix that adds an explicit `type`
attribute to 27 `<button>` elements the `typescript:S9011` rule flagged.

## Why the fix is behaviour-relevant

A `<button>` with no `type` defaults to `type="submit"`. Inside a `<form>` that
implicitly submits the form (page reload / navigation). All 27 flagged buttons
are **action buttons** (they carry an `onClick` that toggles state, mutates data,
navigates via the router, or opens a dialog) and **none of them sit inside a
`<form>`** — verified: `grep '<form'` returns nothing across the 12 touched
files. Every one therefore received `type="button"`. No button received
`type="submit"` because none is the submit control of a form. No `onClick`,
styling, or layout was changed.

## Playwright screenshot evidence (Approvals + AppShell)

Captured against `vite preview` (production build of this branch) with the
backend stubbed via `page.route` and an auth JWT seeded into `sessionStorage`
(post-AAASM-4322 the token lives in `sessionStorage`, not `localStorage`).

| File | Proves |
|---|---|
| `01-approvals-loaded.png` | App boots on this build; AppShell nav + Log out (L129), tabs (L124/127), filter bar render; 2 pending rows |
| `02-bulk-toolbar-visible.png` | Row checkbox reveals the bulk toolbar (Approve/Reject selected, L261/271) |
| `03-reject-dialog-open.png` | Clicking **Reject selected** (`type="button"`) opens the reject dialog — Cancel (L71) + Confirm reject (L77) — **URL stayed stable, no form submit / reload** |
| `04-decided-tab.png` | Clicking the **Decided** tab (`type="button"`) switches tab — URL stable |

The capture script asserted `url before === url after` at each click; had any
button defaulted to submit, a navigation/reload would have broken the stable-URL
assertion and the subsequent `waitFor`. All assertions passed (`CAPTURE_OK`).

## Primary behaviour proof — vitest component tests

The dashboard's vitest suite (`pnpm test`) is the authoritative behaviour proof:
**168 files, 1491 tests, all green** after the change. Every one of the 12 touched
components has a co-located test that clicks its buttons via `@testing-library`
`user-event`:

| Component | Test file | Button click coverage |
|---|---|---|
| ApprovalsPage | `src/pages/ApprovalsPage.test.tsx` | tabs, bulk approve/reject, row approve/reject, dialog cancel/confirm |
| TeamsPage | `src/pages/TeamsPage.test.tsx` | retry, prev/next pagination |
| TeamDetailPage | `src/pages/TeamDetailPage.test.tsx` | suspend/resume, confirm dialog, open-in-topology |
| AppShell | `src/components/AppShell.test.tsx` | hamburger, logout, error-boundary "Try again" |
| AgentDetailPage | `src/pages/AgentDetailPage.test.tsx` | retry |
| FleetPage | `src/pages/FleetPage.test.tsx` | retry (bulkbar clear already had `type`) |
| TopologyPage | `src/pages/TopologyPage.test.tsx` | retry |
| TraceViewPage | `src/pages/TraceViewPage.test.tsx` | retry |
| ViolationHeatmap | `src/components/__tests__/ViolationHeatmap.test.tsx` | "Show all" |
| ExpiredApprovalsSection | `src/features/approvals/ExpiredApprovalsSection.test.tsx` | expand/collapse toggle |
| ServiceIdentitiesPanel | `src/features/iam/ServiceIdentitiesPanel.test.tsx` | (defensive hidden escape button) |
| ApprovalsFilterBar | `src/features/approvals/ApprovalsFilterBar.test.tsx` | clear filters |

## Playwright e2e lane — infra dependency (not run here)

The `tests/e2e/*.spec.ts` functional lane could not run headless in this
environment. `hitl-approval.spec.ts` boots a **real Rust `aa-api` gateway
fixture**; the network-stubbed specs (`teams.spec`, `fleet.spec`, `trace.spec`,
`approvals-expired.spec`) seed auth via the **legacy `localStorage` key** that
AAASM-4322 deliberately stopped honouring, so they redirect to `/login` — this
was confirmed to fail **identically on the pristine base branch** (changes
stashed), i.e. it is a pre-existing environment dependency, not a regression
from this change. Per the ticket's fallback, the vitest suite above is the
behaviour proof and the four screenshots above are the browser-level evidence.
