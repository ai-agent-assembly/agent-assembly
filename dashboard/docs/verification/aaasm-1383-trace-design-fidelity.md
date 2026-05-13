# AAASM-1383 — Trace UI Design-Fidelity Report

**Story**: [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95) (S22 — Security engineer trace + violation highlights)
**Sub-task**: [AAASM-1383](https://lightning-dust-mite.atlassian.net/browse/AAASM-1383) — design-fidelity verification (trace UI)
**Pairs with**: AAASM-1152 (functional AC verification, merged) · AAASM-1341 (topology functional, pending) · AAASM-1384 (topology design-fidelity, pending)
**Hi-fi reference**: `agent-assembly/design/v1/hi-fi/trace.jsx` + `agent-assembly/design/v1/hi-fi/styles.css`
**Verified at master HEAD**: `ab42c754` (PR #382 merge)
**Evidence captured by**: `dashboard/tests/e2e/trace-design-fidelity.spec.ts` (6 tests, all passing in 1.5s)

## Token alignment (source-of-truth check)

The dashboard's `dashboard/src/styles.css` and the hi-fi's `design/v1/hi-fi/styles.css` declare the **exact same CSS variables with the exact same hex values**:

| Token | Hex | Used for |
|---|---|---|
| `--paper` | `#f5f4f0` | neutral row background |
| `--paper-2` | `#ffffff` | modal body / panel background |
| `--paper-3` | `#ebe9e2` | skeleton row background |
| `--danger-bg` | `#f6dad6` | critical severity row background |
| `--danger` | `#b8291e` | critical severity border / accent |
| `--warn-bg` | `#f5e6c4` | warning severity + credential-leak row background |
| `--warn` | `#8a5a00` | warning border / accent |
| `--info-bg` | `#d6dfee` | info severity row background |
| `--info` | `#1d3a7a` | info border / accent |

The fidelity assertions below resolve the *rendered* `getComputedStyle().backgroundColor` to the exact RGB equivalent of these tokens, so any drift between the two `styles.css` files would surface here.

## Fidelity checks

Each row maps a fidelity dimension to the spec assertion and the captured evidence file.

| # | Fidelity dimension | Assertion | Evidence | Status |
|---|---|---|---|---|
| 1 | Severity backgrounds resolve to hi-fi token RGB | `getComputedStyle(row).backgroundColor` equals `rgb(214, 223, 238)` for info, `rgb(246, 218, 214)` for critical, `rgb(245, 230, 196)` for credential leak (event-type override), `rgb(245, 244, 240)` for neutral | `aaasm-1383/01-severity-tokens.png` | ✅ |
| 2 | Row grid layout has 5 columns | `getComputedStyle(row).gridTemplateColumns` splits to 5 tracks (`9rem 1.5rem 8rem 1fr 5rem`); first cell has `.trace-event__time`, last cell has `.trace-event__duration` | `aaasm-1383/02-row-grid.png` | ✅ |
| 3 | PayloadModal proportions within hi-fi constraints | Modal `width` ≤ 720px (content-box) / ≤ 722px (incl. 2px borders); `height` ≤ 80vh; redacted line uses `--warn-bg` background | `aaasm-1383/03-payload-modal-proportions.png` | ✅ |
| 4 | Export toolbar above the filter, right-aligned | Toolbar `y` is less than filter `y` (toolbar is above); `getComputedStyle(toolbar).justifyContent` equals `flex-end` | `aaasm-1383/04-toolbar-position.png` | ✅ |
| 5 | Filter-empty state uses shared `<EmptyState>` component | `data-testid="trace-filter-empty"` wraps an element with `data-testid="empty-state"`; visible text contains `"All events hidden by filter"` | `aaasm-1383/05-filter-empty-state.png` | ✅ |
| 6 | Policy violation tooltip surfaces the violation reason | Hover on `.trace-event__icon` of `[data-event-type="policy_violation"]` opens `role="tooltip"` element with exact text `"refund > $100 requires human approval"` | `aaasm-1383/06-violation-tooltip.png` | ✅ |

All 6 fidelity dimensions pass. Token resolution is byte-exact with the hi-fi.

## Divergence flagged — bug sub-task opened

| Divergence | Severity | Tracking |
|---|---|---|
| **Per-event visual layout**: row-grid (current) vs vertical step-card (hi-fi). Hi-fi `.trc-step` renders icon + connecting line on the left and body (label / detail / meta) on the right. Current dashboard renders a flat horizontal row with 5 cells. | Medium (visual divergence, no functional impact) | **[AAASM-1391](https://lightning-dust-mite.atlassian.net/browse/AAASM-1391)** — Bug sub-task opened under AAASM-95 with proposed fix and AC checklist |

This divergence was inherited from AAASM-1067 (the timeline implementation sub-task) and slipped past functional-AC review because every functional bullet still passes. The new design-fidelity workflow (per `feedback_ui_ticket_design_fidelity_followup` memory rule) is designed to surface exactly this kind of visual-only gap.

## Cross-cutting health

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Lint | `pnpm lint` | ✅ pass (0 warnings, 0 errors) |
| Design-fidelity spec | `pnpm test:e2e tests/e2e/trace-design-fidelity.spec.ts` | ✅ 6 tests pass (1.5s) |

## Sign-off

- [x] Token-level fidelity verified — all severity backgrounds resolve to hi-fi token RGB
- [x] Layout-level fidelity verified — row grid, modal proportions, toolbar position match documented contracts
- [x] State coverage — screenshots captured for 6 representative UI states
- [x] Divergence flagged with bug sub-task (AAASM-1391) for the row-grid vs step-card visual gap

AAASM-1383 can be transitioned to **Done** once this PR merges. The trace half of AAASM-95 is then complete for functional + design-fidelity verification, with one visual-polish follow-up tracked in AAASM-1391.
