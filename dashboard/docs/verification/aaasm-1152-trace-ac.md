# AAASM-1152 — Trace AC Verification Report

**Story**: [AAASM-95](https://lightning-dust-mite.atlassian.net/browse/AAASM-95) (S22 — Security engineer trace + violation highlights)
**Sub-task**: [AAASM-1152](https://lightning-dust-mite.atlassian.net/browse/AAASM-1152) — functional verification of the **trace half**
**Pairs with**: AAASM-1383 (trace design-fidelity) · AAASM-1341 (topology functional) · AAASM-1384 (topology design-fidelity)
**Verified at master HEAD**: `b255fb8a` (Merge PR #377, 2026-05-13)
**Evidence captured by**: `dashboard/tests/e2e/verify-aaasm-1152.spec.ts` (6 tests, all passing in 1.3s)

## Scope note

The original sub-task description said "verify AAASM-95 AC" (covers trace + topology). It has been re-scoped to the trace half only, since:

- Topology functional verification has its own sub-task **AAASM-1341**
- Topology implementation (AAASM-1333 / 1335 / 1337 / 1339 / 1340) is still in progress
- Design fidelity (visual comparison vs hi-fi prototype) is handled in **AAASM-1383** (trace) and **AAASM-1384** (topology)

## Cross-cutting health checks

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Unit + component tests | `pnpm test` | ✅ 65 files / 569 tests pass |
| Trace-specific E2E spec | `pnpm test:e2e tests/e2e/trace.spec.ts` | ✅ pass (1.6s, captured during AAASM-1071) |
| This evidence-capture spec | `pnpm test:e2e tests/e2e/verify-aaasm-1152.spec.ts` | ✅ 6 tests pass (1.3s) |

## AC bullet-by-bullet verification

Each row maps a parent-story AC bullet to the captured evidence file and a short observation.

| # | AC bullet (from AAASM-95) | Evidence | Observation | Status |
|---|---|---|---|---|
| 1 | Trace drawer shows complete session as vertical timeline of events | `aaasm-1152/01-timeline-full.png` | 4 mixed-severity events render as a vertical `<ol>` with the documented 5-column grid (time / icon / agent / preview / duration). Row order matches input order. | ✅ |
| 2 | Policy violations displayed with red background and violation reason tooltip | `aaasm-1152/02-policy-violation-tooltip.png` | `[data-event-type="policy_violation"]` row carries `data-severity="critical"` → resolves to `var(--danger-bg)`. Hovering the icon surfaces a `role="tooltip"` element with the exact `violationReason` text (`"refund > $100 requires human approval"`). | ✅ |
| 3 | Credential leak events highlighted with orange background | `aaasm-1152/03-credential-leak.png` | `[data-event-type="credential_leak"]` row keeps its underlying `data-severity="warning"` (so the filter can still find/hide it). CSS rule `.trace-event[data-event-type="credential_leak"]` forces `var(--warn-bg)` regardless of severity. | ✅ |
| 4 | Each event node shows: timestamp, event type, agent, duration, payload preview | `aaasm-1152/01-timeline-full.png` (annotated via row anatomy assertions in the spec) | First row asserts presence of `.trace-event__time`, `.trace-event__icon`, `.trace-event__agent`, `.trace-event__preview`, `.trace-event__duration` (with `ms`). Event-type is encoded as the icon glyph plus `data-event-type` attribute. | ✅ |
| 5 | Clicking an event expands full payload (redacted fields clearly marked) | `aaasm-1152/05-payload-modal-redacted.png` | Click on the policy-violation row opens `<PayloadModal>` with the pretty-printed JSON. The `user_id` line renders as `"<redacted: user_id>"` with a 🔒 icon and the "Redacted by policy" tooltip. Defensive check: the original value `4521` does **not** appear in the modal text. | ✅ |
| 6 | Filter bar allows hiding event types to focus on violations only | `aaasm-1152/06a-filter-before.png` · `aaasm-1152/06b-filter-after.png` | All 4 rows visible before. Unchecking Info + Neutral hides the `llm_call` and `tool_call` rows, leaving only the critical (policy violation) and warning (credential leak) rows. Filter state lives in the page; timeline stays presentational. | ✅ |
| 7 | Trace can be exported as JSON via "Export" button | `aaasm-1152/07-export-toolbar.png` · `aaasm-1152/07-export-trace.json` | Export button in the toolbar above the filter triggers a blob download named `trace-agent-aaasm-1152-session-aaasm-1152.json`. The downloaded file parses cleanly against `traceExportSchema` (zod). Includes all 4 events (filter is a view concern; export is a session artifact). | ✅ |

## Bug sub-tasks opened

None. All 7 trace-related AC bullets pass.

## Sign-off

- [x] All trace-half AC bullets satisfied
- [x] Evidence captured and committed
- [x] Type check + full test suite + trace E2E green at verification time
- [x] No bugs opened

AAASM-1152 can be transitioned to **Done** once this PR merges. The remaining sub-tasks under AAASM-95 are:

- **AAASM-1383** — trace design-fidelity (the visual side, this report's natural pair)
- AAASM-1333 → 1340 — topology implementation
- AAASM-1341 — topology functional verification (after impl)
- AAASM-1384 — topology design-fidelity verification (after impl)
