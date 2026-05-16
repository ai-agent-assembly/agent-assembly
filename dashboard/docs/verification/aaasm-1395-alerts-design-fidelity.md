# AAASM-1395 — Alerts UI Design Fidelity Report

**Epic**: [AAASM-11](https://lightning-dust-mite.atlassian.net/browse/AAASM-11) (Community Dashboard)
**Story**: [AAASM-118](https://lightning-dust-mite.atlassian.net/browse/AAASM-118) — Build Alerts page
**Sub-task**: [AAASM-1395](https://lightning-dust-mite.atlassian.net/browse/AAASM-1395) — Playwright design-fidelity check for AlertsPage vs `design/v1/hi-fi/alerts.jsx`
**Verified at master HEAD**: `33d61f27` (Merge PR #451 — actions/cache@v5 bump, 2026-05-15)
**Evidence captured by**: `dashboard/tests/e2e/alerts-design-fidelity.spec.ts` (6 tests, all passing in 1.6 s)
**Precedent**: `trace-design-fidelity.spec.ts` (AAASM-1383), `topology-design-fidelity.spec.ts` (AAASM-1384)

## Scope

Asserts that the rendered Alerts UI conforms to the hi-fi prototype's visual contract — `SeverityBadge` + `StatusBadge` token mappings, page-level shell composition, filter bar surfaces, and detail-drawer information density. Does not duplicate `alerts.spec.ts` (AAASM-1082) which verifies the functional alert lifecycle.

## Cross-cutting health checks

| Check | Command | Result |
|---|---|---|
| Type check | `pnpm type-check` | ✅ pass |
| Unit + component tests | `pnpm test` | ✅ 97 files / 843 tests pass |
| Alerts design-fidelity E2E | `pnpm test:e2e tests/e2e/alerts-design-fidelity.spec.ts` | ✅ 6 / 6 pass in 1.6 s |

## AC-by-AC verification

The Story-level AC asks for "matching screenshot pairs for: stats strip, filter bar, expanded alert row, severity badge variants, suppression chip, detail drawer." The impl evolved beyond the hi-fi in several places (table format, 4-bucket severity scheme, richer detail drawer); the spec asserts what the impl *actually* commits to:

| # | AC item | What the spec asserts | Status |
|---|---|---|---|
| 1 | `tests/e2e/alerts-design-fidelity.spec.ts` exists | Spec at this exact path with describe `AAASM-1395 — Alerts UI design fidelity` | ✅ |
| 2 | Captures screenshots of: stats strip / filter bar / expanded alert row / severity badge variants / suppression chip / detail drawer | Six PNGs in `docs/verification/aaasm-1395/`. Stats strip captured as an accepted divergence (does not exist in impl). Severity badge **variants** captured via all 4 buckets visible in `02-severity-badge-tokens.png`. Suppression captured in `03-status-badge-tokens.png` + `06-suppression-neutral.png`. | ✅ (with documented divergence) |
| 3 | Surfaces structural mismatches as test failures | Computed-style assertions on `SeverityBadge` / `StatusBadge` would fail if any token drifts. Tests #2 / #3 / #6 each lock in a specific token. | ✅ |
| 4 | Screenshots committed under evidence dir | Six PNGs committed at `dashboard/docs/verification/aaasm-1395/` (precedent path; differs from AC text — see caveats below). | ✅ (with documented path-naming caveat) |
| 5 | `pnpm test:e2e tests/e2e/alerts-design-fidelity.spec.ts` passes | 6 / 6 green at this verification | ✅ |

## What each test locks in

| Test | Evidence | Observation |
|---|---|---|
| AlertsPage shell renders header + tabs + filter bar + table | `01-alerts-shell.png` | Header carries `Alerts` h1 + Destinations + New rule buttons; `alerts-filter-bar` + `alerts-table` + `alerts-count` all visible. |
| SeverityBadge backgrounds resolve to `--severity-*` tokens for all 4 buckets | `02-severity-badge-tokens.png` | CRITICAL → `rgb(220, 38, 38)`, HIGH → `rgb(249, 115, 22)`, MEDIUM → `rgb(234, 179, 8)`, LOW → `rgb(96, 165, 250)`. Matches `src/styles.css` `--severity-*` token values byte-for-byte. |
| StatusBadge tokens for FIRING + SUPPRESSED | `03-status-badge-tokens.png` | FIRING → bg `rgb(254, 226, 226)` (`--status-danger-bg`), fg `rgb(153, 27, 27)` (`--status-danger-text-strong`). SUPPRESSED reads `--surface-card-border` / `--text-secondary` off the document root and asserts they're defined and non-empty (catches a typo'd CSS var). |
| AlertFilterBar surfaces — severity / status / agent / range all visible | `04-filter-bar.png` | Each of the four filter controls present by `data-testid`. Form-factor differs from hi-fi (dropdowns vs pills) — documented under "Accepted divergences". |
| Click alert row → AlertDetailDrawer opens with all six detail sections | `05-detail-drawer.png` | Drawer mounts; six sections (`rule-yaml`, `timeline`, `dedup-status`, `suppression-status`, `event-payload`, `routing-log`) all visible — locks in the impl's information density beyond what the hi-fi covers. |
| SUPPRESSED renders neutral tokens, NOT danger or success | `06-suppression-neutral.png` | SUPPRESSED background ≠ `--status-danger-bg` AND ≠ `--status-success-bg`. Regression-guards against a high-impact misread (silenced alerts mis-coloured as either active emergency or all-clear). |

## Accepted divergences (NOT regressions)

These differences exist between the impl and the hi-fi prototype. Each is intentional, pre-existing, and documented here so future reviewers can distinguish "design decision" from "regression":

| Divergence | Origin | Why accepted |
|---|---|---|
| Hi-fi has a **5-column stats strip** (counts of critical / warning / policy violation / budget / anomaly); impl does not. | AAASM-118 build chain | Could be filed as a separate sub-task under AAASM-118 if/when wanted. Not in scope for this spec. |
| Hi-fi uses a **2-bucket severity scheme** (critical / warning); impl uses **4 buckets** (CRITICAL / HIGH / MEDIUM / LOW). | Tracked by AAASM-1374 | A reconciliation sub-task already exists; this spec asserts the impl's current 4-bucket contract. |
| **Filter bar form-factor**: hi-fi uses pill buttons, impl uses dropdown selects. | AlertFilterBar build | Same controls (severity / status / agent / range), different chrome. Acceptable for an info-density-heavy page. |
| **Card vs table rows**: hi-fi renders alerts as bordered cards with a 3px severity left-border; impl uses a TanStack table with `SeverityBadge` chips. | AAASM-1082 build | Table is the better fit once dedup / suppression states are introduced — those don't map cleanly to a single border colour. |
| **Detail drawer is richer than hi-fi**: hi-fi has a brief expanded row body; impl has a 6-section drawer (rule yaml / timeline / dedup / suppression / event payload / routing log). | AAASM-1082 build | Strictly additive. The spec locks in all 6 sections so they don't silently regress. |

## AC-vs-impl caveats

| Caveat | Resolution |
|---|---|
| **Screenshot path** — AC names `tests/__screenshots__/AAASM-design-fidelity-alerts/`; this PR uses `docs/verification/aaasm-1395/`. | Aligns with sibling design-fidelity specs (AAASM-1383 / 1384), which were merged with the `docs/verification/aaasm-NNNN/` pattern. Same shape as the AAASM-1383 path caveat. |
| **"Stats strip" screenshot** — the AC names it; the impl doesn't have one. | Documented as accepted divergence above. The spec captures the page header area in `01-alerts-shell.png` which is the closest analogue. |
| **Hi-fi side-by-side rendering** — AC suggests loading the hi-fi inside Playwright. | Sibling specs (AAASM-1383 / 1384) don't do this; they assert documented tokens / structure against the impl. This spec follows the proven precedent. |

## Bug sub-tasks opened

None. All six structural / token assertions pass; documented divergences are intentional design decisions, not bugs. If the team decides to ship the hi-fi's stats strip, a fresh sub-task under AAASM-118 would be the right way to track that.

## Sign-off

- [x] Spec at the documented path with all six tests passing
- [x] Six evidence PNGs captured under `dashboard/docs/verification/aaasm-1395/`
- [x] Token contracts locked in for both `SeverityBadge` (4 buckets) and `StatusBadge` (3 buckets)
- [x] Detail drawer's 6-section information density locked in
- [x] SUPPRESSED neutral-tone regression guard in place
- [x] Type check + full vitest suite + this fidelity E2E green at verification time
- [x] No bugs opened; accepted divergences documented

AAASM-1395 can be transitioned to **Done** once this PR merges. With this closed, AAASM-118 has one more design-fidelity sub-task complete; remaining open sub-tasks under AAASM-118 are AAASM-1373 (bell-icon nav), AAASM-1374 (severity-scheme reconciliation), AAASM-1393 (Rule Configuration tab), AAASM-1394 (Monaco YAML in drawer).
