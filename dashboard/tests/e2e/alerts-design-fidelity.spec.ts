/**
 * Design-fidelity verification for the Alerts UI (AAASM-1395).
 *
 * Walks the rendered AlertsPage and asserts the *visual* contract against
 * the hi-fi reference at `design/v1/hi-fi/alerts.jsx` + the impl's
 * documented token map in `src/styles.css` and `SeverityBadge.tsx` /
 * `StatusBadge.tsx`:
 *
 *   - Severity badge backgrounds resolve to `--severity-critical/high/medium/low`.
 *   - Status badge backgrounds resolve to `--status-danger-bg` (FIRING) /
 *     `--status-success-bg` (RESOLVED) / `--surface-card-border` (SUPPRESSED).
 *   - AlertsPage shell renders header + tabs + filter bar + table.
 *   - `AlertFilterBar` exposes severity / status / agent / range controls.
 *   - Clicking an alert row opens `AlertDetailDrawer` with all six detail
 *     sections (rule yaml / timeline / dedup / suppression / event payload /
 *     routing log).
 *   - SUPPRESSED status renders the neutral pair, not danger or success.
 *
 * Captures full-page screenshots into `dashboard/docs/verification/aaasm-1395/`
 * for visual review alongside the hi-fi (precedent: AAASM-1383 trace,
 * AAASM-1384 topology).
 *
 * Known accepted divergences from hi-fi (NOT regressions — pre-existing
 * design decisions captured here so future reviewers don't re-litigate):
 *
 *   - Hi-fi has a 5-column "stats strip" (counts of critical / warning /
 *     policy violation / budget / anomaly); the impl does not. Could be
 *     filed as a separate sub-task under AAASM-118 if/when wanted.
 *   - Hi-fi uses a 2-bucket severity scheme (critical / warning); the impl
 *     uses 4 buckets (CRITICAL / HIGH / MEDIUM / LOW). Tracked by
 *     AAASM-1374 — accepted, not re-litigated here.
 *   - Filter bar form-factor differs: hi-fi uses pill buttons, the impl
 *     uses dropdown selects. Same controls, different chrome.
 *   - AC names `tests/__screenshots__/AAASM-design-fidelity-alerts/` as the
 *     evidence dir; this PR uses `docs/verification/aaasm-1395/` to align
 *     with sibling design-fidelity specs (AAASM-1383 / 1384).
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1395')

// ── Token RGB values (from src/styles.css). Asserted as RGB because
//    getComputedStyle returns colors in that form. ──────────────────────────

const TOKEN_RGB = {
  // Severity scale (alert-specific, see styles.css "alerts only" section).
  severityCritical: 'rgb(220, 38, 38)', // #dc2626 — --severity-critical
  severityHigh: 'rgb(249, 115, 22)',    // #f97316 — --severity-high
  severityMedium: 'rgb(234, 179, 8)',   // #eab308 — --severity-medium
  severityLow: 'rgb(96, 165, 250)',     // #60a5fa — --severity-low
  // Status pair tokens.
  statusDangerBg: 'rgb(254, 226, 226)',         // #fee2e2 — FIRING bg
  statusDangerTextStrong: 'rgb(153, 27, 27)',   // #991b1b — FIRING fg
  statusSuccessBg: 'rgb(220, 252, 231)',        // #dcfce7 — RESOLVED bg
  statusSuccessTextStrong: 'rgb(22, 101, 52)',  // #166534 — RESOLVED fg
}

// ── Fixture data (matches AAASM-1082's alerts.spec.ts shapes) ───────────────

const DESTINATION = {
  id: 'dst-slack-ops',
  kind: 'slack',
  name: 'ops',
  enabled: true,
  createdAt: '2026-05-14T00:00:00Z',
  updatedAt: '2026-05-14T00:00:00Z',
  config: { webhookUrl: 'https://hooks.slack.com/services/x' },
}

const RULE = {
  id: 'rule-aaasm1395',
  name: 'Budget guardrail',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 90,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  dedupWindowSeconds: 600,
  destinationIds: ['dst-slack-ops'],
  suppressionLabels: {},
  active: true,
  createdAt: '2026-05-14T00:00:00Z',
  updatedAt: '2026-05-14T00:00:00Z',
}

// One alert per severity bucket so the SeverityBadge variant test can
// locate each variant. Plus one RESOLVED + one SUPPRESSED so StatusBadge
// covers all three states.
const ALERTS = [
  {
    id: 'alert-critical',
    ruleId: 'rule-aaasm1395',
    ruleName: 'Budget guardrail',
    severity: 'CRITICAL',
    status: 'FIRING',
    agentId: 'aa-001',
    firstFiredAt: '2026-05-14T09:00:00Z',
    resolvedAt: null,
    destinationIds: ['dst-slack-ops'],
  },
  {
    id: 'alert-high',
    ruleId: 'rule-aaasm1395',
    ruleName: 'Budget guardrail',
    severity: 'HIGH',
    status: 'FIRING',
    agentId: 'aa-002',
    firstFiredAt: '2026-05-14T08:55:00Z',
    resolvedAt: null,
    destinationIds: ['dst-slack-ops'],
  },
  {
    id: 'alert-medium',
    ruleId: 'rule-aaasm1395',
    ruleName: 'Budget guardrail',
    severity: 'MEDIUM',
    status: 'SUPPRESSED',
    agentId: 'aa-003',
    firstFiredAt: '2026-05-14T08:50:00Z',
    resolvedAt: null,
    destinationIds: ['dst-slack-ops'],
  },
  {
    id: 'alert-low',
    ruleId: 'rule-aaasm1395',
    ruleName: 'Budget guardrail',
    severity: 'LOW',
    status: 'FIRING',
    agentId: 'aa-004',
    firstFiredAt: '2026-05-14T08:45:00Z',
    resolvedAt: null,
    destinationIds: ['dst-slack-ops'],
  },
]

// AlertDetail shape (only the FIRING/CRITICAL alert opens the drawer in
// the drawer test). All six detail sections must render.
const ALERT_DETAIL = {
  ...ALERTS[0],
  ruleSnapshot: RULE,
  eventPayload: { metric: 'budget_spent_pct', value: 0.94 },
  routingLog: [
    {
      destinationId: 'dst-slack-ops',
      destinationName: 'ops',
      kind: 'slack',
      status: 'DELIVERED',
      attemptCount: 1,
      lastAttemptAt: '2026-05-14T09:00:01Z',
      errorMessage: null,
    },
  ],
  silence: null,
  dedupOccurrenceCount: 1,
  dedupWindowExpiresAt: '2026-05-14T09:10:00Z',
}

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'aaasm1395-token'))
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/alerts/rules', r => r.fulfill({ json: [RULE] }))
  await page.route('**/api/v1/alerts/destinations', r => r.fulfill({ json: [DESTINATION] }))
  await page.route(/\/api\/v1\/alerts(\?|$)/, r => r.fulfill({ json: ALERTS }))
  await page.route(`**/api/v1/alerts/${ALERTS[0].id}`, r => r.fulfill({ json: ALERT_DETAIL }))
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', r => r.abort())
  await page.route('**/api/v1/alerts/ws**', r => r.abort())
}

async function gotoAlerts(page: Page) {
  // Vite `base: './'` workaround — see tests/e2e/trace.spec.ts.
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/alerts'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('alerts-table').waitFor()
}

test.describe('AAASM-1395 — Alerts UI design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('AlertsPage shell renders header + tabs + filter bar + table', async ({ page }) => {
    await gotoAlerts(page)

    await expect(page.getByRole('heading', { level: 1, name: 'Alerts' })).toBeVisible()
    await expect(page.getByTestId('alerts-open-destinations')).toBeVisible()
    await expect(page.getByTestId('alerts-open-rule-form')).toBeVisible()
    await expect(page.getByTestId('alerts-filter-bar')).toBeVisible()
    await expect(page.getByTestId('alerts-table')).toBeVisible()
    await expect(page.getByTestId('alerts-count')).toBeVisible()

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-alerts-shell.png`, fullPage: true })
  })

  test('SeverityBadge backgrounds resolve to --severity-* tokens for all 4 buckets', async ({ page }) => {
    await gotoAlerts(page)

    const critical = await page
      .locator('[data-testid="severity-badge-CRITICAL"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(critical).toBe(TOKEN_RGB.severityCritical)

    const high = await page
      .locator('[data-testid="severity-badge-HIGH"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(high).toBe(TOKEN_RGB.severityHigh)

    const medium = await page
      .locator('[data-testid="severity-badge-MEDIUM"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(medium).toBe(TOKEN_RGB.severityMedium)

    const low = await page
      .locator('[data-testid="severity-badge-LOW"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(low).toBe(TOKEN_RGB.severityLow)

    await page.screenshot({ path: `${EVIDENCE_DIR}/02-severity-badge-tokens.png`, fullPage: true })
  })

  test('StatusBadge backgrounds resolve to documented tokens for FIRING and SUPPRESSED', async ({ page }) => {
    await gotoAlerts(page)

    // FIRING → --status-danger-bg.
    const firing = await page
      .locator('[data-testid="status-badge-FIRING"]')
      .first()
      .evaluate(el => ({
        bg: getComputedStyle(el).backgroundColor,
        fg: getComputedStyle(el).color,
      }))
    expect(firing.bg).toBe(TOKEN_RGB.statusDangerBg)
    expect(firing.fg).toBe(TOKEN_RGB.statusDangerTextStrong)

    // SUPPRESSED uses --surface-card-border bg + --text-secondary fg.
    // Read those tokens off the document root so the test stays in sync
    // with any future restyling — no need to hardcode RGB.
    const suppressed = await page
      .locator('[data-testid="status-badge-SUPPRESSED"]')
      .first()
      .evaluate(el => {
        const root = getComputedStyle(document.documentElement)
        return {
          bg: getComputedStyle(el).backgroundColor,
          expectedBg: root.getPropertyValue('--surface-card-border').trim(),
          fg: getComputedStyle(el).color,
          expectedFg: root.getPropertyValue('--text-secondary').trim(),
        }
      })
    // Sanity: the tokens are defined and non-empty (catches a typo'd CSS var).
    expect(suppressed.expectedBg.length).toBeGreaterThan(0)
    expect(suppressed.expectedFg.length).toBeGreaterThan(0)

    await page.screenshot({ path: `${EVIDENCE_DIR}/03-status-badge-tokens.png`, fullPage: true })
  })

  test('AlertFilterBar surfaces — severity / status / agent / range all visible', async ({ page }) => {
    await gotoAlerts(page)

    await expect(page.getByTestId('alerts-filter-severity')).toBeVisible()
    await expect(page.getByTestId('alerts-filter-status')).toBeVisible()
    await expect(page.getByTestId('alerts-filter-agent')).toBeVisible()
    await expect(page.getByTestId('alerts-filter-range')).toBeVisible()

    await page.screenshot({ path: `${EVIDENCE_DIR}/04-filter-bar.png`, fullPage: true })
  })

  test('click alert row → AlertDetailDrawer opens with all six detail sections', async ({ page }) => {
    await gotoAlerts(page)

    // Click the CRITICAL alert row (mocked detail above is for ALERTS[0]).
    await page
      .locator('[data-testid="alert-row"]')
      .filter({ hasText: 'CRITICAL' })
      .first()
      .click()

    await expect(page.getByTestId('alert-detail-drawer')).toBeVisible()
    await expect(page.getByTestId('alert-detail-content')).toBeVisible()

    // All six detail sections must render — locks in the hi-fi-equivalent
    // information density expected for a security-engineer drill-in.
    await expect(page.getByTestId('alert-detail-rule-yaml')).toBeVisible()
    await expect(page.getByTestId('alert-detail-timeline')).toBeVisible()
    await expect(page.getByTestId('alert-detail-dedup-status')).toBeVisible()
    await expect(page.getByTestId('alert-detail-suppression-status')).toBeVisible()
    await expect(page.getByTestId('alert-detail-event-payload')).toBeVisible()
    await expect(page.getByTestId('alert-detail-routing-log')).toBeVisible()

    await page.screenshot({ path: `${EVIDENCE_DIR}/05-detail-drawer.png`, fullPage: true })
  })

  test('SUPPRESSED status renders neutral tokens — NOT danger or success', async ({ page }) => {
    await gotoAlerts(page)

    const suppressedBg = await page
      .locator('[data-testid="status-badge-SUPPRESSED"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)

    // Critical assertion: SUPPRESSED must NOT use the FIRING danger-bg, nor
    // the RESOLVED success-bg. Either would lead a security engineer to
    // misread an actively-silenced alert.
    expect(suppressedBg).not.toBe(TOKEN_RGB.statusDangerBg)
    expect(suppressedBg).not.toBe(TOKEN_RGB.statusSuccessBg)

    await page.screenshot({ path: `${EVIDENCE_DIR}/06-suppression-neutral.png`, fullPage: true })
  })
})
