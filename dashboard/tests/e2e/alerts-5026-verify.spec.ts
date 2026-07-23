// AAASM-5026 — visual verification of the design-spec presentational surfaces
// added to /alerts: the 5-tile clickable stats strip, the severity-bordered
// card-feed view (with inline expand), and the derived category filter chips.
//
// Seeds a deterministic alert + rule fixture (rules carry distinct metrics so
// every derived category renders), authenticates via sessionStorage `aa_token`
// (the tokenStorage tier since AAASM-4322), and screenshots the strip + table
// and the card feed in both light and dark themes into verify/AAASM-5026/.
// Local visual gate only — not wired into any CI lane.

import { test, expect, type Page, type Route } from '@playwright/test'

const OUT = 'verify/AAASM-5026'
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

function rule(id: string, name: string, metric: string) {
  return {
    id,
    name,
    description: '',
    metric,
    operator: '>',
    threshold: 80,
    evaluationWindowSeconds: 300,
    severity: 'HIGH',
    destinationIds: [],
    dedupWindowSeconds: 600,
    suppressionLabels: {},
    enabled: true,
    createdAt: '2026-05-14T00:00:00Z',
    updatedAt: '2026-05-14T00:00:00Z',
  }
}

const RULES = [
  rule('r-budget', 'Budget guardrail', 'budget_spent_pct'),
  rule('r-policy', 'Policy violation spike', 'policy_violation_count'),
  rule('r-anomaly', 'Anomaly detector', 'anomaly_score'),
]

function alert(
  id: string,
  ruleId: string,
  ruleName: string,
  severity: string,
  status: string,
  agentId: string,
  firstFiredAt: string,
) {
  return { id, ruleId, ruleName, severity, status, agentId, firstFiredAt, resolvedAt: null, destinationIds: ['dst-slack'] }
}

const ALERTS = [
  alert('al-1', 'r-budget', 'Budget guardrail', 'CRITICAL', 'FIRING', 'agent-billing-01', '2026-05-14T09:00:00Z'),
  alert('al-2', 'r-policy', 'Policy violation spike', 'CRITICAL', 'FIRING', 'agent-research-04', '2026-05-14T08:30:00Z'),
  alert('al-3', 'r-policy', 'Policy violation spike', 'HIGH', 'FIRING', 'agent-support-02', '2026-05-14T08:00:00Z'),
  alert('al-4', 'r-anomaly', 'Anomaly detector', 'MEDIUM', 'SUPPRESSED', 'agent-ops-09', '2026-05-13T22:15:00Z'),
  alert('al-5', 'r-budget', 'Budget guardrail', 'LOW', 'FIRING', 'agent-batch-11', '2026-05-13T19:45:00Z'),
]

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'aaasm5026-verify-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/alerts/ws*', (r: Route) => r.abort())
  await page.route('**/api/v1/ws/events**', (r: Route) => r.abort())
  await page.route('**/api/v1/approvals**', (r: Route) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (r: Route) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/alerts/destinations*', (r: Route) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/alerts/rules**', (r: Route) => r.fulfill({ json: RULES }))
  // List endpoint returns a paginated { items, total } object (AAASM-4892).
  await page.route('**/api/v1/alerts*', (r: Route) => {
    const url = r.request().url()
    if (url.includes('/alerts/rules') || url.includes('/alerts/destinations') || url.includes('/alerts/ws')) {
      return r.fallback()
    }
    if (/\/alerts\/[a-zA-Z0-9-]+/.test(new URL(url).pathname)) return r.fallback()
    return r.fulfill({ json: { items: ALERTS, total: ALERTS.length } })
  })
}

test.describe('AAASM-5026 — alerts stats strip + card feed + category filters', () => {
  for (const theme of THEMES) {
    test(`renders the strip, table and card feed in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)

      await page.goto('/alerts')
      await expect(page.getByTestId('alerts-stats-strip')).toBeVisible()
      await expect(page.getByTestId('alerts-stat-count-CRITICAL')).toHaveText('2')
      await expect(page.getByTestId('alerts-table')).toBeVisible()
      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)
      await page.screenshot({ path: `${OUT}/${theme}-01-strip-and-table.png`, fullPage: true })

      // Switch to the severity card-feed view and screenshot it.
      await page.getByTestId('alerts-view-cards').click()
      await expect(page.getByTestId('alert-card-feed')).toBeVisible()
      await expect(page.getByTestId('alert-card').first()).toBeVisible()
      await page.screenshot({ path: `${OUT}/${theme}-02-card-feed.png`, fullPage: true })

      // Expand the first card to show the inline detail.
      await page.getByTestId('alert-card-toggle-al-1').click()
      await expect(page.getByTestId('alert-card-detail-al-1')).toBeVisible()
      await page.screenshot({ path: `${OUT}/${theme}-03-card-expanded.png`, fullPage: true })

      // Apply a derived category filter (budget) and screenshot the narrowed feed.
      await page.getByTestId('alerts-category-budget').click()
      await expect(page.getByTestId('alerts-count')).toHaveText('2 alerts')
      await page.screenshot({ path: `${OUT}/${theme}-04-category-budget.png`, fullPage: true })
    })
  }
})
