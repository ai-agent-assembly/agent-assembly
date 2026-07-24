// AAASM-5032: Playwright verification for the Costs page 7-day spend-history
// bar chart and the org → team → agent budget-inheritance tree, in light AND
// dark themes.
//
// Only the network is stubbed — the real app renders — so this exercises both
// components end-to-end against the new GET /api/v1/costs/history and
// /api/v1/costs/budget-tree endpoints through the fixture harness. Focused
// artifacts land in verify/5032/. Run with:
//
//   pnpm exec playwright test verify-aaasm-5032

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const COST_HISTORY = {
  days: 7,
  points: [
    { date: '2026-05-05', spend_usd: '38.20' },
    { date: '2026-05-06', spend_usd: '42.10' },
    { date: '2026-05-07', spend_usd: '35.80' },
    { date: '2026-05-08', spend_usd: '44.50' },
    { date: '2026-05-09', spend_usd: '51.20' },
    { date: '2026-05-10', spend_usd: '48.90' },
    { date: '2026-05-11', spend_usd: '47.80' },
  ],
}

const BUDGET_TREE = {
  root: {
    id: 'acme-corp',
    label: 'acme-corp',
    kind: 'org',
    depth: 0,
    budget_limit_usd: '100',
    own_spend_usd: '0',
    subtree_spend_usd: '47.82',
    children: [
      {
        id: 'data-platform',
        label: 'data-platform',
        kind: 'team',
        depth: 1,
        budget_limit_usd: '50',
        own_spend_usd: '0',
        subtree_spend_usd: '25.26',
        children: [
          {
            id: 'research-bot-04',
            label: 'research-bot-04',
            kind: 'agent',
            depth: 2,
            budget_limit_usd: '20',
            own_spend_usd: '9.50',
            subtree_spend_usd: '14.22',
            governance_level: 'L2Enforce',
            children: [
              {
                id: 'etl-worker-01',
                label: 'etl-worker-01',
                kind: 'agent',
                depth: 3,
                budget_limit_usd: '8',
                own_spend_usd: '3.22',
                subtree_spend_usd: '3.22',
                governance_level: 'L2Enforce',
                children: [],
              },
            ],
          },
          {
            id: 'analytics-runner',
            label: 'analytics-runner',
            kind: 'agent',
            depth: 2,
            budget_limit_usd: '13',
            own_spend_usd: '11.04',
            subtree_spend_usd: '11.04',
            governance_level: 'L3Native',
            children: [],
          },
        ],
      },
      {
        id: 'platform',
        label: 'platform',
        kind: 'team',
        depth: 1,
        budget_limit_usd: '25',
        own_spend_usd: '0',
        subtree_spend_usd: '10.22',
        children: [
          {
            id: 'infra-ops-bot',
            label: 'infra-ops-bot',
            kind: 'agent',
            depth: 2,
            budget_limit_usd: '15',
            own_spend_usd: '7.91',
            subtree_spend_usd: '7.91',
            governance_level: 'L3Native',
            children: [],
          },
        ],
      },
    ],
  },
}

const COST_SUMMARY = {
  date: '2026-05-11',
  daily_spend_usd: '47.82',
  daily_limit_usd: '100.00',
  monthly_spend_usd: '891.44',
  monthly_limit_usd: '2500.00',
  per_agent: [
    { agent_id: 'research-bot-04', daily_spend_usd: '14.22', date: '2026-05-11', monthly_spend_usd: '287.40' },
  ],
  per_team: [{ team_id: 'data-platform', daily_spend_usd: '25.26', date: '2026-05-11', monthly_spend_usd: '486.12' }],
}

const TOPOLOGY_OVERVIEW = {
  root_agent_count: 2,
  standalone_root_agents: [],
  team_count: 2,
  total_agent_count: 3,
  teams: [
    { team_id: 'data-platform', agent_count: 2, root_agent_count: 1 },
    { team_id: 'platform', agent_count: 1, root_agent_count: 1 },
  ],
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      // Auth token lives in sessionStorage (AAASM-4322); theme in localStorage.
      sessionStorage.setItem('aa_token', 'costs-e2e-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', r => r.abort())
  await page.route('**/api/v1/alerts/ws**', r => r.abort())
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', r => r.fulfill({ status: 404, json: { detail: 'No active policy' } }))
  await page.route('**/api/v1/policies', r => (r.request().method() === 'GET' ? r.fulfill({ json: [] }) : r.fallback()))
  await page.route(/\/api\/v1\/agents(\?.*)?$/, r => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/alerts**', r => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route('**/api/v1/analytics/cost-breakdown**', r => r.fulfill({ json: { buckets: [] } }))
  // Playwright matches the LAST-registered route first, so the bare /costs
  // summary is registered before the more specific endpoints under test — those
  // then take precedence for /costs/history and /costs/budget-tree.
  await page.route('**/api/v1/costs**', r => r.fulfill({ json: COST_SUMMARY }))
  await page.route('**/api/v1/costs/history**', r => r.fulfill({ json: COST_HISTORY }))
  await page.route('**/api/v1/costs/budget-tree**', r => r.fulfill({ json: BUDGET_TREE }))
}

async function navToCosts(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/costs')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('costs-page')).toBeVisible()
}

test.describe('AAASM-5032 — Costs history + budget-inheritance tree', () => {
  for (const theme of THEMES) {
    test(`renders history chart and budget tree in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToCosts(page)

      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)

      const history = page.getByTestId('costs-history')
      await expect(page.getByTestId('costs-history-chart')).toBeVisible()
      await history.scrollIntoViewIfNeeded()
      await history.screenshot({ path: `verify/5032/costs-history-${theme}.png` })

      const tree = page.getByTestId('budget-tree')
      await expect(page.getByTestId('budget-tree-grid')).toBeVisible()
      // Expand a sub-agent so the nested inheritance is visible in the artifact.
      await page.getByTestId('budget-toggle-research-bot-04').click()
      await expect(page.getByTestId('budget-node-etl-worker-01')).toBeVisible()
      await tree.scrollIntoViewIfNeeded()
      await tree.screenshot({ path: `verify/5032/budget-tree-${theme}.png` })
    })
  }
})
