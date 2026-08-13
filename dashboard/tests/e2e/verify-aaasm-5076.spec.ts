// AAASM-5076: Playwright verification for the restructured Costs page — the
// reconciled KPI strip (Daily / Monthly / Agents-tracked + Utilisation +
// Blocked), the daily-burn callout banner, the Per-agent / Per-team /
// Budget-tree tab bar, and the per-agent cost table — in light AND dark themes.
//
// Only the network is stubbed; the real app renders. Focused artifacts land in
// verify/parity-costs/. Run with:
//
//   pnpm exec playwright test --config playwright.costs-5076.config.ts

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// daily 192/200 = 96% → red critical callout + red Daily KPI; monthly 891/2500.
const COST_SUMMARY = {
  date: '2026-05-11',
  daily_spend_usd: '192.40',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3180.90',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'research-bot-04', daily_spend_usd: '78.20', date: '2026-05-11', monthly_spend_usd: '1420.40' },
    { agent_id: 'analytics-runner', daily_spend_usd: '52.10', date: '2026-05-11', monthly_spend_usd: '980.10' },
    { agent_id: 'infra-ops-bot', daily_spend_usd: '38.60', date: '2026-05-11', monthly_spend_usd: '540.30' },
    { agent_id: 'cx-triage-agent', daily_spend_usd: '17.30', date: '2026-05-11', monthly_spend_usd: '190.10' },
    { agent_id: 'idle-scout', daily_spend_usd: '6.20', date: '2026-05-11', monthly_spend_usd: '49.90' },
  ],
  per_team: [
    { team_id: 'data-platform', daily_spend_usd: '130.30', date: '2026-05-11', monthly_spend_usd: '2400.50' },
    { team_id: 'platform', daily_spend_usd: '38.60', date: '2026-05-11', monthly_spend_usd: '540.30' },
    { team_id: 'cx-tools', daily_spend_usd: '23.50', date: '2026-05-11', monthly_spend_usd: '240.00' },
  ],
}

const TOPOLOGY_OVERVIEW = {
  root_agent_count: 3,
  standalone_root_agents: [],
  team_count: 3,
  total_agent_count: 5,
  teams: [
    { team_id: 'data-platform', agent_count: 2, root_agent_count: 1 },
    { team_id: 'platform', agent_count: 1, root_agent_count: 1 },
    { team_id: 'cx-tools', agent_count: 2, root_agent_count: 1 },
  ],
}

function agentNode(id: string, team: string) {
  return {
    id,
    name: id,
    status: 'active',
    depth: 1,
    flagged: false,
    mode: 'enforce',
    team_id: team,
  }
}

// Backs the per-agent table's team column (resolved from GET /api/v1/topology).
const TOPOLOGY_GRAPH = {
  nodes: [
    agentNode('research-bot-04', 'data-platform'),
    agentNode('analytics-runner', 'data-platform'),
    agentNode('infra-ops-bot', 'platform'),
    agentNode('cx-triage-agent', 'cx-tools'),
    // idle-scout intentionally has no node → team renders as a dash.
  ],
  edges: [],
}

const COST_HISTORY = {
  days: 7,
  points: [
    { date: '2026-05-05', spend_usd: '138.20' },
    { date: '2026-05-06', spend_usd: '152.10' },
    { date: '2026-05-07', spend_usd: '135.80' },
    { date: '2026-05-08', spend_usd: '164.50' },
    { date: '2026-05-09', spend_usd: '181.20' },
    { date: '2026-05-10', spend_usd: '178.90' },
    { date: '2026-05-11', spend_usd: '192.40' },
  ],
}

const BUDGET_TREE = {
  root: {
    id: 'acme-corp',
    label: 'acme-corp',
    kind: 'org',
    depth: 0,
    budget_limit_usd: '250',
    own_spend_usd: '0',
    subtree_spend_usd: '192.40',
    children: [
      {
        id: 'data-platform',
        label: 'data-platform',
        kind: 'team',
        depth: 1,
        budget_limit_usd: '150',
        own_spend_usd: '0',
        subtree_spend_usd: '130.30',
        children: [
          {
            id: 'research-bot-04',
            label: 'research-bot-04',
            kind: 'agent',
            depth: 2,
            budget_limit_usd: '90',
            own_spend_usd: '78.20',
            subtree_spend_usd: '78.20',
            governance_level: 'L2Enforce',
            children: [],
          },
        ],
      },
    ],
  },
}

const COST_BREAKDOWN = {
  buckets: [
    {
      label: 'Today',
      segments: [
        { key: 'research-bot-04', name: 'research-bot-04', value: 78.2 },
        { key: 'analytics-runner', name: 'analytics-runner', value: 52.1 },
        { key: 'infra-ops-bot', name: 'infra-ops-bot', value: 38.6 },
        { key: 'cx-triage-agent', name: 'cx-triage-agent', value: 17.3 },
        { key: 'idle-scout', name: 'idle-scout', value: 6.2 },
      ],
    },
  ],
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
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
  await page.route('**/api/v1/analytics/cost-breakdown**', r => r.fulfill({ json: COST_BREAKDOWN }))
  // Playwright matches the LAST-registered route first: register the bare
  // /costs and /topology summaries before their more-specific siblings.
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route(/\/api\/v1\/topology(\?.*)?$/, r => r.fulfill({ json: TOPOLOGY_GRAPH }))
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

test.describe('AAASM-5076 — Costs FE parity (KPIs / callouts / tabs / per-agent table)', () => {
  for (const theme of THEMES) {
    test(`renders the restructured Costs page in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToCosts(page)

      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)

      // KPI strip: all five reconciled cards present.
      await expect(page.getByTestId('costs-kpi-daily')).toBeVisible()
      await expect(page.getByTestId('costs-kpi-monthly')).toBeVisible()
      await expect(page.getByTestId('costs-kpi-agents')).toBeVisible()
      await expect(page.getByTestId('costs-kpi-utilisation')).toBeVisible()
      await expect(page.getByTestId('costs-kpi-blocked')).toBeVisible()

      // Daily 96% → red critical callout.
      await expect(page.getByTestId('costs-callout-danger')).toBeVisible()

      // KPI strip + callout artifact.
      await page.getByTestId('costs-kpis').screenshot({
        path: `verify/parity-costs/kpis-${theme}.png`,
      })
      await page.getByTestId('costs-callout-danger').screenshot({
        path: `verify/parity-costs/callout-${theme}.png`,
      })

      // Default Per-agent tab: table with team column + the analytics breakdown.
      await expect(page.getByTestId('costs-tab-agents')).toHaveAttribute('aria-selected', 'true')
      const table = page.getByTestId('costs-agent-table')
      await expect(table).toBeVisible()
      await expect(table.locator('[data-agent="research-bot-04"]')).toContainText('data-platform')
      await table.scrollIntoViewIfNeeded()
      await table.screenshot({ path: `verify/parity-costs/per-agent-table-${theme}.png` })

      // Full page (KPIs + callout + history + tabs) artifact.
      await page.screenshot({ path: `verify/parity-costs/page-${theme}.png`, fullPage: true })

      // Per-team tab.
      await page.getByTestId('costs-tab-teams').click()
      await expect(page.getByTestId('costs-team-budgets')).toBeVisible()
      await expect(page.getByTestId('team-budget-bar').first()).toBeVisible()
      await page.getByTestId('costs-team-budgets').screenshot({
        path: `verify/parity-costs/per-team-${theme}.png`,
      })

      // Budget-tree tab.
      await page.getByTestId('costs-tab-tree').click()
      await expect(page.getByTestId('costs-budget-tree')).toBeVisible()
      await expect(page.getByTestId('budget-tree-grid')).toBeVisible()
      await page.getByTestId('costs-budget-tree').screenshot({
        path: `verify/parity-costs/budget-tree-${theme}.png`,
      })

      // Tab bar artifact (on the tree tab so the active state is captured).
      await page.getByTestId('costs-tabs').screenshot({
        path: `verify/parity-costs/tabs-${theme}.png`,
      })
    })
  }
})
