// AAASM-5044: Playwright verification for the two-pane Teams view — team list
// on the left and the selected team's detail cards (budget usage, approval
// routing, members) on the right, in light AND dark themes.
//
// Only the network is stubbed — the real app renders — so this exercises the
// two-pane end-to-end against the existing topology/cost/budget-tree/approvals
// endpoints. Artifacts land in verify/5044/. Run against a preview server on
// 4510 (started out-of-band so sibling servers are untouched):
//
//   pnpm exec playwright test --config playwright.5044.config.ts

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const TOPOLOGY_OVERVIEW = {
  root_agent_count: 2,
  standalone_root_agents: [],
  team_count: 2,
  total_agent_count: 4,
  teams: [
    { team_id: 'data-platform', agent_count: 3, root_agent_count: 1 },
    { team_id: 'growth', agent_count: 1, root_agent_count: 1 },
  ],
}

const COST_SUMMARY = {
  date: '2026-05-13',
  daily_spend_usd: '61.00',
  daily_limit_usd: '200.00',
  per_team: [
    { team_id: 'data-platform', date: '2026-05-13', daily_spend_usd: '48.00', monthly_spend_usd: null },
    { team_id: 'growth', date: '2026-05-13', daily_spend_usd: '13.00', monthly_spend_usd: null },
  ],
}

const BUDGET_TREE = {
  root: {
    id: 'acme-corp', label: 'acme-corp', kind: 'org', depth: 0, own_spend_usd: '0', subtree_spend_usd: '61.00', budget_limit_usd: '200',
    children: [
      { id: 'data-platform', label: 'data-platform', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '48.00', budget_limit_usd: '50', children: [] },
      { id: 'growth', label: 'growth', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '13.00', budget_limit_usd: '40', children: [] },
    ],
  },
}

const APPROVALS = {
  items: [
    { id: 'apr-1', action: 'net.egress', agent_id: 'a1', reason: 'call to api.stripe.com', created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T10:05:00Z', status: 'pending', team_id: 'data-platform', routing_status: { status: 'routed_to_team_admin', target_role: 'TeamAdmin', history: [] } },
    { id: 'apr-2', action: 'fs.write', agent_id: 'a2', reason: 'write /etc/hosts', created_at: '2026-05-13T09:40:00Z', expires_at: '2026-05-13T09:45:00Z', status: 'pending', team_id: 'data-platform', routing_status: { status: 'escalated_to_org_admin', target_role: 'OrgAdmin', history: [] } },
  ],
}

const DATA_PLATFORM_TEAM = {
  team_id: 'data-platform',
  agent_count: 3,
  members: [
    { id: 'a1', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce' },
    { id: 'a2', name: 'etl-worker', status: 'suspended', depth: 1, flagged: true, mode: 'shadow' },
    { id: 'a3', name: 'analytics-runner', status: 'active', depth: 1, flagged: false, mode: 'enforce' },
  ],
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'teams-e2e-token')
      localStorage.setItem('aa_team_admin', '1')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', r => r.abort())
  await page.route('**/api/v1/alerts/ws**', r => r.abort())
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: APPROVALS }))
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route('**/api/v1/topology/team/data-platform', r => r.fulfill({ json: DATA_PLATFORM_TEAM }))
  await page.route('**/api/v1/topology/team/growth', r => r.fulfill({ json: { team_id: 'growth', agent_count: 1, members: [{ id: 'g1', name: 'campaign-bot', status: 'active', depth: 0, flagged: false, mode: 'enforce' }] } }))
  // Playwright matches the LAST-registered route first: register the bare
  // /costs summary before the more specific budget-tree endpoint.
  await page.route('**/api/v1/costs**', r => r.fulfill({ json: COST_SUMMARY }))
  await page.route('**/api/v1/costs/budget-tree**', r => r.fulfill({ json: BUDGET_TREE }))
}

async function navToTeams(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/teams')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('teams-two-pane')).toBeVisible()
}

test.describe('AAASM-5044 — Teams two-pane detail cards', () => {
  for (const theme of THEMES) {
    test(`renders list + budget/approval/members cards in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToTeams(page)

      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)

      // Left pane: both teams listed.
      await expect(page.getByTestId('team-list-row')).toHaveCount(2)

      // Right pane defaults to the first team; all three cards render.
      await expect(page.getByTestId('team-detail-header')).toContainText('data-platform')
      await expect(page.getByTestId('team-budget-pct')).toContainText('96.0% used')
      await expect(page.getByTestId('team-approval-row')).toHaveCount(2)
      await expect(page.getByTestId('team-members-card')).toContainText('Members (3)')

      await page.getByTestId('teams-two-pane').screenshot({ path: `verify/5044/teams-two-pane-${theme}.png` })

      // Select the second team → detail updates.
      await page.getByTestId('team-list-row').filter({ hasText: 'growth' }).click()
      await expect(page.getByTestId('team-detail-header')).toContainText('growth')
      await expect(page.getByTestId('team-members-card')).toContainText('Members (1)')
      await expect(page.getByTestId('team-approval-empty')).toBeVisible()

      await page.getByTestId('teams-two-pane').screenshot({ path: `verify/5044/teams-two-pane-growth-${theme}.png` })
    })
  }
})
