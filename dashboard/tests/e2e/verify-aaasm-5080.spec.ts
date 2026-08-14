// AAASM-5080 evidence capture: FE-parity for the Teams left-pane "unclaimed"
// orphan-agents section + count chip + the no-governance callout, per
// design/v1/hi-fi/teams.jsx. Reuses the real-app + network-stub approach from
// verify-aaasm-5044.spec.ts, seeding the topology overview with
// standalone_root_agents so the orphan section has content. Writes light+dark
// screenshots to verify/parity-teams/.
import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const TOPOLOGY_OVERVIEW = {
  root_agent_count: 4,
  team_count: 2,
  total_agent_count: 6,
  teams: [
    { team_id: 'data-platform', agent_count: 3, root_agent_count: 1 },
    { team_id: 'growth', agent_count: 1, root_agent_count: 1 },
  ],
  // Orphans: root agents with no team — drives the unclaimed section + callout.
  standalone_root_agents: [
    { id: 'o1', name: 'lonely-scraper', status: 'active', depth: 0, flagged: false, mode: 'off' },
    { id: 'o2', name: 'rogue-bot', status: 'suspended', depth: 0, flagged: true, mode: 'off' },
  ],
}
const COST_SUMMARY = {
  date: '2026-05-13', daily_spend_usd: '61.00', daily_limit_usd: '200.00',
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
const APPROVALS = { items: [] as unknown[] }
const DATA_PLATFORM_TEAM = {
  team_id: 'data-platform', agent_count: 3,
  members: [
    { id: 'a1', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce' },
    { id: 'a2', name: 'etl-worker', status: 'suspended', depth: 1, flagged: true, mode: 'shadow' },
    { id: 'a3', name: 'analytics-runner', status: 'active', depth: 1, flagged: false, mode: 'enforce' },
  ],
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript((opts: { key: string; theme: string }) => {
    sessionStorage.setItem('aa_token', 'teams-e2e-token')
    localStorage.setItem(opts.key, opts.theme)
  }, { key: THEME_KEY, theme })
}
async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', r => r.abort())
  await page.route('**/api/v1/alerts/ws**', r => r.abort())
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: APPROVALS }))
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route('**/api/v1/topology/team/data-platform', r => r.fulfill({ json: DATA_PLATFORM_TEAM }))
  await page.route('**/api/v1/topology/team/growth', r => r.fulfill({ json: { team_id: 'growth', agent_count: 1, members: [{ id: 'g1', name: 'campaign-bot', status: 'active', depth: 0, flagged: false, mode: 'enforce' }] } }))
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

test.describe('AAASM-5080 — Teams orphan / unclaimed section', () => {
  for (const theme of THEMES) {
    test(`orphan section + callout in ${theme}`, async ({ page }) => {
      const appErrors: string[] = []
      page.on('console', m => {
        if (m.type() !== 'error') return
        const t = m.text()
        if (!t.startsWith('Failed to load resource')) appErrors.push(t)
      })
      page.on('pageerror', e => appErrors.push(String(e)))

      await seed(page, theme)
      await mockBackend(page)
      await navToTeams(page)

      // Left pane: the unclaimed section with a count chip (2 orphans).
      await expect(page.getByTestId('team-list-orphan-section')).toBeVisible()
      await expect(page.getByTestId('team-list-orphan-count')).toHaveText('2')
      await page.getByTestId('teams-two-pane').screenshot({ path: `verify/parity-teams/teams-orphan-list-${theme}.png` })

      // Select the orphan section → detail pane swaps to the orphan view.
      await page.getByTestId('team-list-orphan-row').click()
      await expect(page.getByTestId('orphan-detail-callout')).toContainText('No governance applied')
      await expect(page.getByTestId('orphan-detail-agent-count')).toContainText('2 agents')
      await expect(page.getByTestId('orphan-agent-row')).toHaveCount(2)
      await page.getByTestId('teams-two-pane').screenshot({ path: `verify/parity-teams/teams-orphan-detail-${theme}.png` })

      expect(appErrors, `app/runtime console errors: ${appErrors.join(' | ')}`).toEqual([])
    })
  }
})
