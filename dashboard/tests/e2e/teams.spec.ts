import { test, expect, type Page } from '@playwright/test'

async function injectAuth(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
    localStorage.setItem('aa_team_admin', '1')
  })
}

const TEAM_MEMBERS = [
  { id: '11111111111111111111111111111111', name: 'orchestrator', status: 'active', depth: 0, team_id: 'team-alpha' },
  { id: '22222222222222222222222222222222', name: 'worker-1', status: 'active', depth: 1, team_id: 'team-alpha' },
  { id: '33333333333333333333333333333333', name: 'worker-2', status: 'active', depth: 1, team_id: 'team-alpha' },
]

const OVERVIEW = {
  team_count: 1,
  total_agent_count: 3,
  root_agent_count: 1,
  standalone_root_agents: [],
  teams: [{ team_id: 'team-alpha', agent_count: 3, root_agent_count: 1 }],
}

const COSTS = {
  date: '2026-05-13',
  daily_spend_usd: '120.00',
  daily_limit_usd: '200.00',
  per_team: [{ team_id: 'team-alpha', date: '2026-05-13', daily_spend_usd: '42.00', monthly_spend_usd: null }],
}

const LINEAGE = {
  agent_id: '11111111111111111111111111111111',
  ancestor_count: 1,
  ancestors: [{ id: '11111111111111111111111111111111', name: 'orchestrator', depth: 0 }],
}

test.describe('Teams flow', () => {
  test('list → drill → suspend → resume', async ({ page }) => {
    await injectAuth(page)

    let memberStatus: 'active' | 'suspended' = 'active'

    await page.route('**/api/v1/topology/overview', route => route.fulfill({ json: OVERVIEW }))
    await page.route('**/api/v1/costs', route => route.fulfill({ json: COSTS }))
    await page.route('**/api/v1/topology/team/team-alpha', route =>
      route.fulfill({
        json: { team_id: 'team-alpha', agent_count: 3, members: TEAM_MEMBERS.map(m => ({ ...m, status: memberStatus })) },
      }),
    )
    await page.route(/\/api\/v1\/topology\/lineage\/[0-9a-f]+/, route => route.fulfill({ json: LINEAGE }))
    await page.route(/\/api\/v1\/agents\/[0-9a-f]+\/suspend/, route => {
      memberStatus = 'suspended'
      route.fulfill({ status: 200, json: {} })
    })
    await page.route(/\/api\/v1\/agents\/[0-9a-f]+\/resume/, route => {
      memberStatus = 'active'
      route.fulfill({ status: 200, json: {} })
    })

    await page.goto('/teams')
    await expect(page.getByTestId('teams-table')).toBeVisible()
    await page.getByRole('link', { name: 'team-alpha' }).click()

    await expect(page.getByTestId('team-detail-header')).toBeVisible()
    await expect(page.getByTestId('team-member-row')).toHaveCount(3)

    await page.getByTestId('team-suspend-btn').click()
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await page.getByTestId('confirm-ok').click()
    await expect(page.getByTestId('team-member-status').first()).toHaveText('suspended')

    await page.getByTestId('team-resume-btn').click()
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await page.getByTestId('confirm-ok').click()
    await expect(page.getByTestId('team-member-status').first()).toHaveText('active')
  })
})
