import { test, expect, type Page } from '@playwright/test'

// A real 3-part JWT carrying an admin-scoped `scope` claim. Team management
// (the ActionBar Suspend/Resume controls) is gated on `useCanManageTeam()` →
// `useCan('admin')` since AAASM-5253, and scopes are recovered from the token's
// `scope` claim via `parseScopesFromJwt`. This grants team-admin through the
// same verified-scope machinery as production — never the removed
// client-writable `aa_team_admin` flag.
const b64url = (o: object) =>
  Buffer.from(JSON.stringify(o)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
const ADMIN_JWT = `${b64url({ alg: 'none' })}.${b64url({ sub: 'e2e-admin', scope: ['read', 'write', 'admin'] })}.sig`

async function injectAuth(page: Page) {
  await page.addInitScript((token) => {
    sessionStorage.setItem('aa_token', token)
  }, ADMIN_JWT)
}

const TEAM_MEMBERS = [
  { id: '11111111111111111111111111111111', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce', team_id: 'team-alpha' },
  { id: '22222222222222222222222222222222', name: 'worker-1', status: 'active', depth: 1, flagged: false, mode: 'enforce', team_id: 'team-alpha' },
  { id: '33333333333333333333333333333333', name: 'worker-2', status: 'active', depth: 1, flagged: false, mode: 'enforce', team_id: 'team-alpha' },
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

const BUDGET_TREE = {
  root: {
    id: 'org', label: 'acme-corp', kind: 'org', depth: 0, own_spend_usd: '0', subtree_spend_usd: '42.00', budget_limit_usd: '200',
    children: [
      { id: 'team-alpha', label: 'team-alpha', kind: 'team', depth: 1, own_spend_usd: '0', subtree_spend_usd: '42.00', budget_limit_usd: '100', children: [] },
    ],
  },
}

const APPROVALS = {
  items: [
    { id: 'apr-1', action: 'net.egress', agent_id: '11111111111111111111111111111111', reason: 'external call', created_at: '2026-05-13T10:00:00Z', expires_at: '2026-05-13T10:05:00Z', status: 'pending', team_id: 'team-alpha', routing_status: { status: 'routed_to_team_admin', target_role: 'TeamAdmin', history: [] } },
  ],
}

const LINEAGE = {
  agent_id: '11111111111111111111111111111111',
  ancestor_count: 1,
  ancestors: [{ id: '11111111111111111111111111111111', name: 'orchestrator', depth: 0 }],
}

async function stubTeamsApi(page: Page, memberStatusRef: { value: 'active' | 'suspended' }) {
  await page.route('**/api/v1/topology/overview', route => route.fulfill({ json: OVERVIEW }))
  // The whole fleet, which is what the unclaimed section is derived from since
  // AAASM-5157 — every agent here is claimed, so that section stays empty.
  await page.route('**/api/v1/topology', route => route.fulfill({ json: { nodes: TEAM_MEMBERS, edges: [] } }))
  await page.route('**/api/v1/costs', route => route.fulfill({ json: COSTS }))
  await page.route('**/api/v1/costs/budget-tree', route => route.fulfill({ json: BUDGET_TREE }))
  await page.route('**/api/v1/approvals**', route => route.fulfill({ json: APPROVALS }))
  await page.route('**/api/v1/topology/team/team-alpha', route =>
    route.fulfill({
      json: { team_id: 'team-alpha', agent_count: 3, members: TEAM_MEMBERS.map(m => ({ ...m, status: memberStatusRef.value })) },
    }),
  )
  await page.route(/\/api\/v1\/topology\/lineage\/[0-9a-f]+/, route => route.fulfill({ json: LINEAGE }))
  await page.route(/\/api\/v1\/agents\/[0-9a-f]+\/suspend/, route => {
    memberStatusRef.value = 'suspended'
    route.fulfill({ status: 200, json: {} })
  })
  await page.route(/\/api\/v1\/agents\/[0-9a-f]+\/resume/, route => {
    memberStatusRef.value = 'active'
    route.fulfill({ status: 200, json: {} })
  })
}

test.describe('Teams two-pane', () => {
  test('list selects a team → detail cards render', async ({ page }) => {
    await injectAuth(page)
    await stubTeamsApi(page, { value: 'active' })

    await page.goto('/teams')

    // Two-pane shell with the team list and the default-selected detail.
    await expect(page.getByTestId('teams-two-pane')).toBeVisible()
    await expect(page.getByTestId('team-list-row')).toHaveCount(1)
    await page.getByTestId('team-list-row').click()

    await expect(page.getByTestId('team-detail-header')).toContainText('team-alpha')
    await expect(page.getByTestId('team-budget-card')).toBeVisible()
    await expect(page.getByTestId('team-budget-pct')).toContainText('42.0% used')
    await expect(page.getByTestId('team-approval-card')).toBeVisible()
    await expect(page.getByTestId('team-approval-routing')).toContainText('TeamAdmin')
    await expect(page.getByTestId('team-members-card')).toContainText('Members (3)')
    await expect(page.getByTestId('team-member-row')).toHaveCount(3)
  })

  test('full detail drill → suspend → resume', async ({ page }) => {
    await injectAuth(page)
    const memberStatus = { value: 'active' as 'active' | 'suspended' }
    await stubTeamsApi(page, memberStatus)

    await page.goto('/teams')
    await page.getByTestId('team-open-full-detail').click()

    await expect(page.getByTestId('team-detail-header')).toBeVisible()
    await expect(page.getByTestId('team-member-row')).toHaveCount(3)

    await page.getByTestId('team-suspend-btn').click()
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await page.getByTestId('confirm-dialog-confirm').click()
    await expect(page.getByTestId('team-member-status').first()).toHaveText('suspended')

    await page.getByTestId('team-resume-btn').click()
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await page.getByTestId('confirm-dialog-confirm').click()
    await expect(page.getByTestId('team-member-status').first()).toHaveText('active')
  })
})
