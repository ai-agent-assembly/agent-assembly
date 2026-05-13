import { test, expect } from '@playwright/test'

async function injectToken(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

// ── Fixtures ───────────────────────────────────────────────────────────────────

const AGENT = {
  id: 'agent-e2e-001',
  name: 'E2E Agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 3,
  policy_violations_count: 0,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search'],
  recent_events: [],
}

const KPI = { value: 5, delta: 0.1 }

const ACTION_VOLUME = {
  series: [{ key: 'allowed', name: 'Allowed', points: [{ t: 1746000000, value: 100 }] }],
}

const COST_BREAKDOWN = {
  buckets: [{ label: '2026-05-12', segments: [{ key: 'gpt-4', name: 'GPT-4', value: 10.5 }] }],
}

const POLICY_EFFECTIVENESS = {
  rules: [{ id: 'r1', name: 'Rule 1', days: [{ date: '2026-05-12', blocks: 2, warns: 1, passes: 10 }] }],
}

const TOOL_USAGE = {
  tools: [{ name: 'search', calls: 100, errorRate: 0.02 }],
}

const FLEET_HEALTH = {
  agents: [{ id: 'agent-e2e-001', name: 'E2E Agent', points: [{ t: 1746000000, score: 95 }] }],
}

const APPROVAL_ANALYTICS = {
  volume: 1240,
  medianTta: 185,
  approvalRate: 0.874,
  byOutcome: { approved: 1083, rejected: 124, expired: 33 },
}

// ── Helper ─────────────────────────────────────────────────────────────────────

async function routeAnalyticsApis(page: import('@playwright/test').Page) {
  await page.route('/api/v1/agents**', route => route.fulfill({ json: [AGENT] }))
  await page.route('/api/v1/topology/overview', route =>
    route.fulfill({
      json: { teams: [{ team_id: 'team-alpha', agent_count: 2, root_agent_count: 1 }] },
    }),
  )
  await page.route('/api/v1/analytics/kpis**', route => route.fulfill({ json: KPI }))
  await page.route('/api/v1/analytics/action-volume**', route =>
    route.fulfill({ json: ACTION_VOLUME }),
  )
  await page.route('/api/v1/analytics/cost-breakdown**', route =>
    route.fulfill({ json: COST_BREAKDOWN }),
  )
  await page.route('/api/v1/analytics/policy-effectiveness**', route =>
    route.fulfill({ json: POLICY_EFFECTIVENESS }),
  )
  await page.route('/api/v1/analytics/tool-usage**', route =>
    route.fulfill({ json: TOOL_USAGE }),
  )
  await page.route('/api/v1/analytics/fleet-health**', route =>
    route.fulfill({ json: FLEET_HEALTH }),
  )
  await page.route('/api/v1/analytics/approvals**', route =>
    route.fulfill({ json: APPROVAL_ANALYTICS }),
  )
}

// ── Analytics page ─────────────────────────────────────────────────────────────

test.describe('Analytics page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await routeAnalyticsApis(page)
  })

  test('renders all 7 panel containers', async ({ page }) => {
    await page.goto('/analytics')
    await expect(page.getByTestId('kpi-agents')).toBeVisible()
    await expect(page.getByTestId('action-volume-panel')).toBeVisible()
    await expect(page.getByTestId('cost-breakdown-panel')).toBeVisible()
    await expect(page.getByTestId('policy-effectiveness-panel')).toBeVisible()
    await expect(page.getByTestId('tool-usage-panel')).toBeVisible()
    await expect(page.getByTestId('fleet-health-panel')).toBeVisible()
    await expect(page.getByTestId('approval-analytics-panel')).toBeVisible()
  })

  test('date-range change updates URL to ?range=30d', async ({ page }) => {
    await page.goto('/analytics')
    await page.getByTestId('filter-range').selectOption('30d')
    await expect(page).toHaveURL(/[?&]range=30d/)
  })

  test('agent filter selection adds agents param to URL', async ({ page }) => {
    await page.goto('/analytics')
    await page.getByTestId('filter-agents').selectOption('agent-e2e-001')
    await expect(page).toHaveURL(/[?&]agents=agent-e2e-001/)
  })

  test('filters are restored from URL on page reload', async ({ page }) => {
    await page.goto('/analytics?range=30d&agents=agent-e2e-001')
    await expect(page.getByTestId('filter-range')).toHaveValue('30d')
  })

  test('cost-breakdown group-by toggle updates URL to costBy=team', async ({ page }) => {
    await page.goto('/analytics')
    await page.getByTestId('cost-breakdown-toggle-team').click()
    await expect(page).toHaveURL(/[?&]costBy=team/)
  })
})
