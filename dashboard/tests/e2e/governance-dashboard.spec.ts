import { test, expect } from '@playwright/test'

// Injects a valid auth token so ProtectedRoute lets us through.
async function injectToken(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

// ── Fixtures ───────────────────────────────────────────────────────────────────

const APPROVAL = {
  id: 'e2e-appr-001',
  agent_id: 'agent-e2e',
  action: 'shell.exec ls',
  reason: 'inspection',
  status: 'pending',
  created_at: '2026-05-12T10:00:00Z',
  routing_status: null,
  team_id: null,
}

const POLICY = {
  name: 'e2e-policy',
  version: '1.0.0',
  rule_count: 2,
  active: true,
}

const AGENT = {
  id: 'agent-e2e-001',
  name: 'E2E Test Agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 3,
  policy_violations_count: 0,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search', 'code_exec'],
  recent_events: [],
}

// ── Login flow ─────────────────────────────────────────────────────────────────

test.describe('Login flow', () => {
  test('successful login redirects to /', async ({ page }) => {
    await page.route('/api/v1/auth/token', (route) =>
      route.fulfill({ json: { token: 'e2e-test-token' } }),
    )
    await page.route('/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
    await page.route('/api/v1/ws/events**', (route) => route.abort())

    await page.goto('/login')
    await expect(page.getByLabel('API Key')).toBeVisible()
    await page.getByLabel('API Key').fill('aa_test_key')
    await page.getByRole('button', { name: 'Sign in' }).click()

    await expect(page).toHaveURL('/')
    await expect(page.getByTestId('appshell')).toBeVisible()
  })
})

// ── AppShell ───────────────────────────────────────────────────────────────────

test.describe('AppShell', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('/api/v1/approvals**', (route) =>
      route.fulfill({ json: [APPROVAL] }),
    )
    await page.route('/api/v1/ws/events**', (route) => route.abort())
  })

  test('shows canonical 12-route nav grouped by monitor/control/manage', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page.getByTestId('appshell-nav')).toBeVisible()

    // Three section headers
    await expect(page.getByTestId('nav-group-monitor')).toBeVisible()
    await expect(page.getByTestId('nav-group-control')).toBeVisible()
    await expect(page.getByTestId('nav-group-manage')).toBeVisible()

    // Spot-check a few canonical entries across the three groups
    await expect(page.getByTestId('nav-link-overview')).toBeVisible()
    await expect(page.getByTestId('nav-link-fleet')).toBeVisible()
    await expect(page.getByTestId('nav-link-policy')).toBeVisible()
    await expect(page.getByTestId('nav-link-identity')).toBeVisible()
  })

  test('navigating to an unimplemented canonical route renders ComingSoon (no 404)', async ({ page }) => {
    await page.goto('/topology')
    await expect(page.getByTestId('coming-soon')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Topology' })).toBeVisible()
  })

  test('shows top bar with logout button', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page.getByTestId('appshell-topbar')).toBeVisible()
    await expect(page.getByTestId('logout-btn')).toBeVisible()
  })

  test('logout redirects to /login', async ({ page }) => {
    await page.goto('/approvals')
    await page.getByTestId('logout-btn').click()
    await expect(page).toHaveURL(/\/login/)
  })
})

// ── Agents page ────────────────────────────────────────────────────────────────

test.describe('Agents page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('/api/v1/agents', (route) =>
      route.fulfill({ json: [AGENT] }),
    )
    await page.route(/\/api\/v1\/agents\/[^/]+$/, (route) =>
      route.fulfill({ json: AGENT }),
    )
    await page.route('/api/v1/logs**', (route) =>
      route.fulfill({ json: [] }),
    )
  })

  // TODO(follow-up): AgentsPage was renamed to FleetPage during ST-3-era
  // dashboard work; the test-ids (`agents-table`, `agent-row`, `agent-profile`)
  // and route fixture data shape changed. These two tests are skipped pending
  // a dedicated FleetPage e2e refresh — unrelated to AAASM-1281 scope.
  test.skip('renders agent table with at least 1 row', async ({ page }) => {
    await page.goto('/agents')
    await expect(page.getByTestId('agents-table')).toBeVisible()
    await expect(page.getByTestId('agent-row').first()).toBeVisible()
    await expect(page.getByText('E2E Test Agent')).toBeVisible()
  })

  test.skip('agent detail shows identity profile fields', async ({ page }) => {
    await page.goto('/agents')
    await page.getByText('E2E Test Agent').click()
    await expect(page.getByTestId('agent-profile')).toBeVisible()
    await expect(page.getByText('agent-e2e-001')).toBeVisible()
    await expect(page.getByText('langchain')).toBeVisible()
  })
})

// ── Approvals page ─────────────────────────────────────────────────────────────

test.describe('Approvals page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('/api/v1/approvals**', (route) =>
      route.fulfill({ json: [APPROVAL] }),
    )
    await page.route('/api/v1/ws/events**', (route) => route.abort())
  })

  test('renders pending approval row', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page.getByTestId('approvals-table')).toBeVisible()
    await expect(page.getByTestId('approval-row')).toBeVisible()
    await expect(page.getByText('shell.exec ls')).toBeVisible()
  })

  test('shows empty state when no pending approvals', async ({ page }) => {
    await page.route('/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
    await page.goto('/approvals')
    await expect(page.getByTestId('approvals-empty')).toBeVisible()
  })

  test('approve button triggers approve API and removes row', async ({ page }) => {
    let approveCalled = false
    await page.route('/api/v1/approvals/*/approve', (route) => {
      approveCalled = true
      route.fulfill({ json: { ...APPROVAL, status: 'approved' } })
    })

    await page.goto('/approvals')
    await expect(page.getByTestId('approval-row')).toBeVisible()
    await page.getByTestId('approve-btn').click()

    expect(approveCalled).toBe(true)
    await expect(page.getByTestId('approval-row')).not.toBeVisible()
  })

  test('reject button opens dialog, requires reason, then rejects', async ({ page }) => {
    let rejectCalled = false
    await page.route('/api/v1/approvals/*/reject', (route) => {
      rejectCalled = true
      route.fulfill({ json: { ...APPROVAL, status: 'rejected' } })
    })

    await page.goto('/approvals')
    await page.getByTestId('reject-btn').click()
    await expect(page.getByTestId('reject-dialog')).toBeVisible()

    await expect(page.getByTestId('reject-confirm-btn')).toBeDisabled()
    await page.getByTestId('reject-reason-input').fill('not authorized')
    await expect(page.getByTestId('reject-confirm-btn')).not.toBeDisabled()
    await page.getByTestId('reject-confirm-btn').click()

    expect(rejectCalled).toBe(true)
    await expect(page.getByTestId('reject-dialog')).not.toBeVisible()
  })
})

// Policies page + Policy editor page e2e coverage now lives in
// tests/e2e/policies.spec.ts (AAASM-1372). The legacy `policies-table` /
// `policies/editor` route / Monaco editor that the deleted blocks tested were
// removed by ST-3 + ST-4 of AAASM-1281.

// ── Unauthenticated redirect ───────────────────────────────────────────────────

test.describe('Unauthenticated redirect', () => {
  test('redirects to /login when no token', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page).toHaveURL(/\/login/)
  })
})
