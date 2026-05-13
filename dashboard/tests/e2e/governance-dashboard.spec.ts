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
    await expect(page.getByLabelText('API Key')).toBeVisible()
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

  test('shows nav with Approvals, Agents, Policies links', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page.getByTestId('appshell-nav')).toBeVisible()
    await expect(page.getByTestId('nav-link-approvals')).toBeVisible()
    await expect(page.getByTestId('nav-link-agents')).toBeVisible()
    await expect(page.getByTestId('nav-link-policies')).toBeVisible()
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

  test('renders agent table with at least 1 row', async ({ page }) => {
    await page.goto('/agents')
    await expect(page.getByTestId('agents-table')).toBeVisible()
    await expect(page.getByTestId('agent-row').first()).toBeVisible()
    await expect(page.getByText('E2E Test Agent')).toBeVisible()
  })

  test('agent detail shows identity profile fields', async ({ page }) => {
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

// ── Policies page ──────────────────────────────────────────────────────────────

test.describe('Policies page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('/api/v1/policies**', (route) =>
      route.fulfill({ json: [POLICY] }),
    )
  })

  test('renders policy list', async ({ page }) => {
    await page.goto('/policies')
    await expect(page.getByTestId('policies-table')).toBeVisible()
    await expect(page.getByText('e2e-policy')).toBeVisible()
    await expect(page.getByText('active')).toBeVisible()
  })

  test('Edit link navigates to policy editor', async ({ page }) => {
    await page.goto('/policies')
    await page.getByTestId('edit-policy-link').first().click()
    await expect(page).toHaveURL(/\/policies\/editor/)
    await expect(page.getByTestId('policy-editor')).toBeVisible()
  })
})

// ── Policy editor page ─────────────────────────────────────────────────────────

test.describe('Policy editor page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('/api/v1/policies', (route) => {
      if (route.request().method() === 'GET') {
        return route.fulfill({ json: [POLICY] })
      }
      return route.fulfill({ json: { ...POLICY, version: '1.0.1' } })
    })
  })

  test('Apply button is visible and enabled with default template', async ({ page }) => {
    await page.goto('/policies/editor')
    await expect(page.getByTestId('apply-btn')).toBeVisible()
    await expect(page.getByTestId('apply-btn')).not.toBeDisabled()
  })

  test('Diff button toggles to diff panel and back', async ({ page }) => {
    await page.goto('/policies/editor')
    await expect(page.getByTestId('toggle-diff-btn')).toHaveText('Diff')
    await page.getByTestId('toggle-diff-btn').click()
    // Monaco loads async; confirm the toggle state changed before the editor resolves
    await expect(page.getByTestId('toggle-diff-btn')).toHaveText('Editor')
    await page.getByTestId('toggle-diff-btn').click()
    await expect(page.getByTestId('toggle-diff-btn')).toHaveText('Diff')
  })

  test('Discard navigates back to /policies', async ({ page }) => {
    await page.goto('/policies/editor')
    await page.getByTestId('discard-btn').click()
    await expect(page).toHaveURL(/\/policies$/)
  })
})

// ── Unauthenticated redirect ───────────────────────────────────────────────────

test.describe('Unauthenticated redirect', () => {
  test('redirects to /login when no token', async ({ page }) => {
    await page.goto('/approvals')
    await expect(page).toHaveURL(/\/login/)
  })
})
