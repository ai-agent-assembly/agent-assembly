// E2E acceptance for AAASM-1917 (Dashboard wire-up: SandboxSummaryCard banner
// on PoliciesPage + dry-run toggle + amber "Would: X" badge on the
// AgentDetailPage events table).
//
// Walks two flows:
//   1. /policies — stubs the new GET /api/v1/audit/sandbox-summary endpoint
//      with a populated response and asserts the SandboxSummaryCard banner
//      renders with the counts + top rule from the mocked payload.
//   2. /agents/<id> — stubs /api/v1/logs to return mixed live + dry-run
//      events and asserts (a) the amber badge appears only on the dry-run
//      row and (b) the toggle filters the table down to dry-run rows only.
//
// State screenshots land in tests/__screenshots__/AAASM-1917/ for the
// closing comment / parent Story (AAASM-1553).

import { test, expect, type Page } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1917'

const ACTIVE_POLICY = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
  policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
}

const SANDBOX_SUMMARY_RESPONSE = {
  counts: {
    would_be_denies: 7,
    would_be_redactions: 2,
    would_be_pending_approvals: 1,
  },
  top_rule: { id: 'block-secrets', count: 5 },
  window_secs: 86_400,
  generated_at: '2026-05-23T00:00:00Z',
}

const AGENT = {
  id: 'a'.repeat(32),
  name: 'sandbox-test-agent',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  team: 'platform',
  mode: 'normal',
  trust_score: 88,
  last_seen: '2026-05-23T00:00:00Z',
  active_sessions: [],
  recent_traces: [],
  policy_violations_count: 0,
  tool_names: [],
  metadata: {},
  pid: null,
}

const LIVE_LOG = {
  agent_id: AGENT.id,
  event_type: 'ToolCallIntercepted',
  payload: '{"decision":"Allow"}',
  seq: 1,
  session_id: 's'.repeat(32),
  timestamp: '2026-05-23T00:00:01Z',
}

const SANDBOX_LOG = {
  agent_id: AGENT.id,
  event_type: 'ToolCallIntercepted',
  payload: '{"dry_run":true,"shadow_decision":"deny"}',
  seq: 2,
  session_id: 't'.repeat(32),
  timestamp: '2026-05-23T00:00:02Z',
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockAppShell(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
}

test.describe('AAASM-1917 — SandboxSummaryCard banner on /policies', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockAppShell(page)
    await page.route('**/api/v1/policies', (route) => {
      if (route.request().method() === 'GET') {
        return route.fulfill({ json: [ACTIVE_POLICY] })
      }
      return route.fallback()
    })
    await page.route('**/api/v1/audit/sandbox-summary**', (route) =>
      route.fulfill({ json: SANDBOX_SUMMARY_RESPONSE }),
    )
  })

  test('renders the SandboxSummaryCard banner with counts and top rule', async ({ page }) => {
    await page.goto('/policies')
    await expect(page.getByTestId('policies-page')).toBeVisible()

    const banner = page.getByTestId('policies-sandbox-banner')
    await expect(banner).toBeVisible()
    await expect(banner).toContainText('7')
    await expect(banner).toContainText('2')
    await expect(banner).toContainText('1')
    await expect(banner).toContainText('block-secrets')

    await page.screenshot({
      path: `${SCREENSHOT_DIR}/01-policies-sandbox-banner.png`,
      fullPage: true,
    })
  })
})

test.describe('AAASM-1917 — amber Would: X badge + Sandbox events toggle on agent detail', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockAppShell(page)
    // Stub the sandbox summary so PoliciesPage doesn't error if the user
    // navigates back; not load-bearing for these assertions.
    await page.route('**/api/v1/audit/sandbox-summary**', (route) =>
      route.fulfill({ json: {
        counts: { would_be_denies: 0, would_be_redactions: 0, would_be_pending_approvals: 0 },
        top_rule: null,
        window_secs: 86_400,
        generated_at: '2026-05-23T00:00:00Z',
      } }),
    )
    await page.route('**/api/v1/agents**', (route) => {
      const url = route.request().url()
      if (url.includes(`/agents/${AGENT.id}/capabilities`)) {
        return route.fulfill({ json: { allow: [], deny: [], sources: [] } })
      }
      if (url.includes(`/agents/${AGENT.id}/subtree-burn`)) {
        return route.fulfill({ json: {
          window: '7d',
          total_usd: 0,
          daily: [],
          top_children: [],
          generated_at: '2026-05-23T00:00:00Z',
        } })
      }
      if (url.includes(`/agents/${AGENT.id}`)) {
        return route.fulfill({ json: AGENT })
      }
      if (route.request().method() === 'GET') {
        return route.fulfill({ json: [AGENT] })
      }
      return route.fallback()
    })
    await page.route('**/api/v1/logs**', (route) =>
      route.fulfill({ json: [LIVE_LOG, SANDBOX_LOG] }),
    )
  })

  test('amber badge renders only on the dry-run row', async ({ page }) => {
    await page.goto(`/agents/${AGENT.id}`)
    await expect(page.getByTestId('agent-events')).toBeVisible()

    const badges = page.getByTestId('event-sandbox-badge')
    await expect(badges).toHaveCount(1)
    await expect(badges.first()).toContainText(/Would: deny/i)

    await page.screenshot({
      path: `${SCREENSHOT_DIR}/02-amber-badge.png`,
      fullPage: true,
    })
  })

  test('toggle filters the events table down to dry-run rows', async ({ page }) => {
    await page.goto(`/agents/${AGENT.id}`)
    await expect(page.getByTestId('agent-events')).toBeVisible()
    await expect(page.getByTestId('event-row')).toHaveCount(2)

    await page.getByTestId('agent-events-sandbox-toggle').check()
    await expect(page.getByTestId('event-row')).toHaveCount(1)
    await expect(page.getByTestId('event-sandbox-badge')).toBeVisible()

    await page.screenshot({
      path: `${SCREENSHOT_DIR}/03-sandbox-toggle-on.png`,
      fullPage: true,
    })
  })
})
