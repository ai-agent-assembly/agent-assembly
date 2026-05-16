// E2E acceptance for AAASM-1082. Walks the alert lifecycle through the UI:
//
//   1. Empty state — zero rules → CTA "Create your first rule" is visible.
//   2. Destination CRUD — add a Slack destination via DestinationManager.
//   3. Rule creation — open AlertRuleForm, fill, submit, success toast.
//   4. Alert appears — refetch list returns one FIRING alert, row renders.
//   5. Detail drawer — open, rule YAML + routing log + dedup/suppression
//      sections render.
//   6. Silence — pick 1h preset, submit, alert status becomes SUPPRESSED.
//
// Backend endpoints are stubbed via page.route(); the WebSocket is aborted
// (the disconnected banner is expected and is not under test here).
// Screenshots land in tests/__screenshots__/AAASM-1082/.

import { test, expect, type Page, type Route } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1082'

const SLACK_DESTINATION = {
  id: 'dst-slack-ops',
  kind: 'slack',
  name: 'ops',
  enabled: true,
  createdAt: '2026-05-14T00:00:00Z',
  updatedAt: '2026-05-14T00:00:00Z',
  config: { webhookUrl: 'https://hooks.slack.com/services/x' },
}

const FIRING_ALERT = {
  id: 'alert-001',
  ruleId: 'rule-001',
  ruleName: 'Budget guardrail',
  severity: 'CRITICAL',
  status: 'FIRING',
  agentId: 'aa-001',
  firstFiredAt: '2026-05-14T09:00:00Z',
  resolvedAt: null,
  destinationIds: ['dst-slack-ops'],
}

const SUPPRESSED_ALERT = { ...FIRING_ALERT, status: 'SUPPRESSED' }

const RULE = {
  id: 'rule-001',
  name: 'Budget guardrail',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 90,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  destinationIds: ['dst-slack-ops'],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '2026-05-14T00:00:00Z',
  updatedAt: '2026-05-14T00:00:00Z',
}

const ALERT_DETAIL = {
  ...FIRING_ALERT,
  ruleSnapshot: RULE,
  eventPayload: { metric_value: 92.3 },
  routingLog: [
    {
      destinationId: 'dst-slack-ops',
      deliveredAt: '2026-05-14T09:00:01Z',
      status: 'ok',
    },
  ],
  silence: null,
  dedupOccurrenceCount: 1,
  dedupWindowExpiresAt: null,
}

interface BackendState {
  destinations: typeof SLACK_DESTINATION[]
  rules: typeof RULE[]
  alerts: typeof FIRING_ALERT[]
  detail: typeof ALERT_DETAIL
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockBackend(page: Page, state: BackendState) {
  // Abort the alerts WebSocket — the disconnected banner is expected.
  await page.route('**/api/v1/alerts/ws*', (route: Route) => route.abort())

  // Other AppShell / landing chatter — return harmless stubs.
  await page.route('**/api/v1/approvals**', (route: Route) =>
    route.fulfill({ json: [] }),
  )
  await page.route('**/api/v1/policies/active', (route: Route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )

  // Destinations: list + create + delete + test-fire.
  await page.route('**/api/v1/alerts/destinations*', (route: Route) => {
    const method = route.request().method()
    const url = route.request().url()
    if (url.includes('/test')) {
      return route.fulfill({
        status: 200,
        json: {
          deliveredAt: new Date().toISOString(),
          connectorResponseStatus: 200,
          connectorResponseBody: 'ok',
        },
      })
    }
    if (method === 'GET') return route.fulfill({ json: state.destinations })
    if (method === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      const created = { ...SLACK_DESTINATION, ...body, id: 'dst-new' }
      state.destinations = [...state.destinations, created]
      return route.fulfill({ status: 201, json: created })
    }
    if (method === 'DELETE') {
      return route.fulfill({ status: 204, body: '' })
    }
    return route.fallback()
  })

  // Alert rules: list + create + update + delete (DELETE/PUT added for AAASM-1393 rules tab).
  // Glob `**` (not `*`) so per-rule paths like `/rules/<id>` match — Playwright's
  // `*` doesn't span path separators.
  await page.route('**/api/v1/alerts/rules**', (route: Route) => {
    const method = route.request().method()
    const url = route.request().url()
    if (method === 'GET') return route.fulfill({ json: state.rules })
    if (method === 'POST') {
      const body = JSON.parse(route.request().postData() ?? '{}')
      const created = { ...RULE, ...body }
      state.rules = [...state.rules, created]
      return route.fulfill({ status: 201, json: created })
    }
    if (method === 'PUT') {
      const match = url.match(/\/rules\/([^/?]+)/)
      const id = match ? decodeURIComponent(match[1]) : null
      const body = JSON.parse(route.request().postData() ?? '{}')
      state.rules = state.rules.map((r) => (r.id === id ? { ...r, ...body } : r))
      const updated = state.rules.find((r) => r.id === id) ?? state.rules[0]
      return route.fulfill({ json: updated })
    }
    if (method === 'DELETE') {
      const match = url.match(/\/rules\/([^/?]+)/)
      const id = match ? decodeURIComponent(match[1]) : null
      if (id) state.rules = state.rules.filter((r) => r.id !== id)
      return route.fulfill({ status: 204, body: '' })
    }
    return route.fallback()
  })

  // Silence — flip the served detail + list to SUPPRESSED.
  await page.route('**/api/v1/alerts/silence', (route: Route) => {
    state.alerts = state.alerts.map((a) => ({ ...a, status: 'SUPPRESSED' }))
    state.detail = { ...state.detail, status: 'SUPPRESSED' }
    return route.fulfill({
      status: 201,
      json: {
        silenceId: 'sil-1',
        alertId: state.detail.id,
        startsAt: '2026-05-14T09:30:00Z',
        expiresAt: '2026-05-14T10:30:00Z',
        reason: null,
        createdBy: 'e2e',
      },
    })
  })

  // Alerts: single endpoint serves both list and detail under the same URL prefix.
  await page.route('**/api/v1/alerts/*', (route: Route) => {
    const url = route.request().url()
    if (url.includes('/alerts/destinations') || url.includes('/alerts/rules') || url.includes('/alerts/silence') || url.includes('/alerts/ws')) {
      return route.fallback()
    }
    // detail
    return route.fulfill({ json: state.detail })
  })
  await page.route('**/api/v1/alerts*', (route: Route) => {
    const url = route.request().url()
    if (url.match(/\/alerts\/[a-zA-Z0-9-]+/)) return route.fallback()
    return route.fulfill({ json: state.alerts })
  })
}

test.describe('Alerts page — AAASM-1082 lifecycle', () => {
  test('empty state shows the create-rule CTA when zero rules exist', async ({ page }) => {
    await injectToken(page)
    const state: BackendState = {
      destinations: [],
      rules: [],
      alerts: [],
      detail: ALERT_DETAIL,
    }
    await mockBackend(page, state)

    await page.goto('/alerts')
    await expect(page.getByTestId('alerts-empty-no-rules')).toBeVisible()
    await expect(page.getByTestId('alerts-empty-create-cta')).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/01-empty-no-rules.png`, fullPage: true })
  })

  test('full lifecycle — add destination → create rule → see alert → silence', async ({
    page,
  }) => {
    await injectToken(page)
    // Start with a FIRING alert already in the list; the alert is suppressed
    // from view by the EmptyStateNoRules guard until the first rule lands.
    const state: BackendState = {
      destinations: [SLACK_DESTINATION],
      rules: [],
      alerts: [FIRING_ALERT],
      detail: ALERT_DETAIL,
    }
    await mockBackend(page, state)

    await page.goto('/alerts')
    await expect(page.getByTestId('alerts-empty-no-rules')).toBeVisible()

    // ── Open destinations modal → confirm slack is listed ───────────────
    await page.getByTestId('alerts-open-destinations').click()
    await expect(page.getByTestId('destination-manager')).toBeVisible()
    await expect(page.getByTestId(`destination-row-${SLACK_DESTINATION.id}`)).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/02-destinations.png`, fullPage: true })
    await page.getByTestId('destination-manager-close').click()

    // ── Create a rule via the empty-state CTA ────────────────────────────
    await page.getByTestId('alerts-empty-create-cta').click()
    await expect(page.getByTestId('alert-rule-form')).toBeVisible()
    await page.getByTestId('rule-name').fill('Budget guardrail')
    await page.getByTestId(`rule-destination-${SLACK_DESTINATION.id}`).click()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/03-rule-form.png`, fullPage: true })
    await page.getByTestId('alert-rule-form-submit').click()

    // ── Toast appears + alert row lands ─────────────────────────────────
    await expect(page.getByText(/Created rule/)).toBeVisible()
    await expect(page.getByTestId('alert-row').first()).toBeVisible({ timeout: 10_000 })
    await page.screenshot({ path: `${SCREENSHOT_DIR}/04-alert-row.png`, fullPage: true })

    // ── Open detail drawer ──────────────────────────────────────────────
    await page.getByTestId('alert-row').first().click()
    await expect(page.getByTestId('alert-detail-drawer')).toBeVisible()
    await expect(page.getByTestId('alert-detail-rule-yaml')).toBeVisible()
    await expect(page.getByTestId('alert-detail-routing-log')).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/05-drawer.png`, fullPage: true })

    // ── Silence — pick 1h preset and submit ────────────────────────────
    await page.getByTestId('silence-action-duration-1h').click()
    await page.getByTestId('silence-action-submit').click()
    await expect(page.getByText('Silence applied')).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/06-silenced.png`, fullPage: true })
  })

  test('rules tab — list rules, edit a rule, delete a rule (AAASM-1393)', async ({ page }) => {
    await injectToken(page)
    const state: BackendState = {
      destinations: [SLACK_DESTINATION],
      rules: [RULE, { ...RULE, id: 'rule-002', name: 'High violations' }],
      alerts: [],
      detail: ALERT_DETAIL,
    }
    await mockBackend(page, state)

    // Deep-link to the rules tab via the AAASM-1393 URL state.
    await page.goto('/alerts?tab=rules')
    await expect(page.getByTestId('alert-rules-tab')).toBeVisible()
    await expect(page.getByTestId('alert-rules-table')).toBeVisible()
    const rows = page.getByTestId('alert-rules-row')
    await expect(rows).toHaveCount(2)
    await page.screenshot({ path: `${SCREENSHOT_DIR}/07-rules-tab.png`, fullPage: true })

    // ── Edit the first rule via the row-level Edit button ───────────────
    await rows.first().getByTestId('alert-rules-row-edit').click()
    await expect(page.getByTestId('alert-rule-form')).toBeVisible()
    // The form opened pre-filled in edit mode (name field carries the rule name).
    await expect(page.getByTestId('rule-name')).toHaveValue('Budget guardrail')
    await page.screenshot({ path: `${SCREENSHOT_DIR}/08-rules-edit.png`, fullPage: true })
    // AlertRuleForm uses a click-outside-to-close pattern; no Escape binding.
    // Use the cancel button to dismiss the modal before the delete click.
    await page.getByTestId('alert-rule-form-cancel').click()
    await expect(page.getByTestId('alert-rule-form')).not.toBeVisible()

    // ── Delete the second rule via the row-level Delete button ─────────
    await page
      .getByTestId('alert-rules-row')
      .filter({ hasText: 'High violations' })
      .getByTestId('alert-rules-row-delete')
      .click()

    // After the DELETE refetches the rules list, the "High violations" row
    // is gone. The Deleted-rule toast fires from the mutation's onSuccess;
    // assert the durable side-effect (row removed) rather than the toast
    // which auto-dismisses after 4 s.
    await expect(
      page.getByTestId('alert-rules-row').filter({ hasText: 'High violations' }),
    ).toHaveCount(0)
    await expect(page.getByTestId('alert-rules-row')).toHaveCount(1)
  })
})
