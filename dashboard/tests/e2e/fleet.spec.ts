import { test, expect } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import path from 'node:path'

async function injectToken(page: import('@playwright/test').Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

const ACTIVE_AGENT = {
  id: 'agent-fleet-01',
  name: 'alpha-bot',
  framework: 'langgraph',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 8,
  policy_violations_count: 2,
  last_event: '2026-05-13T12:00:00Z',
  tool_names: ['search'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { owner: 'alice' },
  pid: null,
}

const SUSPENDED_AGENT = {
  id: 'agent-fleet-02',
  name: 'beta-bot',
  framework: 'crewai',
  version: '0.1.0',
  status: 'suspended',
  layer: 'sdk',
  session_count: 3,
  policy_violations_count: 0,
  last_event: '2026-05-13T11:00:00Z',
  tool_names: ['shell'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

const EVIDENCE_DIR = path.join('verification-reports', 'AAASM-217-evidence')

test.describe('Fleet golden path', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    let suspended = false

    await page.route('/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
    await page.route('/api/v1/ws/events**', (route) => route.abort())
    await page.route('/api/v1/agents**', (route) => {
      const url = route.request().url()
      const suspendMatch = url.match(/\/api\/v1\/agents\/([^/]+)\/suspend$/)
      if (suspendMatch) {
        suspended = true
        return route.fulfill({
          json: { agent_id: suspendMatch[1], previous_status: 'active', new_status: 'suspended' },
        })
      }
      const agentMatch = url.match(/\/api\/v1\/agents\/([^/?]+)(?:\?|$)/)
      if (agentMatch && !url.includes('/suspend') && !url.includes('/resume')) {
        const id = agentMatch[1]
        const a = id === ACTIVE_AGENT.id ? ACTIVE_AGENT : SUSPENDED_AGENT
        const live = a.id === ACTIVE_AGENT.id && suspended
          ? { ...a, status: 'suspended' }
          : a
        return route.fulfill({ json: live })
      }
      const list = [
        suspended ? { ...ACTIVE_AGENT, status: 'suspended' } : ACTIVE_AGENT,
        SUSPENDED_AGENT,
      ]
      return route.fulfill({ json: list })
    })
    await page.route('/api/v1/logs**', (route) => route.fulfill({ json: [] }))

    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test('list, filter active, open drawer, suspend with reason, row flips', async ({ page }) => {
    await page.goto('/agents')

    await expect(page.getByTestId('fleet-page-head')).toBeVisible()
    await expect(page.getByTestId('agent-row')).toHaveCount(2)
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '01-fleet-list.png'), fullPage: true })

    await page.getByTestId('fleet-filter-status-active').click()
    await expect(page.getByTestId('agent-row')).toHaveCount(1)
    await expect(page.getByText('alpha-bot')).toBeVisible()
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '02-fleet-filter-active.png'), fullPage: true })

    await page.getByTestId('agent-row').first().click()
    await expect(page.getByTestId('drawer-panel')).toBeVisible()
    await expect(page.getByTestId('agent-detail')).toBeVisible()
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '03-agent-detail-drawer.png'), fullPage: true })

    await page.getByTestId('agent-detail-suspend').click()
    await expect(page.getByTestId('suspend-dialog')).toBeVisible()
    await page.getByTestId('suspend-dialog-input').fill('budget exceeded')
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '04-suspend-dialog-filled.png'), fullPage: true })

    await page.getByTestId('suspend-dialog-confirm').click()
    await page.getByTestId('fleet-filter-status-all').click()
    await expect(page.getByText('alpha-bot')).toBeVisible()
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '05-after-suspend.png'), fullPage: true })
  })

  test('bulk suspend two agents from selection bar', async ({ page }) => {
    await page.goto('/agents')
    await expect(page.getByTestId('agent-row')).toHaveCount(2)

    await page.getByTestId('fleet-select-all').click()
    await expect(page.getByTestId('fleet-bulkbar')).toBeVisible()
    await expect(page.getByTestId('fleet-bulkbar-count')).toContainText('2 selected')
    await page.screenshot({ path: path.join(EVIDENCE_DIR, '06-bulk-bar-selected.png'), fullPage: true })

    await page.getByTestId('fleet-bulkbar-suspend').click()
    await expect(page.getByTestId('suspend-dialog')).toBeVisible()
    await page.getByTestId('suspend-dialog-input').fill('batch maintenance')
    await page.getByTestId('suspend-dialog-confirm').click()

    await expect(page.getByText(/suspended/i).first()).toBeVisible()
  })
})
