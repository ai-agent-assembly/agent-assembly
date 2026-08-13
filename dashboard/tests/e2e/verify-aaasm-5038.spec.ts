/**
 * Verification capture for AAASM-5038 — Fleet → Active Sessions.
 *
 * Stands the Fleet page up against a mocked `/api/v1/fleet/active-sessions`
 * fixture (the read-only endpoint added in this ticket), switches to the Active
 * Sessions tab, asserts the fleet-wide session table rendered, then screenshots
 * it in both light and dark themes into `dashboard/verify/5038/` for review next
 * to `design/v1/hi-fi/fleet.jsx`.
 *
 * Evidence-capture spec, not a pixel baseline nor part of any CI lane.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5038')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

const iso = (secondsAgo: number) => new Date(Date.now() - secondsAgo * 1000).toISOString()

// Fleet-wide open sessions across three agents / two teams, mixed statuses and
// ages so the "running" elapsed column spans seconds / minutes / hours.
const SESSIONS = [
  { agent_id: 'a'.repeat(32), agent_name: 'research-bot-04', team_id: 'growth', session_id: 'sess-9a4f', started_at: iso(45), status: 'running' },
  { agent_id: 'a'.repeat(32), agent_name: 'research-bot-04', team_id: 'growth', session_id: 'sess-9a4e', started_at: iso(600), status: 'running' },
  { agent_id: 'b'.repeat(32), agent_name: 'analytics-runner', team_id: 'growth', session_id: 'sess-8b12', started_at: iso(3 * 3600), status: 'idle' },
  { agent_id: 'c'.repeat(32), agent_name: 'infra-ops-bot', team_id: 'platform', session_id: 'sess-7c33', started_at: iso(90), status: 'running' },
]

const AGENTS = SESSIONS.map((s) => ({
  id: s.agent_id,
  name: s.agent_name,
  framework: 'langgraph',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 0,
  last_event: iso(30),
  tool_names: [],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { owner: 'alice', team: s.team_id },
  pid: null,
}))

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5038')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )
  await page.route('**/api/v1/fleet/active-sessions', (r) => r.fulfill({ json: SESSIONS }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: AGENTS, total: AGENTS.length, page: 1, per_page: 100 } }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0, page: 1, per_page: 50 } }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
}

async function gotoSessions(page: Page) {
  // Vite `base: './'` workaround — see tests/e2e/trace.spec.ts.
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/agents'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('fleet-page').waitFor()
  await page.getByTestId('fleet-tab-sessions').click()
  await page.getByTestId('sessions-table').waitFor()
}

test.describe('AAASM-5038 — Fleet active sessions', () => {
  test.use({ viewport: { width: 1280, height: 800 } })

  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`renders the active-sessions list in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)
      await gotoSessions(page)

      // One row per open session, fleet-wide.
      await expect(page.getByTestId('session-row')).toHaveCount(SESSIONS.length)
      // Session id, agent name, team, and status chip all render.
      await expect(page.getByText('sess-9a4f')).toBeVisible()
      await expect(page.getByText('research-bot-04').first()).toBeVisible()
      await expect(page.getByText('platform').first()).toBeVisible()
      await expect(page.getByTestId('fleet-status').first()).toBeVisible()
      // Tab badge reflects the live count.
      await expect(page.getByTestId('fleet-tab-sessions-count')).toHaveText(String(SESSIONS.length))

      await page.screenshot({
        path: `${EVIDENCE_DIR}/fleet-active-sessions-${theme}.png`,
        fullPage: true,
      })
    })
  }
})
