/**
 * Verification capture for AAASM-5084 — per-agent blocked / scrubbed 24h metrics.
 *
 * Stands the real dashboard up against a mocked `/api/v1/agents` list plus the
 * new `/api/v1/analytics/agent-enforcement` fixture, and captures the two
 * surfaces the ticket wires — the Fleet "Blocked / 24h" + "Scrubbed / 24h"
 * columns and the Agent-Detail metric tiles — in both themes. A third agent is
 * deliberately absent from the enforcement fixture so the null-safe `—`
 * placeholder is captured alongside the real values.
 *
 * Screenshots land in dashboard/verify/5084/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5084')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// Stable agent ids (32-char lower-hex, matching the real AgentResponse.id form).
const ID_A = 'a1'.repeat(16)
const ID_B = 'b2'.repeat(16)
const ID_C = 'c3'.repeat(16)

function agent(id: string, name: string, framework: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    name,
    framework,
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: new Date().toISOString(),
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: { owner: 'platform-team', mode: 'enforce' },
    pid: null,
    ...overrides,
  }
}

const AGENTS = [
  agent(ID_A, 'checkout-agent', 'langgraph'),
  agent(ID_B, 'refund-agent', 'crewai'),
  agent(ID_C, 'quiet-agent', 'autogen'), // absent from enforcement fixture -> renders —
]

// `GET /api/v1/analytics/agent-enforcement` returns a bare array of
// { agent_id, blocked, scrubbed }. Agent C is intentionally omitted.
const ENFORCEMENT = [
  { agent_id: ID_A, blocked: 12, scrubbed: 5 },
  { agent_id: ID_B, blocked: 63, scrubbed: 0 },
]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5084')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific) so unmatched reads never 500 the
  // page; specific fixtures registered afterwards win (Playwright matches
  // most-recently-added first).
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => r.fulfill({ json: ENFORCEMENT }))
  await page.route('**/api/v1/agents**', (r) => {
    const url = new URL(r.request().url())
    // /api/v1/agents/<id>[/...] -> single agent; /api/v1/agents[?query] -> list.
    const m = /\/api\/v1\/agents\/([0-9a-f]+)/.exec(url.pathname)
    if (m) {
      const found = AGENTS.find((a) => a.id === m[1]) ?? AGENTS[0]
      return r.fulfill({ json: found })
    }
    return r.fulfill({ json: { items: AGENTS, total: AGENTS.length } })
  })
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
}

test.describe('AAASM-5084 — per-agent blocked / scrubbed 24h', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`Fleet columns + Agent-Detail tiles render real counts in ${theme}`, async ({ page }) => {
      await bootstrap(page, theme)

      // --- Fleet: the blocked/scrubbed columns now carry real numbers. ---
      await page.goto('/agents')
      await page.getByTestId('agents-table').waitFor()
      const rowA = page.locator('[data-testid="agent-row"]', { hasText: 'checkout-agent' })
      await expect(rowA).toContainText('12') // blocked
      await expect(rowA).toContainText('5') // scrubbed
      const rowB = page.locator('[data-testid="agent-row"]', { hasText: 'refund-agent' })
      await expect(rowB).toContainText('63') // blocked
      // The agent absent from the enforcement fixture keeps the em-dash.
      const rowC = page.locator('[data-testid="agent-row"]', { hasText: 'quiet-agent' })
      await expect(rowC).toContainText('—')
      await page.screenshot({ path: `${EVIDENCE_DIR}/fleet-${theme}.png`, fullPage: true })

      // --- Agent-Detail: the metric tiles now carry real numbers. ---
      // Navigate client-side (React Router) by clicking the row, rather than a
      // full page load of the deep `/agents/<id>` route — under `base: './'` a
      // hard load of that nested path resolves assets relative to `/agents/`
      // and 404s. The drawer opens in-app with no asset re-fetch.
      await rowA.getByTestId('fleet-row-name').click()
      await page.getByTestId('agent-detail-identity').waitFor()
      await expect(page.getByTestId('agent-detail-blocked')).toHaveText('12')
      await expect(page.getByTestId('agent-detail-scrubbed')).toHaveText('5')
      await page.screenshot({ path: `${EVIDENCE_DIR}/agent-detail-${theme}.png`, fullPage: true })
    })
  }
})
