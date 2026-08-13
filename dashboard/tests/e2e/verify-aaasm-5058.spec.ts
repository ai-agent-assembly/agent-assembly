/**
 * Verification capture for AAASM-5058 — the agent-detail Traffic tab's
 * per-decision row table, backed by the new read-only endpoint:
 *   - GET /api/v1/agents/{id}/decisions  (recent per-agent decision stream)
 *
 * Evidence-capture spec (not a pixel baseline): stubs the endpoints the tab
 * reads (the AAASM-5041 aggregate plus the new decision stream), opens the
 * agent-detail drawer, switches to the Traffic tab, asserts the aggregate
 * summary and the per-decision table are both present, and screenshots the tab
 * in light and dark themes into `dashboard/verify/5058/` for review beside
 * `design/v1/hi-fi/agent-detail.jsx`.
 */
import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5058')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

const AGENT_ID = 'research-bot-04'

const AGENT = {
  id: AGENT_ID,
  name: 'research-bot-04',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 1421,
  policy_violations_count: 63,
  tool_names: ['gmail.send', 'pg.users'],
  metadata: { owner: 'alice' },
  pid: null,
}

const TOOL_USAGE = {
  tools: [
    { name: 'pg.public.users', calls: 1284, errorRate: 0.004 },
    { name: 'gmail.send', calls: 341, errorRate: 0.058 },
  ],
}

const ACTION_VOLUME = {
  series: [
    { key: 'allow', name: 'allow', points: Array.from({ length: 6 }, (_, i) => ({ t: i, value: 180 + i * 10 })) },
  ],
}

// The design's decision columns: ts / verb / resource / decision / latency /
// policy. `latencyMs` is null on every row (no audit source) — the table must
// render it as `—`, not a fabricated number.
const DECISIONS = {
  decisions: [
    { timestamp: '2026-07-24T14:03:11Z', sessionId: 'ee'.repeat(16), seq: 9, verb: 'TOOL_CALL', resource: 'gmail.send', decision: 2, decisionLabel: 'deny', matchedPolicy: 'P-066', latencyMs: null },
    { timestamp: '2026-07-24T14:03:02Z', sessionId: 'ee'.repeat(16), seq: 8, verb: 'FILE_OPERATION', resource: '/etc/secrets', decision: 4, decisionLabel: 'redact', matchedPolicy: 'P-100', latencyMs: null },
    { timestamp: '2026-07-24T14:02:55Z', sessionId: 'ee'.repeat(16), seq: 7, verb: 'NETWORK_CALL', resource: 'api.example.com', decision: 3, decisionLabel: 'pending', matchedPolicy: 'P-122', latencyMs: null },
    { timestamp: '2026-07-24T14:02:40Z', sessionId: 'ee'.repeat(16), seq: 6, verb: 'TOOL_CALL', resource: 'pg.users', decision: 1, decisionLabel: 'allow', matchedPolicy: null, latencyMs: null },
  ],
}

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Broadest → narrowest (Playwright matches the most-recently-registered first).
  await page.route('**/api/v1/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) => r.fulfill({ json: { ticket: 'e2e-ticket' } }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: [AGENT], total: 1 } }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/tool-usage**', (r) => r.fulfill({ json: TOOL_USAGE }))
  await page.route('**/api/v1/analytics/action-volume**', (r) => r.fulfill({ json: ACTION_VOLUME }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/decisions**`, (r) => r.fulfill({ json: DECISIONS }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/capabilities`, (r) =>
    r.fulfill({ json: { allow: ['file_read'], deny: [], sources: [] } }),
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}/subtree-burn**`, (r) =>
    r.fulfill({ json: { total: 0, daily: [], children: [] } }),
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}`, (r) => r.fulfill({ json: AGENT }))
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, name), fullPage: true })
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

for (const theme of ['light', 'dark'] as const) {
  test(`agent-detail Traffic tab — aggregate + per-decision stream — ${theme}`, async ({ page }) => {
    await bootstrap(page, theme)
    // Assets are relative; load the single-segment Fleet route first, then open
    // the drawer via client-side navigation by clicking the agent row.
    await page.goto('/agents')
    await page.getByTestId('fleet-row-name').first().click()
    await expect(page.getByTestId('agent-detail')).toBeVisible()

    await page.getByTestId('agent-detail-tab-traffic').click()
    await expect(page.getByTestId('agent-traffic-tab')).toBeVisible()

    // Aggregate summary (AAASM-5041) is still present above the stream.
    await expect(page.getByTestId('agent-traffic-total')).toBeVisible()

    // New per-decision table (AAASM-5058).
    await expect(page.getByTestId('agent-decisions-table')).toBeVisible()
    const rows = page.getByTestId('agent-decision-row')
    await expect(rows).toHaveCount(4)
    await expect(rows.first()).toContainText('deny')
    await expect(rows.first()).toContainText('P-066')
    // Latency has no audit source — every row shows an em dash, never a number.
    await expect(page.getByTestId('agent-decision-latency').first()).toHaveText('—')

    await shot(page, `traffic-decisions-${theme}.png`)
  })
}
