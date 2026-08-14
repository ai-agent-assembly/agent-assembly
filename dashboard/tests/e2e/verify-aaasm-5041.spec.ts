/**
 * Verification capture for AAASM-5041 — the agent-detail Traffic / Policies /
 * Lineage tabs, built frontend-first from existing endpoints:
 *   - Lineage  → GET /api/v1/topology/lineage/{id}
 *   - Traffic  → GET /api/v1/analytics/{tool-usage,action-volume} (agent-scoped)
 *   - Policies → GET /api/v1/capability/matrix (filtered by `affects`)
 *
 * Evidence-capture spec (not a pixel baseline): stubs the endpoints each tab
 * reads, opens the agent-detail drawer, switches through the three tabs, and
 * screenshots each in light and dark themes into `dashboard/verify/5041/` for
 * review beside `design/v1/hi-fi/agent-detail.jsx`.
 */
import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5041')
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

const LINEAGE = {
  agent_id: AGENT_ID,
  ancestor_count: 3,
  ancestors: [
    { id: 'orchestrator-00', name: 'orchestrator', depth: 0, team_id: 'platform', delegation_reason: 'spawn research worker' },
    { id: 'router-02', name: 'task-router', depth: 1, team_id: 'platform', delegation_reason: 'delegate research task' },
    { id: AGENT_ID, name: 'research-bot-04', depth: 2, team_id: 'research' },
  ],
}

const TOOL_USAGE = {
  tools: [
    { name: 'pg.public.users', calls: 1284, errorRate: 0.004 },
    { name: 'gdrive.read', calls: 892, errorRate: 0.021 },
    { name: 'gmail.send', calls: 341, errorRate: 0.058 },
    { name: 'http.post', calls: 218, errorRate: 0.011 },
    { name: 's3.write', calls: 97, errorRate: 0.0 },
  ],
}

const ACTION_VOLUME = {
  series: [
    { key: 'allow', name: 'allow', points: Array.from({ length: 6 }, (_, i) => ({ t: i, value: 180 + i * 10 })) },
  ],
}

const MATRIX = {
  resources: [],
  agents: [],
  sampleCalls: [],
  policies: [
    { id: 'P-001', name: 'global default-deny', version: '1', scope: 'global', status: 'active', hits24h: 4210, affects: [AGENT_ID], rules: [] },
    { id: 'P-066', name: 'narrow research-bot writes', version: '3', scope: 'tag:research', status: 'proposed', hits24h: 128, affects: [AGENT_ID], rules: [] },
    { id: 'P-100', name: 'L3 secret scrubbing', version: '2', scope: 'egress:all', status: 'active', hits24h: 63, affects: [AGENT_ID], rules: [] },
    { id: 'P-999', name: 'unrelated policy', version: '1', scope: 'team:sales', status: 'archived', hits24h: 0, affects: ['sales-bot'], rules: [] },
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

  // Playwright matches the most-recently-registered route first, so register
  // broadest → narrowest: the catch-all goes first, the specific routes last.
  await page.route('**/api/v1/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) => r.fulfill({ json: { ticket: 'e2e-ticket' } }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: [AGENT], total: 1 } }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/tool-usage**', (r) => r.fulfill({ json: TOOL_USAGE }))
  await page.route('**/api/v1/analytics/action-volume**', (r) => r.fulfill({ json: ACTION_VOLUME }))
  await page.route('**/api/v1/capability/matrix**', (r) => r.fulfill({ json: MATRIX }))
  await page.route(`**/api/v1/topology/lineage/**`, (r) => r.fulfill({ json: LINEAGE }))
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
  test(`agent-detail Traffic/Policies/Lineage tabs — ${theme}`, async ({ page }) => {
    await bootstrap(page, theme)
    // The production build emits relative asset paths (`./assets/…`), which
    // 404 on a two-segment deep link like `/agents/:id`. Load the single-
    // segment Fleet route first (assets resolve), then open the drawer via
    // client-side navigation by clicking the agent row.
    await page.goto('/agents')
    await page.getByTestId('fleet-row-name').first().click()

    await expect(page.getByTestId('agent-detail')).toBeVisible()

    // Traffic
    await page.getByTestId('agent-detail-tab-traffic').click()
    await expect(page.getByTestId('agent-traffic-tab')).toBeVisible()
    await expect(page.getByTestId('agent-traffic-total')).toBeVisible()
    await expect(page.getByTestId('traffic-tool-pg.public.users')).toBeVisible()
    await shot(page, `traffic-${theme}.png`)

    // Policies
    await page.getByTestId('agent-detail-tab-policies').click()
    await expect(page.getByTestId('agent-policies-tab')).toBeVisible()
    await expect(page.getByTestId('policy-row-P-066')).toBeVisible()
    await expect(page.getByTestId('policy-row-P-999')).toHaveCount(0)
    await shot(page, `policies-${theme}.png`)

    // Lineage
    await page.getByTestId('agent-detail-tab-lineage').click()
    await expect(page.getByTestId('agent-lineage-tab')).toBeVisible()
    await expect(page.getByTestId(`lineage-node-${AGENT_ID}`)).toContainText('current')
    await shot(page, `lineage-${theme}.png`)
  })
}
