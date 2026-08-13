/**
 * Verification capture for AAASM-5045 — topology node owner / policyCount /
 * budget in the node-detail panel.
 *
 * AAASM-5040 shipped the topology graph, but the node-detail panel rendered
 * owner / policy count / budget as neutral placeholders because the `AgentNode`
 * projection carried no source for them. AAASM-5045 enriches the graph
 * endpoint's `AgentNode` with `owner` (agent metadata), `policy_count`
 * (policy-engine cascade), and `budget` ({ spend_usd, limit_usd } from the
 * budget tracker); `mapTopologyGraph` maps them onto the view model.
 *
 * This evidence spec stands the page up against a mocked `/api/v1/topology`
 * fixture in the REAL API shape (snake_case `policy_count`, nested `budget`
 * object), opens the node-detail panel for a node carrying real values, asserts
 * the panel renders them (not placeholders), and screenshots the panel in both
 * light and dark themes into `dashboard/verify/5045/`. A second node with a
 * `null` budget limit confirms the null-safe placeholder path.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5045')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

// Fixture in the live `GET /api/v1/topology` `AgentNode` shape: snake_case
// fields, per-node `budget` object. `planner` carries a real owner, applied
// policy count, and a spend/limit budget; `worker-a` has a `null` budget limit
// (exercises the null-safe placeholder in the panel's budget ratio).
const NODES = [
  {
    id: 'planner',
    name: 'planner',
    depth: 0,
    status: 'active',
    team_id: 'support',
    mode: 'enforce',
    flagged: false,
    trust: null,
    owner: 'platform-team',
    policy_count: 3,
    budget: { spend_usd: 4.1, limit_usd: 100.0 },
  },
  {
    id: 'worker-a',
    name: 'worker-a',
    depth: 1,
    status: 'idle',
    team_id: 'support',
    mode: 'shadow',
    flagged: false,
    trust: null,
    owner: 'ml-team',
    policy_count: 1,
    budget: { spend_usd: 2.5, limit_usd: null },
  },
]

const EDGES = [{ source: 'planner', target: 'worker-a', kind: 'delegation' }]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      // The dashboard reads the JWT from sessionStorage (see auth/tokenStorage.ts).
      sessionStorage.setItem('aa_token', 'e2e-verify-5045')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )
  await page.route('**/api/v1/topology', r => r.fulfill({ json: { nodes: NODES, edges: EDGES } }))
  await page.route('**/api/v1/topology/nodes/*/events', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', r => r.abort())
}

async function gotoTopology(page: Page) {
  // Vite `base: './'` workaround — see tests/e2e/trace.spec.ts.
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/topology'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('topology-graph').waitFor()
  // Let d3-force settle so the layout arranges before we click a node.
  await page.waitForTimeout(600)
}

/** Open the node-detail panel for the node whose label matches `name`. */
async function openNode(page: Page, name: string) {
  await page
    .locator('[data-testid="topology-node"]', { hasText: name })
    .first()
    .click({ force: true })
  await page.getByTestId('node-detail-panel').waitFor()
}

test.describe('AAASM-5045 — node-detail owner / policyCount / budget', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`node-detail shows real owner / policyCount / budget in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)
      await gotoTopology(page)
      await openNode(page, 'planner')

      const panel = page.getByTestId('node-detail-panel')

      // Owner — real metadata value, not the empty placeholder.
      await expect(page.getByTestId('node-detail-identity')).toContainText('platform-team')

      // Applied policy count — real cascade count.
      await expect(page.getByTestId('node-detail-policy-count')).toHaveText('3 policies')

      // Budget spend / limit — real tracker values.
      await expect(page.getByTestId('node-detail-budget')).toContainText('$4.10 / $100.00')

      await page.screenshot({
        path: `${EVIDENCE_DIR}/node-detail-${theme}.png`,
        fullPage: true,
      })
      await panel.screenshot({ path: `${EVIDENCE_DIR}/node-detail-panel-${theme}.png` })
    })
  }

  test('null budget limit falls back to the placeholder budget ratio', async ({ page }) => {
    await bootstrap(page, 'light')
    await gotoTopology(page)
    await openNode(page, 'worker-a')

    // Owner still real; spend real; limit null → placeholder $0.00 / 0%.
    await expect(page.getByTestId('node-detail-identity')).toContainText('ml-team')
    await expect(page.getByTestId('node-detail-budget')).toContainText('$2.50 / $0.00')
    await page
      .getByTestId('node-detail-panel')
      .screenshot({ path: `${EVIDENCE_DIR}/node-detail-null-limit.png` })
  })
})
