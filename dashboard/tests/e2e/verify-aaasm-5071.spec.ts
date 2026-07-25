/**
 * Verification capture for AAASM-5071 — Topology FE parity.
 *
 * Stands the real dashboard up against a mocked `/api/v1/topology` graph (+
 * lineage / events) fixture and captures the new parity surfaces in both
 * themes: the control sidebar (stats, team filter, edge-type checkboxes,
 * cycle alert, status legend), pan/zoom controls, the enriched node-detail
 * panel (lineage + cross-team edges + suspend), and the team-detail panel.
 *
 * Screenshots land in dashboard/verify/parity-topology/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/parity-topology')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// Live `GET /api/v1/topology` AgentNode shape. Two teams, a cross-team call,
// a flagged + suspended agent, and a planner↔auditor delegation cycle so the
// cycle alert + cross-team stats render.
const NODES = [
  { id: 'planner', name: 'planner', depth: 0, status: 'active', team_id: 'support', mode: 'enforce', flagged: false, trust: null, owner: 'platform-team', policy_count: 3, budget: { spend_usd: 4.1, limit_usd: 100.0 } },
  { id: 'worker-a', name: 'worker-a', depth: 1, status: 'active', team_id: 'support', mode: 'shadow', flagged: false, trust: null, owner: 'ml-team', policy_count: 1, budget: { spend_usd: 2.5, limit_usd: 40.0 } },
  { id: 'auditor', name: 'auditor', depth: 1, status: 'suspended', team_id: 'support', mode: 'enforce', flagged: true, trust: null, owner: 'sec-team', policy_count: 5, budget: { spend_usd: 9.5, limit_usd: 10.0 } },
  { id: 'analyst', name: 'analyst', depth: 0, status: 'active', team_id: 'analytics', mode: 'enforce', flagged: false, trust: null, owner: 'data-team', policy_count: 2, budget: { spend_usd: 12.0, limit_usd: 60.0 } },
  { id: 'etl', name: 'etl-worker', depth: 1, status: 'active', team_id: 'analytics', mode: 'enforce', flagged: false, trust: null, owner: 'data-team', policy_count: 1, budget: { spend_usd: 3.0, limit_usd: 30.0 } },
]
const EDGES = [
  { source: 'planner', target: 'worker-a', kind: 'delegation' },
  { source: 'planner', target: 'auditor', kind: 'delegation' },
  { source: 'auditor', target: 'planner', kind: 'delegation' }, // cycle
  { source: 'worker-a', target: 'analyst', kind: 'call' }, // cross-team support→analytics
  { source: 'analyst', target: 'etl', kind: 'delegation' },
]
const LINEAGE = {
  agent_id: 'worker-a',
  ancestor_count: 2,
  ancestors: [
    { id: 'planner', name: 'planner', depth: 0, team_id: 'support' },
    { id: 'worker-a', name: 'worker-a', depth: 1, team_id: 'support', delegation_reason: 'delegate sub-task' },
  ],
}

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5071')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )
  await page.route('**/api/v1/topology', (r) => r.fulfill({ json: { nodes: NODES, edges: EDGES } }))
  await page.route('**/api/v1/topology/nodes/*/events', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology/lineage/**', (r) => r.fulfill({ json: LINEAGE }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
}

async function gotoTopology(page: Page) {
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/topology'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('topology-graph').waitFor()
  await page.waitForTimeout(700) // let d3-force settle
}

test.describe('AAASM-5071 — Topology FE parity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`sidebar + zoom + node/team panels render in ${theme}`, async ({ page }) => {
      await bootstrap(page, theme)
      await gotoTopology(page)

      // Sidebar: stats, team filter, edge-type checkboxes, cycle alert, legend.
      await expect(page.getByTestId('topology-sidebar')).toBeVisible()
      await expect(page.getByTestId('topology-stat-active')).toContainText('active')
      await expect(page.getByTestId('topology-stat-cycle')).toBeVisible()
      await expect(page.getByTestId('topology-cycle-alert')).toBeVisible()
      await expect(page.getByTestId('topology-status-legend')).toBeVisible()
      await expect(page.getByTestId('topology-edge-toggle')).toHaveCount(6)
      // Zoom controls + readout.
      await expect(page.getByTestId('topology-zoom-readout')).toHaveText('100%')
      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-full-${theme}.png`, fullPage: true })

      // Zoom in twice, capture the readout change (done before opening a panel —
      // the node panel closes on any outside click, incl. the zoom controls).
      await page.getByTestId('topology-zoom-in').click()
      await page.getByTestId('topology-zoom-in').click()
      await expect(page.getByTestId('topology-zoom-readout')).not.toHaveText('100%')
      await page.screenshot({ path: `${EVIDENCE_DIR}/zoom-${theme}.png`, fullPage: true })
      await page.getByTestId('topology-zoom-reset').click()

      // Node panel — lineage + cross-team edges + suspend.
      await page.locator('[data-testid="topology-node"]', { hasText: 'worker-a' }).first().click({ force: true })
      await page.getByTestId('node-detail-panel').waitFor()
      await expect(page.getByTestId('node-detail-lineage-chain')).toBeVisible()
      await expect(page.getByTestId('node-detail-crossteam')).toBeVisible()
      await expect(page.getByTestId('node-detail-suspend')).toBeVisible()
      await page.getByTestId('node-detail-panel').screenshot({ path: `${EVIDENCE_DIR}/node-panel-${theme}.png` })

      // Team panel — click the cluster's top-left (its label/header band, clear
      // of the node cards that sit on top of the cluster body). This closes the
      // node panel and opens the team panel in one gesture.
      await page
        .locator('[data-testid="team-cluster"][data-team="support"]')
        .click({ force: true, position: { x: 14, y: 14 } })
      await page.getByTestId('team-detail-panel').waitFor()
      await expect(page.getByTestId('team-detail-crossteam-count')).toBeVisible()
      await page.getByTestId('team-detail-panel').screenshot({ path: `${EVIDENCE_DIR}/team-panel-${theme}.png` })

      // Team filter — narrow to analytics.
      await page.locator('[data-testid="team-filter-item"][data-team="analytics"]').click()
      await page.waitForTimeout(500)
      await page.screenshot({ path: `${EVIDENCE_DIR}/filter-${theme}.png`, fullPage: true })
    })
  }
})
