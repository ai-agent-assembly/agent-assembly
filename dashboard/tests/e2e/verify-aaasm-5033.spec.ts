/**
 * Verification capture for AAASM-5033 — topology node badges + cycle detection.
 *
 * Wires the affordances the topology-design-fidelity spec (AAASM-1384) called
 * out as "not yet wired": the root/depth badge, the enforcement-mode badge, the
 * flagged treatment, and the delegation-cycle marker. Root, depth, and cycle
 * are all computed client-side from the delegation edge data
 * (`features/topology/hierarchy.ts`); mode/flagged come from the node fields.
 *
 * Evidence-capture spec, not a pixel baseline: it stands the page up against a
 * mocked `/api/v1/topology` fixture that contains a delegation tree AND a
 * delegation cycle, asserts the badges/markers rendered, then screenshots the
 * graph in both light and dark themes into `dashboard/verify/5033/` for review
 * next to `design/v1/hi-fi/topology.jsx`.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5033')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

// Fixture: a "support" delegation tree (root + two delegates, mixed modes,
// one flagged) and an "ops" delegation cycle (alpha ⇄ beta) plus an acyclic
// tail (beta → gamma). Budgets span the small/medium/large buckets.
const NODES = [
  { id: 'planner', name: 'planner', framework: 'langgraph', owner: 'alice', team: 'support', status: 'active', policyCount: 3, budgetSpend: 1, budgetLimit: 10, mode: 'enforce' },
  { id: 'worker-a', name: 'worker-a', framework: 'langchain', owner: 'alice', team: 'support', status: 'idle', policyCount: 2, budgetSpend: 6, budgetLimit: 10, mode: 'shadow' },
  { id: 'worker-b', name: 'worker-b', framework: 'crewai', owner: 'alice', team: 'support', status: 'error', policyCount: 1, budgetSpend: 9.4, budgetLimit: 10, mode: 'off', flagged: true },
  { id: 'alpha', name: 'ops-alpha', framework: 'autogen', owner: 'carol', team: 'ops', status: 'active', policyCount: 2, budgetSpend: 4, budgetLimit: 10, mode: 'enforce', flagged: true },
  { id: 'beta', name: 'ops-beta', framework: 'autogen', owner: 'carol', team: 'ops', status: 'active', policyCount: 2, budgetSpend: 5.5, budgetLimit: 10, mode: 'enforce', flagged: true },
  { id: 'gamma', name: 'ops-gamma', framework: 'autogen', owner: 'carol', team: 'ops', status: 'idle', policyCount: 1, budgetSpend: 0.5, budgetLimit: 10, mode: 'shadow' },
]

const EDGES = [
  { source: 'planner', target: 'worker-a', kind: 'delegation' },
  { source: 'planner', target: 'worker-b', kind: 'delegation' },
  { source: 'alpha', target: 'beta', kind: 'delegation' },
  { source: 'beta', target: 'alpha', kind: 'delegation' },
  { source: 'beta', target: 'gamma', kind: 'delegation' },
]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      // The dashboard reads the JWT from sessionStorage (see auth/tokenStorage.ts).
      sessionStorage.setItem('aa_token', 'e2e-verify-5033')
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
  // Let d3-force settle so the depth-informed layout arranges before capture.
  await page.waitForTimeout(600)
}

test.describe('AAASM-5033 — topology badges + cycle detection', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`renders root/depth/mode/flagged/cycle badges in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)
      await gotoTopology(page)

      // Root vs depth badge. Only `planner` has no incoming delegation edge, so
      // it is the sole root; every other node is a delegate at depth ≥ 1.
      await expect(
        page.locator('[data-testid="topology-node"][data-root="true"]'),
      ).toHaveCount(1)
      const rootBadges = page.locator('[data-testid="topology-node-depth"]', { hasText: 'root' })
      await expect(rootBadges.first()).toBeVisible()

      // Mode badge present on a moded node.
      await expect(
        page.locator('[data-testid="topology-node"][data-mode="shadow"]').first(),
      ).toBeVisible()

      // Flagged treatment.
      await expect(
        page.locator('[data-testid="topology-node"][data-flagged="true"]').first(),
      ).toBeVisible()

      // Delegation cycle markers: alpha ⇄ beta are both on a cycle.
      await expect(
        page.locator('[data-testid="topology-node"][data-in-cycle="true"]'),
      ).toHaveCount(2)
      await expect(page.getByTestId('topology-node-cycle').first()).toBeVisible()

      await page.screenshot({
        path: `${EVIDENCE_DIR}/topology-badges-${theme}.png`,
        fullPage: true,
      })
    })
  }

  test('captures a close-up of the delegation cycle', async ({ page }) => {
    await bootstrap(page, 'light')
    await gotoTopology(page)
    const graph = page.getByTestId('topology-graph')
    await expect(
      page.locator('[data-testid="topology-node"][data-in-cycle="true"]'),
    ).toHaveCount(2)
    await graph.screenshot({ path: `${EVIDENCE_DIR}/topology-badges-cycle.png` })
  })
})
