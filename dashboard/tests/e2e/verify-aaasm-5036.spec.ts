/**
 * Verification capture for AAASM-5036 — topology badges driven by real API
 * fields.
 *
 * AAASM-5033 built the mode / flagged badges (and left trust backend-gated), but
 * the topology API response did not carry those per-node fields. AAASM-5036
 * extends the topology response (`AgentNode` / `AgentTree`) to carry per-node
 * `mode` (from `metadata.mode`), `flagged` (`policy_violations_count >=
 * threshold`), and a nullable `trust`, and wires the graph to consume them.
 *
 * This evidence spec stands the page up against a mocked `/api/v1/topology`
 * fixture whose nodes carry mode/flagged/trust exactly as the extended API now
 * emits them, asserts the badges render from that data, and screenshots the
 * graph in light and dark themes into `dashboard/verify/5036/`.
 *
 * Note on trust: the backend currently sends `trust: null` for every node (no
 * trust-analytics source exists yet), which keeps the badge hidden. To prove the
 * wiring, a couple of fixture nodes carry a numeric trust so the badge is
 * visible; a null-trust node in the same fixture shows the hidden case.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5036')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

// Fixture mirrors what the extended topology API now emits per node: mode +
// flagged on every node, trust as a number where a score exists and null
// otherwise. `planner` is the sole delegation root; the support team spans the
// enforce/shadow/off modes and a flagged worker.
const NODES = [
  { id: 'planner', name: 'planner', framework: 'langgraph', owner: 'alice', team: 'support', status: 'active', policyCount: 3, budgetSpend: 1, budgetLimit: 10, mode: 'enforce', flagged: false, trust: 92 },
  { id: 'worker-a', name: 'worker-a', framework: 'langchain', owner: 'alice', team: 'support', status: 'idle', policyCount: 2, budgetSpend: 6, budgetLimit: 10, mode: 'shadow', flagged: false, trust: 74 },
  { id: 'worker-b', name: 'worker-b', framework: 'crewai', owner: 'alice', team: 'support', status: 'error', policyCount: 1, budgetSpend: 9.4, budgetLimit: 10, mode: 'off', flagged: true, trust: null },
  { id: 'runner', name: 'ops-runner', framework: 'autogen', owner: 'carol', team: 'ops', status: 'active', policyCount: 2, budgetSpend: 4, budgetLimit: 10, mode: 'enforce', flagged: false, trust: 55 },
]

const EDGES = [
  { source: 'planner', target: 'worker-a', kind: 'delegation' },
  { source: 'planner', target: 'worker-b', kind: 'delegation' },
]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      // The dashboard reads the JWT from sessionStorage (see auth/tokenStorage.ts).
      sessionStorage.setItem('aa_token', 'e2e-verify-5036')
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

test.describe('AAASM-5036 — topology badges driven by API mode/flagged/trust', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`renders mode/flagged/trust badges from API data in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)
      await gotoTopology(page)

      // Mode badge, straight from the node's API `mode` field.
      await expect(
        page.locator('[data-testid="topology-node"][data-mode="shadow"]').first(),
      ).toBeVisible()
      await expect(
        page.locator('[data-testid="topology-node"][data-mode="off"]').first(),
      ).toBeVisible()

      // Flagged treatment, from the API `flagged` field.
      await expect(
        page.locator('[data-testid="topology-node"][data-flagged="true"]'),
      ).toHaveCount(1)

      // Trust badge renders only for nodes carrying a numeric trust; the
      // null-trust node keeps it hidden. Three of four fixture nodes have a
      // number, so three trust badges render.
      await expect(page.getByTestId('topology-node-trust')).toHaveCount(3)
      await expect(
        page.locator('[data-testid="topology-node"][data-trust]'),
      ).toHaveCount(3)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/topology-badges-${theme}.png`,
        fullPage: true,
      })
    })
  }

  test('captures a close-up of the badge-bearing graph', async ({ page }) => {
    await bootstrap(page, 'light')
    await gotoTopology(page)
    const graph = page.getByTestId('topology-graph')
    await expect(page.getByTestId('topology-node-trust').first()).toBeVisible()
    await graph.screenshot({ path: `${EVIDENCE_DIR}/topology-badges-closeup.png` })
  })
})
