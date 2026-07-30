/**
 * Review pass for AAASM-5099 — independent validation of the Topology page
 * against a realistic widened `GET /api/v1/topology` payload.
 *
 * Re-derives the claims a reviewer would otherwise have to take on trust, so a
 * regression shows up as a failure rather than as a screenshot nobody diffs:
 *
 *  1. all six relation kinds are drawn, and every edge-kind checkbox actually
 *     filters the canvas — including the four that shipped disabled;
 *  2. the cross-team badge and the cross-team toggle follow the server's
 *     `cross_team` flag, not a client re-derivation;
 *  3. the policy-inheritance chain renders one row per cascade tier, with a
 *     tier that carries no document reading `none` and the merged effective
 *     row summarising the real allow/deny;
 *  4. a node whose payload carries no chain folds to the shared `—`
 *     affordance — never to a fabricated empty chain;
 *  5. the page produces no console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5099/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5099')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * The widened projection's real shape. `planner` carries a full cascade;
 * `worker-a` deliberately omits `effective_permissions` — that is the field the
 * gateway leaves absent when no chain is resolved, and the point of the run is
 * that the panel treats "absent" and "empty" as different things.
 */
const NODES = [
  {
    id: 'planner', name: 'planner', depth: 0, status: 'active', team_id: 'support',
    mode: 'enforce', flagged: false, trust: null, owner: 'platform-team',
    policy_count: 2, budget: { spend_usd: 4.1, limit_usd: 100.0 },
    effective_permissions: {
      chain: [
        { tier: 'global', scope: 'global', policies: ['baseline'] },
        // A tier that applies but carries no document — real state, not missing data.
        { tier: 'team', scope: 'team:support', policies: [] },
        { tier: 'agent', scope: 'agent:planner', policies: ['planner-override'] },
      ],
      allow: ['file_read'],
      deny: ['terminal_exec'],
      allow_restricted: true,
    },
  },
  {
    // No effective_permissions key at all.
    id: 'worker-a', name: 'worker-a', depth: 1, status: 'active', team_id: 'support',
    mode: 'shadow', flagged: false, trust: null, owner: 'ml-team',
    policy_count: 1, budget: { spend_usd: 2.5, limit_usd: 40.0 },
  },
  {
    id: 'analyst', name: 'analyst', depth: 0, status: 'active', team_id: 'analytics',
    mode: 'enforce', flagged: false, trust: null, owner: 'data-team',
    policy_count: 1, budget: { spend_usd: 12.0, limit_usd: 60.0 },
    effective_permissions: {
      chain: [{ tier: 'global', scope: 'global', policies: [] }],
      allow: [], deny: [], allow_restricted: false,
    },
  },
]

/** One edge of every stored kind; the four cross-team ones span support↔analytics. */
const EDGES = [
  { source: 'planner', target: 'worker-a', kind: 'delegation', cross_team: false },
  { source: 'worker-a', target: 'planner', kind: 'call', cross_team: false },
  { source: 'planner', target: 'analyst', kind: 'reads', cross_team: true },
  { source: 'analyst', target: 'planner', kind: 'writes', cross_team: true },
  { source: 'worker-a', target: 'analyst', kind: 'approves', cross_team: true },
  { source: 'analyst', target: 'worker-a', kind: 'messages', cross_team: true },
]
const CROSS_TEAM_EDGES = EDGES.filter((e) => e.cross_team).length

const LINEAGE = {
  agent_id: 'planner',
  ancestor_count: 1,
  ancestors: [{ id: 'planner', name: 'planner', depth: 0, team_id: 'support' }],
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text())
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5099')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/topology', (r) => r.fulfill({ json: { nodes: NODES, edges: EDGES, cascade_loaded: true } }))
  await page.route('**/api/v1/topology/nodes/*/events', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology/lineage/**', (r) => r.fulfill({ json: LINEAGE }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

async function gotoTopology(page: Page) {
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/topology'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('topology-graph').waitFor()
  await page.waitForTimeout(700) // let d3-force settle
}

/** Kinds currently drawn on the canvas, in DOM order. */
function drawnKinds(page: Page) {
  return page.getByTestId('topology-edge').evaluateAll((els) =>
    els.map((e) => e.getAttribute('data-kind')),
  )
}

async function toggleKind(page: Page, kind: string) {
  await page.locator(`[data-testid="topology-edge-toggle"][data-kind="${kind}"] input`).click()
}

test.describe('AAASM-5099 review — widened topology projection', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`six kinds, cross-team flag and inheritance chain hold up in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await gotoTopology(page)

      // ── 1. all six kinds are drawn and every checkbox is live ────────────
      const toggles = page.getByTestId('topology-edge-toggle')
      await expect(toggles).toHaveCount(6)
      // None is the disabled "soon" row any more.
      await expect(page.locator('[data-testid="topology-edge-toggle"][data-available="false"]')).toHaveCount(0)
      await expect(page.locator('[data-testid="topology-edge-toggle"] input:disabled')).toHaveCount(0)

      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length)
      expect(new Set(await drawnKinds(page))).toEqual(
        new Set(['delegation', 'call', 'reads', 'writes', 'approves', 'messages']),
      )
      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-six-kinds-${theme}.png`, fullPage: true })

      // ── 2. the checkboxes actually filter ───────────────────────────────
      // Uncheck a kind that shipped disabled: its edge must leave the canvas.
      await toggleKind(page, 'reads')
      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length - 1)
      expect(await drawnKinds(page)).not.toContain('reads')
      await toggleKind(page, 'messages')
      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length - 2)
      expect(await drawnKinds(page)).not.toContain('messages')
      await page.screenshot({ path: `${EVIDENCE_DIR}/edge-kind-filter-${theme}.png`, fullPage: true })
      // Restore.
      await toggleKind(page, 'reads')
      await toggleKind(page, 'messages')
      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length)

      // ── 3. cross-team follows the server flag ───────────────────────────
      await expect(page.getByTestId('topology-stat-crossteam')).toContainText(
        `${CROSS_TEAM_EDGES} cross-team`,
      )
      await expect(page.locator('[data-testid="topology-edge"][data-cross-team="true"]')).toHaveCount(
        CROSS_TEAM_EDGES,
      )
      // Turning the toggle off removes exactly the flagged edges.
      await page.getByTestId('topology-crossteam-toggle').locator('input').click()
      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length - CROSS_TEAM_EDGES)
      await expect(page.locator('[data-testid="topology-edge"][data-cross-team="true"]')).toHaveCount(0)
      await page.getByTestId('topology-crossteam-toggle').locator('input').click()
      await expect(page.getByTestId('topology-edge')).toHaveCount(EDGES.length)

      // ── 4. the inheritance chain renders from real tiers ────────────────
      await page.locator('[data-testid="topology-node"]', { hasText: 'planner' }).first().click({ force: true })
      await page.getByTestId('node-detail-panel').waitFor()
      const chain = page.getByTestId('node-detail-inheritance-chain')
      await expect(chain).toBeVisible()
      const tiers = page.getByTestId('node-detail-inheritance-tier')
      await expect(tiers).toHaveCount(3)
      await expect(tiers.nth(0)).toContainText('baseline')
      // The team tier applies but carries no document — "none", not "—".
      await expect(tiers.nth(1)).toContainText('team (support)')
      await expect(tiers.nth(1)).toContainText('none')
      await expect(tiers.nth(2)).toContainText('planner-override')
      const effective = page.getByTestId('node-detail-inheritance-effective')
      await expect(effective).toContainText('allow-list enforced')
      await expect(effective).toContainText('1 denied')
      await page.getByTestId('node-detail-panel').screenshot({
        path: `${EVIDENCE_DIR}/inheritance-chain-${theme}.png`,
      })

      // Nothing invented a placeholder value anywhere on the panel.
      await expect(page.getByTestId('node-detail-panel')).not.toContainText('undefined')
      await expect(page.getByTestId('node-detail-panel')).not.toContainText('NaN')

      // ── 5. an absent chain folds to `—` ─────────────────────────────────
      await page.locator('[data-testid="topology-node"]', { hasText: 'worker-a' }).first().click({ force: true })
      await page.getByTestId('node-detail-panel').waitFor()
      await expect(page.getByTestId('node-detail-inheritance-chain')).toHaveCount(0)
      await expect(page.getByTestId('node-detail-inheritance-empty')).toHaveText('—')
      await page.getByTestId('node-detail-panel').screenshot({
        path: `${EVIDENCE_DIR}/inheritance-absent-${theme}.png`,
      })

      // ── 6. clean console ────────────────────────────────────────────────
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
