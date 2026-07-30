/**
 * Review pass for AAASM-5184 — Topology no longer renders the unnamed-team
 * group as a team.
 *
 * The regression is driven from the *wire* shape the gateway actually emits
 * (`team_id: null`, which `aa-api`'s `project_graph_nodes` passes through
 * untouched), not from a view model handed straight to a component — so the
 * whole chain the defect lived in is exercised: mapper → page → sidebar →
 * canvas → detail panel.
 *
 * The ticket's own reproduction is the fixture: two agents, exactly one real
 * team. Before the fix that read "2 agents · 2 teams", offered a filter row
 * with an empty label, and drew a nameless cluster.
 *
 * What is asserted:
 *
 *  1. the header counts the one team that exists, not two;
 *  2. the unclaimed filter row carries a visible name, and never leaks the
 *     internal `__orphan__` key to the operator;
 *  3. the sidebar states the gap outright as `⚠ 1 unclaimed`;
 *  4. the canvas cluster is labelled rather than blank;
 *  5. clicking that cluster opens a panel with its own copy — the dead click
 *     AAASM-5140 removed is gone, not merely still absent;
 *  6. a fleet where *every* agent is unclaimed reports 0 teams, not 1;
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the payload is
 * injected with `page.route` at the network layer and the token is seeded with
 * `addInitScript` before any module runs — an in-page shim installed later
 * would never be seen.
 *
 * Screenshots land in dashboard/verify/5184/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5184')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** The internal group key — it must never reach the screen. */
const SENTINEL = '__orphan__'

function agent(over: Record<string, unknown>) {
  return {
    depth: 0,
    status: 'active',
    mode: 'enforce',
    flagged: false,
    trust: null,
    owner: 'ops',
    policy_count: 1,
    budget: { spend_usd: 3.0, limit_usd: 20.0 },
    effective_permissions: { chain: [], allow: [], deny: [], allow_restricted: false },
    ...over,
  }
}

/**
 * The ticket's reproduction: one agent on a real team, one the registry left
 * team-less. `team_id: null` is the gateway's own answer — `AgentNode.team_id`
 * is `Option<String>` and the graph projection never substitutes for it.
 */
const MIXED_NODES = [
  agent({ id: 'support-1', name: 'support-1', team_id: 'support' }),
  agent({ id: 'teamless-1', name: 'teamless-1', team_id: null }),
]

/**
 * The registry also accepts a *blank* team id — `validate_tenant_id`
 * (AAASM-4190) rejects control characters only — and the gateway folds it to no
 * team (`team_of`, AAASM-5182). It must reach the same group here, or the
 * nameless cluster returns through the other door.
 */
const WHITESPACE_TEAM_NODES = [
  agent({ id: 'support-1', name: 'support-1', team_id: 'support' }),
  agent({ id: 'blank-team-1', name: 'blank-team-1', team_id: '   ' }),
]

/** No agent belongs to a team at all — the count must be 0, not 1. */
const ALL_UNCLAIMED_NODES = [
  agent({ id: 'teamless-1', name: 'teamless-1', team_id: null }),
  agent({ id: 'teamless-2', name: 'teamless-2', team_id: null }),
]

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme, nodes: unknown[]): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted sockets are this run's own doing, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      // tokenStorage reads sessionStorage only.
      sessionStorage.setItem('aa_token', 'e2e-review-5184')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first; the specific routes registered after it win,
  // since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/topology', (r) => r.fulfill({ json: { nodes, edges: [], unclaimed_observable: true } }))
  await page.route('**/api/v1/topology/nodes/*/events', (r) => r.fulfill({ json: [] }))
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

const unclaimedCluster = (page: Page) => page.locator(`[data-testid="team-cluster"][data-team="${SENTINEL}"]`)
const unclaimedFilterRow = (page: Page) => page.locator(`[data-testid="team-filter-item"][data-team="${SENTINEL}"]`)

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

for (const theme of THEMES) {
  test.describe(`AAASM-5184 · ${theme}`, () => {
    test('the unclaimed group is named, counted apart, and no longer a phantom team', async ({ page }) => {
      const harness = await bootstrap(page, theme, MIXED_NODES)
      await gotoTopology(page)

      // 1. Two agents, one real team. The header used to say "2 teams".
      await expect(page.getByTestId('topology-meta')).toContainText('2 agents · 1 team')
      await expect(page.getByTestId('topology-meta')).not.toContainText('2 teams')

      // 2. The filter row has a visible name, and the sentinel stays internal.
      const row = unclaimedFilterRow(page)
      await expect(row).toBeVisible()
      await expect(row).toContainText(/unclaimed/i)
      await expect(row).not.toContainText(SENTINEL)

      // 3. The gap is stated rather than folded into the team count.
      await expect(page.getByTestId('topology-stat-unclaimed')).toContainText('1 unclaimed')

      // 4. The canvas cluster is labelled, not blank.
      const cluster = unclaimedCluster(page)
      await expect(cluster).toHaveAttribute('data-unclaimed', 'true')
      const label = cluster.getByTestId('team-cluster-label')
      await expect(label).toContainText(/unclaimed/i)
      await expect(label).not.toContainText(SENTINEL)

      // The real team is still drawn under its own name alongside it.
      await expect(
        page.locator('[data-testid="team-cluster"][data-team="support"]').getByTestId('team-cluster-label'),
      ).toContainText('support')

      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-unclaimed-${theme}.png`, fullPage: true })

      // 5. The cluster opens its own panel — AAASM-5140's dead click is gone.
      await cluster.click({ force: true })
      const panel = page.getByTestId('team-detail-panel')
      await expect(panel).toBeVisible()
      await expect(panel).toHaveAttribute('data-unclaimed', 'true')
      await expect(page.getByTestId('team-detail-unclaimed-note')).toContainText(
        /no team-scoped policy or budget/i,
      )
      // "cross-team edges" is a category error for a group that is not a team.
      await expect(page.getByTestId('team-detail-crossteam-count')).toHaveCount(0)
      await expect(panel).not.toContainText(SENTINEL)

      await page.screenshot({ path: `${EVIDENCE_DIR}/unclaimed-panel-${theme}.png`, fullPage: true })

      expect(harness.errors).toEqual([])
    })

    test('a fleet with no teams at all reports 0 teams', async ({ page }) => {
      const harness = await bootstrap(page, theme, ALL_UNCLAIMED_NODES)
      await gotoTopology(page)

      // The one grouping on screen is not a team, so the count is 0.
      await expect(page.getByTestId('topology-meta')).toContainText('2 agents · 0 teams')
      await expect(page.getByTestId('topology-stat-unclaimed')).toContainText('2 unclaimed')
      await expect(unclaimedCluster(page)).toBeVisible()

      await page.screenshot({ path: `${EVIDENCE_DIR}/all-unclaimed-${theme}.png`, fullPage: true })

      expect(harness.errors).toEqual([])
    })

    test('a whitespace-only team_id lands in the unclaimed group, not a nameless team', async ({ page }) => {
      const harness = await bootstrap(page, theme, WHITESPACE_TEAM_NODES)
      await gotoTopology(page)

      // One real team, not two — and no cluster whose label renders as blank.
      await expect(page.getByTestId('topology-meta')).toContainText('2 agents · 1 team')
      await expect(page.getByTestId('topology-stat-unclaimed')).toContainText('1 unclaimed')
      await expect(unclaimedFilterRow(page)).toContainText(/unclaimed/i)
      await expect(unclaimedCluster(page).getByTestId('team-cluster-label')).toContainText(/unclaimed/i)

      // Every cluster on the canvas carries a visible name.
      for (const label of await page.getByTestId('team-cluster-label').allInnerTexts()) {
        expect(label.replace(/[⚠\s]/g, '')).not.toBe('')
      }

      expect(harness.errors).toEqual([])
    })

    test('a fleet where every agent has a team is untouched', async ({ page }) => {
      const harness = await bootstrap(page, theme, [
        agent({ id: 'a', name: 'a', team_id: 'support' }),
        agent({ id: 'b', name: 'b', team_id: 'analytics' }),
      ])
      await gotoTopology(page)

      await expect(page.getByTestId('topology-meta')).toContainText('2 agents · 2 teams')
      // No unclaimed affordance appears where there is nothing to report.
      await expect(page.getByTestId('topology-stat-unclaimed')).toHaveCount(0)
      await expect(unclaimedCluster(page)).toHaveCount(0)
      await expect(unclaimedFilterRow(page)).toHaveCount(0)

      expect(harness.errors).toEqual([])
    })
  })
}
