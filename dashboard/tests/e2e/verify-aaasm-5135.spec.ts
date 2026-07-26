/**
 * Verification pass for the Topology truthfulness lane — AAASM-5135 / 5136 /
 * 5138 / 5140.
 *
 * The unit tests mock the query hook, so they prove each *component* reacts to
 * a null budget limit or a hidden edge. They cannot prove the wiring: that a
 * real `limit_usd: null` travelling over HTTP, through `mapTopologyGraph` and
 * TanStack Query, still reaches the operator as `—` rather than as `$0.00`.
 * That is what this run drives, over the network layer, in a real browser.
 *
 * Four claims, each in light and dark:
 *
 *  1. **5135** — an agent whose `budget.limit_usd` is `null` renders no `$0`
 *     ceiling and no `aria-valuenow=0`, on the card, in the node panel, and on
 *     its team's cluster bar. An agent that *does* have a ceiling still shows a
 *     real percentage, so the fix is not simply blanking the surface.
 *  2. **5138** — with a team filter active, the sidebar's cross-team counter and
 *     the canvas agree: every crossing is either drawn or carries a `⇆N` badge.
 *  3. **5140** — the two governance buttons cannot be activated.
 *  4. **5136** — the graph actually re-fetches on the ratified 5s cadence,
 *     counted at the network layer rather than read back off the query options.
 *
 * `page.route` is used rather than a `fetch` shim because the generated client
 * captures `globalThis.fetch` at module load; a shim installed later would never
 * be consulted. The auth token is seeded via `addInitScript` for the same
 * reason — it has to exist before any module body runs.
 *
 * Screenshots land in dashboard/verify/5135/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5135')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

interface WireBudget {
  spend_usd: number
  limit_usd: number | null
}

function agentNode(
  id: string,
  name: string,
  team: string,
  budget: WireBudget,
  depth = 0,
) {
  return {
    id,
    name,
    depth,
    status: 'active',
    team_id: team,
    mode: 'enforce',
    flagged: false,
    trust: null,
    owner: 'platform-team',
    policy_count: 3,
    budget,
  }
}

/**
 * `unbudgeted` is the ticket's case: the server resolved neither a per-agent
 * override nor a server-wide daily limit, so `limit_usd` is `null`.
 * `has-ceiling` sits beside it with a real limit, which is the control — the page must keep
 * reporting a genuine percentage for it.
 *
 * `support` therefore has a hole in its team total; `analytics` does not.
 */
const GRAPH = {
  nodes: [
    agentNode('s1', 'unbudgeted', 'support', { spend_usd: 4.1, limit_usd: null }),
    agentNode('s2', 'has-ceiling', 'support', { spend_usd: 2, limit_usd: 10 }, 1),
    agentNode('a1', 'analyst-one', 'analytics', { spend_usd: 4, limit_usd: 10 }),
    agentNode('a2', 'analyst-two', 'analytics', { spend_usd: 1, limit_usd: 10 }, 1),
  ],
  edges: [
    { source: 's1', target: 's2', kind: 'delegation', cross_team: false },
    { source: 's1', target: 'a1', kind: 'call', cross_team: true },
    { source: 's1', target: 'a2', kind: 'call', cross_team: true },
    { source: 's2', target: 'a1', kind: 'reads', cross_team: true },
  ],
}

/** Cross-team edges in the fixture; the sidebar must report exactly this. */
const CROSS_TEAM_TOTAL = 3

interface Harness {
  errors: string[]
  /** How many times `GET /api/v1/topology` has been served. */
  graphRequests: () => number
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text())
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5135')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  let graphRequests = 0

  // Permissive fallback first (least specific); the URL-predicate routes below
  // are registered afterwards and win, since Playwright matches most-recently
  // -added first. Predicates rather than globs so `/topology`, `/topology/nodes`
  // and `/topology/lineage` cannot shadow one another.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route(
    (u) => u.pathname.startsWith('/api/v1/topology/nodes/'),
    (r) => r.fulfill({ json: [] }),
  )
  await page.route(
    (u) => u.pathname.startsWith('/api/v1/topology/lineage/'),
    (r) => r.fulfill({ json: { ancestors: [] } }),
  )
  await page.route(
    (u) => u.pathname === '/api/v1/topology',
    (r) => {
      graphRequests += 1
      return r.fulfill({ json: GRAPH })
    },
  )

  return { errors, graphRequests: () => graphRequests }
}

async function openTopology(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/topology')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('topology-view')).toBeVisible()
  await expect(page.getByTestId('topology-sidebar')).toBeVisible()
}

function teamBar(page: Page, team: string) {
  return page.getByTestId('team-budget-bar').and(page.locator(`[data-team="${team}"]`))
}

function nodeCard(page: Page, name: string) {
  return page.getByTestId('topology-node').filter({ hasText: name })
}

test.describe('AAASM-5135 — Topology asserts only the budgets it was given', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`an unconfigured limit never renders as $0 (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await openTopology(page)

      // ── 5135: the node card ──────────────────────────────────────────────
      const unbudgetedCard = nodeCard(page, 'unbudgeted')
      await expect(unbudgetedCard).toBeVisible()
      const cardBudget = unbudgetedCard.getByTestId('topology-node-budget')
      await expect(cardBudget).toHaveAttribute('data-truth-state', 'unconfigured')
      expect(await cardBudget.textContent()).toContain('$4.1')
      expect(await cardBudget.textContent()).not.toContain('$0')

      // The control: a real ceiling still renders as one, so the fix did not
      // simply blank every budget on the page.
      const budgetedCard = nodeCard(page, 'has-ceiling')
      const knownBudget = budgetedCard.getByTestId('topology-node-budget')
      await expect(knownBudget).not.toHaveAttribute('data-truth-state', 'unconfigured')
      expect(await knownBudget.textContent()).toContain('/ $10')

      // ── 5135: the team cluster bar ───────────────────────────────────────
      // `support` contains the unbudgeted agent, so its total has a hole in it.
      const support = teamBar(page, 'support')
      await expect(support).toHaveAttribute('data-truth-state', 'unconfigured')
      await expect(support).not.toHaveAttribute('aria-valuenow', /.*/)
      await expect(support.getByTestId('team-budget-bar-amount')).not.toContainText('0%')
      await expect(support.getByTestId('team-budget-bar-no-limit')).toBeVisible()

      // `analytics` is fully configured and still reports a real percentage:
      // spent 5 of 20 → 25%.
      const analytics = teamBar(page, 'analytics')
      await expect(analytics).toHaveAttribute('aria-valuenow', '25')
      await expect(analytics).toContainText('$5 / $20 · 25%')

      // ── 5135: the node detail panel ──────────────────────────────────────
      await unbudgetedCard.click()
      await expect(page.getByTestId('node-detail-panel')).toBeVisible()

      const progress = page.getByTestId('node-detail-progress')
      await expect(progress).toHaveAttribute('data-truth-state', 'unconfigured')
      // The headline defect: an unknown ceiling announced as a wholly unburnt
      // budget. ARIA's own encoding of "unknown" is the absence of the value.
      await expect(progress).not.toHaveAttribute('aria-valuenow', /.*/)

      const budgetSection = page.getByTestId('node-detail-budget')
      await expect(budgetSection).toContainText('$4.10')
      await expect(budgetSection).not.toContainText('$0.00')
      await expect(budgetSection).not.toContainText('0%')
      await expect(page.getByTestId('node-detail-budget-limit')).toHaveAttribute(
        'data-truth-state',
        'unconfigured',
      )
      // Blank is not enough — the absence has to be audible.
      await expect(budgetSection).toContainText('Unconfigured')

      // ── 5135 scope correction: policy_count is NOT absent ────────────────
      // The graph endpoint sets it unconditionally (topology.rs:427), so the
      // panel is entitled to state it. The ticket claimed otherwise.
      await expect(page.getByTestId('node-detail-policy-count')).toContainText('3 policies')

      // ── 5140: the two dead governance buttons ────────────────────────────
      const applyPolicy = page.getByTestId('node-detail-apply-policy')
      const shadowMode = page.getByTestId('node-detail-shadow-mode')
      await expect(applyPolicy).toBeDisabled()
      await expect(shadowMode).toBeDisabled()
      await expect(applyPolicy).toHaveAttribute('title', /not available yet/i)
      await expect(shadowMode).toHaveAttribute('title', /not available yet/i)
      // The real actions beside them stay usable.
      await expect(page.getByTestId('node-detail-suspend')).toBeEnabled()

      await expect(page.getByTestId('topology-view')).not.toContainText('NaN')
      await expect(page.getByTestId('topology-view')).not.toContainText('undefined')

      await page.getByTestId('node-detail-budget').screenshot({
        path: `${EVIDENCE_DIR}/node-panel-budget-unconfigured-${theme}.png`,
      })
      await page.getByTestId('node-detail-actions').screenshot({
        path: `${EVIDENCE_DIR}/node-panel-dead-actions-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-budgets-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`the team filter hides no crossing without accounting for it (${theme})`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await openTopology(page)

      // Unfiltered: the sidebar's count and the canvas agree directly.
      const crossTeamStat = page.getByTestId('topology-stat-crossteam')
      await expect(crossTeamStat).toContainText(`${CROSS_TEAM_TOTAL} cross-team`)
      await expect(page.locator('[data-testid="topology-edge"][data-cross-team="true"]')).toHaveCount(
        CROSS_TEAM_TOTAL,
      )
      await expect(page.getByTestId('topology-node-crossteam')).toHaveCount(0)

      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-unfiltered-${theme}.png`, fullPage: true })

      // Filter to `support`, whose two agents hold all three crossings.
      await page.locator('[data-testid="team-filter-item"][data-team="support"]').click()
      await expect(page.getByTestId('topology-node')).toHaveCount(2)

      // The canvas can no longer draw any crossing — each has a hidden endpoint.
      await expect(page.locator('[data-testid="topology-edge"][data-cross-team="true"]')).toHaveCount(0)
      // The counter still reports all three, and all three are still on screen
      // as badges. This is the agreement the ticket is about.
      await expect(crossTeamStat).toContainText(`${CROSS_TEAM_TOTAL} cross-team`)

      const badges = page.getByTestId('topology-node-crossteam')
      await expect(badges).toHaveCount(2)
      const badged = await badges.evaluateAll((els) =>
        els.reduce((total, el) => total + Number(el.getAttribute('data-count')), 0),
      )
      expect(badged, 'every hidden crossing is accounted for by a badge').toBe(CROSS_TEAM_TOTAL)

      // Before the fix this view showed no cross-team edges and no badges —
      // indistinguishable from a team with no external dependencies at all.
      await expect(nodeCard(page, 'unbudgeted').getByTestId('topology-node-crossteam')).toContainText('⇆2')

      await page.getByTestId('topology-graph-wrap').screenshot({
        path: `${EVIDENCE_DIR}/topology-filtered-crossteam-badges-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-filtered-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }

  test('the ratified 5s poll actually issues repeat requests', async ({ page }) => {
    // Counted at the network layer: reading `refetchInterval` back off the query
    // options would only prove the value was passed, which is exactly what
    // ADR-0017 item 3 recorded for two years without it ever being true.
    const harness = await bootstrap(page, 'light')
    await openTopology(page)

    expect(harness.graphRequests()).toBeGreaterThanOrEqual(1)
    await expect
      .poll(() => harness.graphRequests(), {
        message: 'topology re-fetches on the 5s interval',
        timeout: 20_000,
      })
      .toBeGreaterThanOrEqual(3)

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })
})
