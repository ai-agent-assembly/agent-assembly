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
    // A third team, reachable only from `analytics`. Filtering to `support`
    // leaves this crossing counted, undrawn, and touching no visible node — the
    // case a per-node badge structurally cannot represent.
    agentNode('p1', 'payments-one', 'payments', { spend_usd: 2, limit_usd: 10 }),
  ],
  edges: [
    { source: 's1', target: 's2', kind: 'delegation', cross_team: false },
    { source: 's1', target: 'a1', kind: 'call', cross_team: true },
    { source: 's1', target: 'a2', kind: 'call', cross_team: true },
    { source: 's2', target: 'a1', kind: 'reads', cross_team: true },
    { source: 'a1', target: 'p1', kind: 'call', cross_team: true },
  ],
}

/** Cross-team edges in the fixture; the sidebar must report exactly this. */
const CROSS_TEAM_TOTAL = 4
/** Crossings that touch `support` — the three the badges can account for. */
const SUPPORT_CROSSINGS = 3

interface Harness {
  errors: string[]
  /** How many times `GET /api/v1/topology` has been served. */
  graphRequests: () => number
}

async function bootstrap(page: Page, theme: Theme, options: { drift?: boolean } = {}): Promise<Harness> {
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
  // With `drift`, every poll returns *different* spend figures.
  //
  // That matters: serving byte-identical JSON lets TanStack Query's structural
  // sharing hand back the previous object, so the re-render path a live fleet
  // actually takes would never be exercised and a re-scattering graph would
  // still look green. Only the polling test needs it — the assertions about
  // specific budget figures want a stable payload.
  await page.route(
    (u) => u.pathname === '/api/v1/topology',
    (r) => {
      graphRequests += 1
      if (options.drift !== true) return r.fulfill({ json: GRAPH })
      // Small enough that no card crosses a size-bucket threshold: the card
      // grows with burn ratio, so a larger nudge would legitimately change the
      // `transform` (position minus half the new width) and the stability
      // assertion would be measuring a resize rather than a re-scatter.
      const nudge = graphRequests * 0.05
      return r.fulfill({
        json: {
          ...GRAPH,
          nodes: GRAPH.nodes.map((n) => ({
            ...n,
            budget: { ...n.budget, spend_usd: Number((n.budget.spend_usd + nudge).toFixed(2)) },
          })),
        },
      })
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

      const crossTeamStat = page.getByTestId('topology-stat-crossteam')
      const hiddenStat = page.getByTestId('topology-stat-crossteam-hidden')
      const drawnCrossings = page.locator('[data-testid="topology-edge"][data-cross-team="true"]')

      // Unfiltered: the count and the canvas agree directly, so there is nothing
      // to disclose.
      await expect(crossTeamStat).toContainText(`${CROSS_TEAM_TOTAL} cross-team`)
      await expect(drawnCrossings).toHaveCount(CROSS_TEAM_TOTAL)
      await expect(hiddenStat).toHaveCount(0)
      await expect(page.getByTestId('topology-node-crossteam')).toHaveCount(0)

      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-unfiltered-${theme}.png`, fullPage: true })

      // ── The ≥3-team break ────────────────────────────────────────────────
      // Filter to `support`. Three crossings touch it; the fourth (analytics →
      // payments) touches no visible node at all, so no badge can represent it.
      // An earlier revision of this lane claimed badges reconciled the counter;
      // this is the shape that disproves it.
      await page.locator('[data-testid="team-filter-item"][data-team="support"]').click()
      await expect(page.getByTestId('topology-node')).toHaveCount(2)
      await expect(drawnCrossings).toHaveCount(0)

      // The fleet-wide count is not narrowed to match the picture...
      await expect(crossTeamStat).toContainText(`${CROSS_TEAM_TOTAL} cross-team`)
      // ...the gap is stated instead, and it covers all four — including the one
      // the badges cannot reach.
      await expect(hiddenStat).toHaveAttribute('data-hidden-count', String(CROSS_TEAM_TOTAL))
      await expect(hiddenStat).toContainText(`${CROSS_TEAM_TOTAL} not shown`)

      // The badges keep their own narrower job: which *visible* agents have
      // relationships the view is not drawing.
      const badged = await page
        .getByTestId('topology-node-crossteam')
        .evaluateAll((els) => els.reduce((total, el) => total + Number(el.getAttribute('data-count')), 0))
      expect(badged, 'badges cover only the filtered team’s own crossings').toBe(SUPPORT_CROSSINGS)
      await expect(nodeCard(page, 'unbudgeted').getByTestId('topology-node-crossteam')).toContainText('⇆2')

      await page.getByTestId('topology-graph-wrap').screenshot({
        path: `${EVIDENCE_DIR}/topology-filtered-crossteam-badges-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/topology-filtered-${theme}.png`, fullPage: true })

      // ── The `showCrossTeam` break ────────────────────────────────────────
      // Back to the whole fleet, then uncheck the toggle sitting directly beside
      // the counter. Every node is on screen and every curve is gone, so no
      // badge renders at all — verbatim the defect this ticket set out to fix,
      // reachable without any team filter.
      await page.locator('[data-testid="team-filter-item"][data-team="all"]').click()
      await expect(drawnCrossings).toHaveCount(CROSS_TEAM_TOTAL)
      await page.getByTestId('topology-crossteam-toggle').locator('input').uncheck()

      await expect(drawnCrossings).toHaveCount(0)
      await expect(page.getByTestId('topology-node-crossteam')).toHaveCount(0)
      await expect(crossTeamStat).toContainText(`${CROSS_TEAM_TOTAL} cross-team`)
      await expect(hiddenStat).toHaveAttribute('data-hidden-count', String(CROSS_TEAM_TOTAL))

      await page.getByTestId('topology-stats').screenshot({
        path: `${EVIDENCE_DIR}/topology-crossteam-hidden-toggle-${theme}.png`,
      })

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

  test('polling updates the figures without re-scattering the graph', async ({ page }) => {
    // The route above serves a *different* payload each poll, so this exercises
    // the path a live fleet actually takes. Re-simulating on every changed
    // payload would move every card — and therefore every click target — under
    // the operator every five seconds.
    const harness = await bootstrap(page, 'light', { drift: true })
    await openTopology(page)

    const cards = page.getByTestId('topology-node')
    await expect(cards).toHaveCount(GRAPH.nodes.length)

    // Let the force layout settle before sampling, so the comparison is against
    // a resting graph rather than one still finding its shape.
    const positions = async () =>
      cards.evaluateAll((els) => els.map((el) => el.getAttribute('transform')))
    const buckets = async () =>
      cards.evaluateAll((els) => els.map((el) => el.getAttribute('data-size-bucket')))
    let previous = await positions()
    await expect
      .poll(async () => {
        const current = await positions()
        const stable = JSON.stringify(current) === JSON.stringify(previous)
        previous = current
        return stable
      }, { message: 'force layout settles', timeout: 15_000 })
      .toBe(true)

    const settled = await positions()
    const budgetText = async () =>
      page.getByTestId('topology-node-budget').evaluateAll((els) => els.map((el) => el.textContent ?? ''))
    const budgetsBefore = await budgetText()
    const bucketsBefore = await buckets()
    const requestsBefore = harness.graphRequests()

    // Span at least two polls.
    await expect
      .poll(() => harness.graphRequests(), { timeout: 20_000 })
      .toBeGreaterThanOrEqual(requestsBefore + 2)

    // Guard the guard: if a card had resized, `transform` would change for a
    // legitimate reason and this assertion would be meaningless.
    expect(await buckets(), 'no card resized during the run').toEqual(bucketsBefore)
    expect(await positions(), 'cards do not move when only the figures change').toEqual(settled)

    // And the figures really did move — "stop re-scattering" must not have
    // become "stop updating".
    expect(await budgetText(), 'spend figures advanced').not.toEqual(budgetsBefore)

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })
})
