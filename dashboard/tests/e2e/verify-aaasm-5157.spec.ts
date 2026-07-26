/**
 * Verification pass for the Teams grouping fix — AAASM-5157.
 *
 * The unit tests mock the query hooks, so they prove the *component* groups a
 * team-less spawned agent correctly. They cannot prove the wiring: that the
 * page really stopped reading `/topology/overview`'s root-only
 * `standalone_root_agents` and now reads the whole fleet from
 * `GET /api/v1/topology`. This run drives that over the network layer, in a real
 * browser, with an overview response that deliberately omits the spawned agent.
 *
 * Three scenarios, each in light and dark:
 *
 *  1. **governed** — the fleet contains a root orphan and a spawned orphan; the
 *     overview lists only the root one. Both must appear under "unclaimed",
 *     exactly once each, and the count chip must equal the list length.
 *  2. **disagreement** — the registry's `total_agent_count` exceeds what the
 *     groupings can reach. The page must say so rather than silently picking
 *     one of the two numbers.
 *  3. **degraded** — the fleet request 503s. Nothing may read as "everything is
 *     governed": no `0` chip, no "No unclaimed agents."
 *
 * `page.route` is used rather than a `fetch` shim because the generated client
 * captures `globalThis.fetch` at module load; a shim installed later would never
 * be consulted. The auth token is seeded via `addInitScript` for the same
 * reason — it has to exist before any module body runs.
 *
 * Screenshots land in dashboard/verify/5157/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5157')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

interface WireAgent {
  id: string
  name: string
  status: string
  depth: number
  flagged: boolean
  mode: string
  trust: number | null
  team_id?: string | null
}

function wireAgent(over: Partial<WireAgent> & Pick<WireAgent, 'id' | 'name'>): WireAgent {
  return { status: 'active', depth: 0, flagged: false, mode: 'enforce', trust: null, ...over }
}

const TEAM_AGENTS: WireAgent[] = [
  wireAgent({ id: 'aa00', name: 'orchestrator', team_id: 'team-alpha' }),
  wireAgent({ id: 'aa01', name: 'worker-1', depth: 1, team_id: 'team-alpha' }),
]

/** A root agent with no team — the only kind the old predicate surfaced. */
const ORPHAN_ROOT = wireAgent({ id: 'bb00', name: 'lonely-scraper', mode: 'off' })

/**
 * The agent this ticket is about: spawned by a parent and claimed by no team.
 * It was in neither the orphan list nor any team, while `total_agent_count`
 * counted it.
 */
const ORPHAN_SPAWNED = wireAgent({
  id: 'bb01',
  name: 'spawned-rogue',
  depth: 2,
  flagged: true,
  mode: 'off',
  team_id: null,
})

const FLEET = [...TEAM_AGENTS, ORPHAN_ROOT, ORPHAN_SPAWNED]

/**
 * The gateway's real overview shape: `standalone_root_agents` carries only the
 * root orphan, because that is what `depth == 0 && team_id.is_none()` selects.
 */
function overview(totalAgentCount: number) {
  return {
    team_count: 1,
    total_agent_count: totalAgentCount,
    root_agent_count: 2,
    standalone_root_agents: [ORPHAN_ROOT],
    teams: [{ team_id: 'team-alpha', agent_count: 2, root_agent_count: 1 }],
  }
}

const COSTS = {
  date: '2026-07-26',
  daily_spend_usd: '42.00',
  daily_limit_usd: '200.00',
  per_team: [
    { team_id: 'team-alpha', date: '2026-07-26', daily_spend_usd: '42.00', monthly_spend_usd: null },
  ],
}

const BUDGET_TREE = {
  root: {
    id: 'org', label: 'acme-corp', kind: 'org', depth: 0,
    own_spend_usd: '0', subtree_spend_usd: '42.00', budget_limit_usd: '200',
    children: [
      {
        id: 'team-alpha', label: 'team-alpha', kind: 'team', depth: 1,
        own_spend_usd: '0', subtree_spend_usd: '42.00', budget_limit_usd: '100', children: [],
      },
    ],
  },
}

type Scenario = 'governed' | 'disagreement' | 'degraded'

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme, scenario: Scenario): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberate 503 below makes the browser log a resource failure; that is
    // the fixture doing its job, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5157')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/costs', (r) => r.fulfill({ json: COSTS }))
  await page.route('**/api/v1/costs/budget-tree', (r) => r.fulfill({ json: BUDGET_TREE }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/topology/team/**', (r) =>
    r.fulfill({ json: { team_id: 'team-alpha', agent_count: 2, members: TEAM_AGENTS } }),
  )
  // The registry tally: 4 real agents, or one more than any grouping can reach.
  await page.route('**/api/v1/topology/overview', (r) =>
    r.fulfill({ json: overview(scenario === 'disagreement' ? FLEET.length + 1 : FLEET.length) }),
  )
  await page.route('**/api/v1/topology', (r) =>
    scenario === 'degraded'
      ? r.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"service_unavailable"}' })
      : r.fulfill({ json: { nodes: FLEET, edges: [] } }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

async function openUnclaimed(page: Page) {
  await page.goto('/teams')
  await expect(page.getByTestId('teams-two-pane')).toBeVisible()
  await page.getByTestId('team-list-orphan-row').click()
  await expect(page.getByTestId('orphan-detail-pane')).toBeVisible()
}

/** Visible text with the screen-reader sentence removed. */
async function visibleText(page: Page, testId: string): Promise<string> {
  return page.getByTestId(testId).evaluate((el) => {
    const clone = el.cloneNode(true) as HTMLElement
    clone.querySelectorAll('.truth-sr-only').forEach((n) => n.remove())
    return clone.textContent?.trim() ?? ''
  })
}

test.describe('AAASM-5157 — no agent is missing from every Teams grouping', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a spawned team-less agent is listed exactly once (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'governed')
      await openUnclaimed(page)

      // The overview the page also fetched contains only the root orphan, so a
      // page still sourcing this list from it would show one row here.
      const rows = page.getByTestId('orphan-agent-row')
      await expect(rows).toHaveCount(2)
      await expect(page.getByRole('link', { name: 'spawned-rogue', exact: true })).toHaveCount(1)
      await expect(rows.nth(1)).toContainText('depth 2')

      // The chip and the list are the same measurement, so they cannot disagree.
      expect(await visibleText(page, 'team-list-orphan-count')).toBe('2')
      expect(await visibleText(page, 'orphan-detail-agent-count')).toBe('2 agents')
      await expect(page.getByTestId('orphan-census-mismatch')).toHaveCount(0)

      // A claimed agent is still governed and must not appear here.
      await expect(page.getByTestId('orphan-detail-pane')).not.toContainText('orchestrator')

      await page.getByTestId('orphan-detail-pane').screenshot({
        path: `${EVIDENCE_DIR}/unclaimed-governed-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/teams-governed-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`a registry tally the groupings cannot cover is stated, not hidden (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'disagreement')
      await openUnclaimed(page)

      const notice = page.getByTestId('orphan-census-mismatch')
      await expect(notice).toBeVisible()
      await expect(notice).toHaveAttribute('data-truth-state', 'unknown')
      await expect(notice).toContainText('1 agent unaccounted for')
      await expect(notice).toContainText('4 grouped here vs 5 reported by the registry')

      // The list itself is still complete and still agrees with its own chip.
      await expect(page.getByTestId('orphan-agent-row')).toHaveCount(2)
      expect(await visibleText(page, 'team-list-orphan-count')).toBe('2')

      await page.getByTestId('orphan-census-mismatch').screenshot({
        path: `${EVIDENCE_DIR}/census-mismatch-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/teams-disagreement-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`a failed fleet request never reads as "everything is governed" (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'degraded')
      await openUnclaimed(page)

      const chip = page.getByTestId('team-list-orphan-count-value')
      await expect(chip).not.toHaveAttribute('data-truth-state', 'known')
      expect(await visibleText(page, 'team-list-orphan-count')).toBe('—')

      // Retries exhaust well inside this budget; the tone escalates to fault.
      await expect(chip).toHaveAttribute('data-truth-state', 'unavailable', { timeout: 20_000 })
      const absent = page.getByTestId('orphan-agents-absent')
      await expect(absent).toHaveAttribute('data-truth-state', 'unavailable')
      await expect(absent).toContainText('the request for this value failed')

      const pane = page.getByTestId('orphan-detail-pane')
      await expect(pane).not.toContainText('No unclaimed agents')
      await expect(pane).not.toContainText('0 agents')
      await expect(page.getByTestId('orphan-agent-row')).toHaveCount(0)
      // A count that could not be taken cannot disagree with anything either.
      await expect(page.getByTestId('orphan-census-mismatch')).toHaveCount(0)

      await page.getByTestId('orphan-detail-pane').screenshot({
        path: `${EVIDENCE_DIR}/unclaimed-unavailable-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/teams-degraded-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
