/**
 * Review pass for the Costs KPI-strip truthfulness lane (AAASM-5185) and the
 * restored per-team columns (AAASM-5160).
 *
 * Each case is driven against a shape `/api/v1/costs` actually produces:
 *
 *  1. a *successful* summary carrying spend and no `daily_limit_usd` — the OSS
 *     shape until a budget is configured — leaves Blocked-by-budget absent
 *     rather than `0 · no teams over the daily limit`, and stops contradicting
 *     the Utilisation card beside it (AAASM-5185);
 *  2. a summary covering only some of the roster states its coverage instead of
 *     presenting the unmeasured remainder as compliant;
 *  3. a failed `/costs` surfaces as `unavailable` across the strip, never as a
 *     measured zero anywhere;
 *  4. a fully-measured, fully-compliant roster still reads `0`, so the absences
 *     above are specific rather than the page giving up;
 *  5. the Per-team tab is a table carrying agent count and month-to-date spend,
 *     with an absent monthly figure rendered as a stated absence, not `$0`
 *     (AAASM-5160);
 *  6. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so every fixture
 * is injected with `page.route` and the token is seeded into **sessionStorage**
 * (which is all `auth/tokenStorage.ts` reads) with `addInitScript`, before any
 * module runs — a fetch shim installed later would never be seen.
 *
 * Screenshots land in dashboard/verify/5185/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5185')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query three
 * times with exponential backoff before settling into `isError`. That is real
 * product behaviour, so the run waits it out rather than reconfiguring the app
 * to fail faster than it does.
 */
const OUTAGE_SETTLE_MS = 30_000

const OVERVIEW = {
  root_agent_count: 2,
  standalone_root_agents: [],
  team_count: 2,
  total_agent_count: 5,
  teams: [
    { team_id: 'team-hot', agent_count: 3, root_agent_count: 1 },
    { team_id: 'team-cool', agent_count: 2, root_agent_count: 1 },
  ],
}

/** A fully-configured org, one team in the danger band (190/200 = 95%). */
const COSTS_FULL = {
  date: '2026-05-13',
  daily_spend_usd: '210.00',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3200.00',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'agent-spendy', daily_spend_usd: '150.00', monthly_spend_usd: '2200.00', date: '2026-05-13' },
    { agent_id: 'agent-thrifty', daily_spend_usd: '40.00', monthly_spend_usd: '600.00', date: '2026-05-13' },
  ],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '190.00', monthly_spend_usd: '2900.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', monthly_spend_usd: '300.00', date: '2026-05-13' },
  ],
}

/**
 * Spend recorded, no ceiling configured in either window — the exact
 * successful-but-unmeasurable case AAASM-5185 was opened for, and the same
 * fixture shape as `COSTS_NO_LIMITS` in the AAASM-5126 review spec.
 *
 * `daily_limit_usd` / `monthly_limit_usd` are `skip_serializing_if =
 * "Option::is_none"`, so an unset limit is an absent key rather than a null.
 */
const COSTS_NO_LIMITS = {
  date: '2026-05-13',
  daily_spend_usd: '150.00',
  per_agent: [{ agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13' }],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '130.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13' },
  ],
}

/** Only one of the two teams appears in the breakdown — partial coverage. */
const COSTS_PARTIAL = {
  ...COSTS_FULL,
  per_team: [{ team_id: 'team-hot', daily_spend_usd: '190.00', date: '2026-05-13' }],
}

/** Every team measured and comfortably under its ceiling — a genuine zero. */
const COSTS_COMPLIANT = {
  ...COSTS_FULL,
  daily_spend_usd: '40.00',
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '20.00', monthly_spend_usd: '300.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', monthly_spend_usd: '300.00', date: '2026-05-13' },
  ],
}

interface Harness {
  errors: string[]
}

interface Fixture {
  /** Body for `GET /api/v1/costs`. Defaults to the fully-configured org. */
  costs?: unknown
  /** Fail `GET /api/v1/costs` at the network layer instead. */
  failCosts?: boolean
}

/**
 * Minimal unsigned JWT. The claim is `scope` (an array), which is what
 * `parseScopesFromJwt` reads; the signature is irrelevant because the dashboard
 * never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5185', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [] }

  page.on('console', m => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberately-failed fixture is the run's own doing, not the app
    // misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', e => harness.errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(['read', 'write', 'admin']) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', r => r.fulfill({ json: {} }))
  await page.route('**/api/v1/agents**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology**', r => r.fulfill({ json: { nodes: [], edges: [] } }))
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: OVERVIEW }))
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/analytics/**', r => r.fulfill({ json: { buckets: [] } }))
  await page.route('**/api/v1/costs/history**', r => r.fulfill({ json: { points: [] } }))
  await page.route('**/api/v1/costs/budget-tree**', r => r.fulfill({ json: { root: null } }))

  // The pattern has no trailing wildcard, so it matches the summary endpoint
  // exactly and never the `/costs/history` or `/costs/budget-tree`
  // sub-resources routed above.
  await page.route('**/api/v1/costs', (r: Route) =>
    fixture.failCosts
      ? r.fulfill({ status: 503, json: { detail: 'budget tracker unavailable' } })
      : r.fulfill({ json: fixture.costs ?? COSTS_FULL }),
  )

  return harness
}

async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(target => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

async function openTeamsTab(page: Page) {
  await page.getByTestId('costs-tabs').waitFor()
  await page.getByTestId('costs-tab-teams').click()
}

test.describe('AAASM-5185/5160 review — Costs counts only what it measured', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a successful response with no ceiling leaves Blocked-by-budget absent — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_NO_LIMITS })
      await navigate(page, '/costs')

      const blocked = page.getByTestId('costs-kpi-blocked')
      const blockedValue = blocked.getByTestId('costs-kpi-blocked-value')
      await expect(blockedValue).toHaveAttribute('data-truth-state', 'unconfigured')
      // The regression: `0 · no teams over the daily limit`, asserted for teams
      // the page never measured, on a request that succeeded.
      await expect(blocked).not.toContainText('no teams over the daily limit')
      await expect(blocked).toContainText('no team has a daily ceiling configured')

      // …and the neighbour it used to contradict now agrees there is no limit.
      const util = page.getByTestId('costs-kpi-utilisation')
      await expect(util.getByTestId('costs-kpi-utilisation-value')).toHaveAttribute(
        'data-truth-state',
        'unconfigured',
      )
      await expect(util).toContainText('no daily budget limit set')

      // The spend half is real and is still asserted — the absence is specific.
      await expect(page.getByTestId('costs-kpi-daily')).toContainText('$150.00')

      await shot(page, `blocked-unconfigured-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a partly-measurable roster states its coverage — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_PARTIAL })
      await navigate(page, '/costs')

      const blocked = page.getByTestId('costs-kpi-blocked')
      await expect(blocked.getByTestId('costs-kpi-blocked-value')).toContainText('1')
      // The unmeasured team is named as unmeasured, not absorbed as compliant.
      await expect(blocked).toContainText('1 of 2 teams measured · 1 unmeasured')

      await shot(page, `blocked-partial-coverage-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a failed /costs never becomes a measured zero on the strip — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { failCosts: true })
      await navigate(page, '/costs')

      // Waiting on the per-team error first is what settles the retry: the KPI
      // absences below are already correct while the request is in flight, so
      // asserting them first would pass before the failure had landed.
      await openTeamsTab(page)
      await expect(page.getByTestId('costs-error')).toBeVisible({ timeout: OUTAGE_SETTLE_MS })

      for (const id of ['costs-kpi-blocked', 'costs-kpi-agents', 'costs-kpi-daily']) {
        const card = page.getByTestId(id)
        await expect(card.getByTestId(`${id}-value`)).toHaveAttribute(
          'data-truth-state',
          'unavailable',
        )
        await expect(card).not.toContainText('$0.00')
      }
      await expect(page.getByTestId('costs-kpi-blocked')).toContainText(
        'daily burn could not be loaded',
      )
      await expect(page.getByTestId('costs-kpi-agents')).not.toContainText('across 0 teams')

      await shot(page, `strip-outage-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a measured, fully-compliant roster still reads 0 — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_COMPLIANT })
      await navigate(page, '/costs')

      const blocked = page.getByTestId('costs-kpi-blocked')
      // The point of the absence: a real zero must survive it intact.
      await expect(blocked.getByTestId('costs-kpi-blocked-value')).toHaveAttribute(
        'data-truth-state',
        'known',
      )
      await expect(blocked).toContainText('0')
      await expect(blocked).toContainText('no teams over the daily limit')

      await shot(page, `blocked-measured-zero-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the per-team tab carries agent count and monthly spend — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/costs')
      await openTeamsTab(page)

      const table = page.getByTestId('costs-team-table')
      await expect(table).toBeVisible()
      await expect(table.getByRole('columnheader')).toHaveText([
        'Team',
        'Agents',
        'Daily spend',
        'vs daily limit',
        'Monthly spend',
      ])
      // `TeamCostEntry` carries no ceiling of any window; the mock's Monthly
      // limit reads a fixture, and a fabricated one is worse than a gap.
      await expect(table).not.toContainText('Monthly limit')

      // Scoped to the row, not `[data-team]` — `TeamBudgetBar` carries the same
      // attribute inside the "vs daily limit" cell.
      const hot = table.locator('tr[data-testid="costs-team-row"][data-team="team-hot"]')
      await expect(hot.getByTestId('costs-team-agents')).toHaveText('3')
      await expect(hot).toContainText('$190.00')
      await expect(hot).toContainText('$2900.00')
      // The bar is kept verbatim as the "vs daily limit" cell, so AAASM-5135's
      // absence handling continues to hold.
      await expect(hot.getByTestId('team-budget-bar')).toHaveAttribute(
        'data-threshold-bucket',
        'danger',
      )

      await shot(page, `per-team-table-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an absent per-team monthly figure is never drawn as $0 — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_NO_LIMITS })
      await navigate(page, '/costs')
      await openTeamsTab(page)

      const table = page.getByTestId('costs-team-table')
      await expect(table).toBeVisible()
      // Both teams are in the breakdown with a daily figure and no monthly one:
      // monthly tracking is off, which is not a month of zero spend.
      const markers = table.getByTestId('costs-team-no-monthly')
      await expect(markers).toHaveCount(2)
      for (const marker of await markers.all()) {
        await expect(marker).toHaveAttribute('data-truth-state', 'unconfigured')
      }
      await expect(table).not.toContainText('$0.00')

      await shot(page, `per-team-monthly-unconfigured-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
