/**
 * Review pass for the Costs truthfulness lane (AAASM-5126 / AAASM-5127).
 *
 * Each regression is driven against the shape `/api/v1/costs` actually
 * produces, rather than against a fixture invented for the test:
 *
 *  1. the page offers no Daily/Monthly period control — the toggle relabelled
 *     the per-team section while `TeamBudgetContent` went on passing the daily
 *     pair, and flipped the Utilisation KPI while Blocked-by-budget beside it
 *     stayed daily. Per-team monthly has no successful path (`TeamCostEntry`
 *     carries spend and no ceiling of any window; a team-tier monthly limit is
 *     sign-off-gated on ADR-0020/AAASM-5087), and the org-monthly figure the
 *     toggle *could* move is already printed on its own permanent card. So the
 *     affordance is gone, not relabelled (AAASM-5126);
 *  2. the per-team section names the window its bars are drawn from, and the
 *     bars carry that window's numbers (AAASM-5126);
 *  3. a wire with no monthly figures at all — the production shape until a
 *     monthly limit is configured, because the gateway only seeds
 *     `monthly_spent_usd` behind a `has_monthly` gate — leaves the Monthly
 *     card's mini bar unmeasured rather than green at 0% (AAASM-5127);
 *  4. a summary with no `daily_limit_usd` leaves every per-team bar
 *     `unconfigured` and unbucketed, never `$0 / $0 · 0%` in green
 *     (AAASM-5127);
 *  5. a failed `/costs` never becomes a measured zero anywhere on the page;
 *  6. a real budget still measures, so the absences above are specific rather
 *     than the page giving up;
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so every fixture
 * is injected with `page.route` and the token is seeded with `addInitScript`
 * before any module runs — a fetch shim installed later would never be seen.
 *
 * Screenshots land in dashboard/verify/5126/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5126')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query
 * three times with exponential backoff before settling into `isError`. That is
 * real product behaviour, so the run waits it out rather than reconfiguring
 * the app to fail faster than it does.
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

/** A fully-configured org: both windows limited, both spends recorded. */
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
 * The production shape with no monthly budget configured.
 *
 * `monthly_spend_usd` is absent everywhere — not zero — because
 * `accumulate_spend` only seeds `monthly_spent_usd` when `has_monthly`
 * (`aa-gateway/src/budget/tracker.rs`), and the API maps `None` straight
 * through. `daily_limit_usd`/`monthly_limit_usd` are `skip_serializing_if
 * = "Option::is_none"`, so an unset limit is an absent key.
 */
const COSTS_NO_MONTHLY = {
  date: '2026-05-13',
  daily_spend_usd: '150.00',
  daily_limit_usd: '200.00',
  per_agent: [{ agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13' }],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '150.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13' },
  ],
}

/** Spend recorded, no ceiling configured in either window. */
const COSTS_NO_LIMITS = {
  date: '2026-05-13',
  daily_spend_usd: '150.00',
  per_agent: [{ agent_id: 'agent-spendy', daily_spend_usd: '150.00', date: '2026-05-13' }],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '130.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', date: '2026-05-13' },
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
 * `parseScopesFromJwt` reads; the signature is irrelevant because the
 * dashboard never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5126', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [] }

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberately-failed fixture is the run's own doing, not the app
    // misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', (e) => harness.errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(['read', 'write', 'admin']) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology**', (r) => r.fulfill({ json: { nodes: [], edges: [] } }))
  await page.route('**/api/v1/topology/overview**', (r) => r.fulfill({ json: OVERVIEW }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/analytics/**', (r) => r.fulfill({ json: { buckets: [] } }))
  await page.route('**/api/v1/costs/history**', (r) => r.fulfill({ json: { points: [] } }))
  await page.route('**/api/v1/costs/budget-tree**', (r) => r.fulfill({ json: { root: null } }))

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
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

/** Open the Per-team tab and return its bars. */
async function openTeamsTab(page: Page) {
  await page.getByTestId('costs-tabs').waitFor()
  await page.getByTestId('costs-tab-teams').click()
}

test.describe('AAASM-5126/5127 review — Costs claims only the window it measured', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`the page offers no period it cannot honour — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/costs')

      await page.getByTestId('costs-kpis').waitFor()

      // ── the affordance that could not change the data is gone ──────────
      await expect(page.getByTestId('costs-period-daily')).toHaveCount(0)
      await expect(page.getByTestId('costs-period-monthly')).toHaveCount(0)

      // ── both windows are on screen at once instead ─────────────────────
      await expect(page.getByTestId('costs-kpi-daily')).toContainText('$210.00')
      await expect(page.getByTestId('costs-kpi-monthly')).toContainText('$3200.00')

      // ── and the two KPIs that share the daily window both say so ───────
      const util = page.getByTestId('costs-kpi-utilisation')
      await expect(util).toContainText('105.0%')
      await expect(util).toContainText('daily · of $200.00 limit')
      await expect(page.getByTestId('costs-kpi-blocked')).toContainText('daily limit')

      await shot(page, `no-period-toggle-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the per-team section names the window its bars carry — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/costs')
      await openTeamsTab(page)

      const hint = page.getByTestId('costs-team-hint')
      await expect(hint).toContainText('daily spend vs org daily limit')
      // The regression: this read "monthly spend vs org limit" over daily bars.
      await expect(hint).not.toContainText(/monthly/i)

      const bars = page.getByTestId('team-budget-bar')
      await expect(bars).toHaveCount(2)
      // 190/200 — the daily pair the hint claims, not 2900 against anything.
      await expect(
        page.locator('[data-testid="team-budget-bar"][data-team="team-hot"]'),
      ).toContainText('$190 / $200 · 95%')

      await shot(page, `per-team-daily-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an unconfigured monthly budget is not drawn as headroom — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_NO_MONTHLY })
      await navigate(page, '/costs')

      const monthly = page.getByTestId('costs-kpi-monthly')
      await expect(monthly).toContainText('—')
      await expect(monthly).toContainText('no monthly limit set')

      const monthlyBar = monthly.getByTestId('costs-budget-bar')
      await expect(monthlyBar).toHaveAttribute('data-truth-state', 'unknown')
      // The regression: `used={spend ?? 0}` + `bucket = … : 'ok'` drew a green
      // 0%-burnt track for a month nobody ever measured.
      await expect(monthlyBar).not.toHaveAttribute('data-threshold-bucket', /.*/)
      await expect(monthlyBar).toHaveAttribute('aria-label', /unknown/)
      await expect(monthly.getByText(/% used/)).toHaveCount(0)

      // …while the daily bar beside it still measures, so the absence is
      // specific rather than the page giving up.
      const dailyBar = page.getByTestId('costs-kpi-daily').getByTestId('costs-budget-bar')
      await expect(dailyBar).toHaveAttribute('data-threshold-bucket', 'ok')
      await expect(page.getByTestId('costs-kpi-daily')).toContainText('75.0% used')

      await shot(page, `monthly-unconfigured-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an unknown per-team ceiling is never green at $0 / $0 — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_NO_LIMITS })
      await navigate(page, '/costs')

      // Utilisation has no denominator and says so, rather than reading 0%.
      // The marker replaced a locally-invented `N/A` in AAASM-5185; the
      // guarantee is unchanged, only its vocabulary.
      const util = page.getByTestId('costs-kpi-utilisation')
      await expect(util.getByTestId('costs-kpi-utilisation-value')).toHaveAttribute(
        'data-truth-state',
        'unconfigured',
      )
      await expect(util).toContainText('no daily budget limit set')

      await openTeamsTab(page)
      const bars = page.getByTestId('team-budget-bar')
      await expect(bars).toHaveCount(2)
      for (const bar of await bars.all()) {
        // The regression: `?? 0` on both sides printed "$0 / $0 · 0%" and
        // `bucketForBudget(0, 0)` bucketed it `ok` — green.
        await expect(bar).toHaveAttribute('data-truth-state', 'unconfigured')
        await expect(bar).not.toHaveAttribute('data-threshold-bucket', /.*/)
        await expect(bar).not.toHaveAttribute('aria-valuenow', /.*/)
        await expect(bar).not.toContainText('$0 / $0')
      }
      // The spend half is real and is still shown against the absent ceiling.
      await expect(
        page.locator('[data-testid="team-budget-bar"][data-team="team-hot"]'),
      ).toContainText('$130')

      await shot(page, `team-ceiling-unconfigured-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a failed /costs never becomes a measured zero — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failCosts: true })
      await navigate(page, '/costs')

      // The per-team section reports the outage rather than an empty roster.
      // Waiting on this first is what settles the retry: the KPI dashes below
      // are already correct while the request is in flight, so asserting them
      // first would pass before the failure had actually landed.
      await openTeamsTab(page)
      await expect(page.getByTestId('costs-error')).toBeVisible({ timeout: OUTAGE_SETTLE_MS })
      await expect(page.getByTestId('team-budget-bar')).toHaveCount(0)

      const daily = page.getByTestId('costs-kpi-daily')
      await expect(daily).toContainText('—')
      await expect(daily).not.toContainText('$0.00')
      await expect(
        page.getByTestId('costs-kpi-utilisation').getByTestId('costs-kpi-utilisation-value'),
      ).toHaveAttribute('data-truth-state', 'unavailable')

      // Neither mini bar may claim a burn it never measured.
      for (const id of ['costs-kpi-daily', 'costs-kpi-monthly']) {
        const bar = page.getByTestId(id).getByTestId('costs-budget-bar')
        await expect(bar).toHaveAttribute('data-truth-state', 'unknown')
        await expect(bar).not.toHaveAttribute('data-threshold-bucket', /.*/)
      }

      await shot(page, `costs-outage-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
