/**
 * Review pass for the Alerts truthfulness lane (AAASM-5150 / 5123 / 5122 /
 * 5121 / 5147).
 *
 * The headline regression is driven explicitly rather than assumed: the
 * alert-rules query is failed at the network layer while alerts ARE firing, and
 * the page is required not to narrate that as "No alerts in this window".
 *
 * What each run re-derives:
 *
 *  1. a failed rules query renders as `unavailable` — a named banner with a
 *     retry, category counts folded to `—`, category selection disabled, and
 *     the alert rows still on screen (AAASM-5150);
 *  2. a failed alerts query renders an `unavailable` state, never an empty
 *     state, and no stat tile reads `0` (AAASM-5150);
 *  3. a page short of the envelope's `total` says so, and the stat tiles say
 *     they cover this page only (AAASM-5123);
 *  4. `GET /api/v1/alerts` is requested with no filter query string, and the
 *     severity chip still narrows the rendered feed (AAASM-5122);
 *  5. the resolve affordance POSTs to the shipped
 *     `/api/v1/alerts/{id}/resolve` endpoint (AAASM-5121);
 *  6. a read-scope caller gets every write affordance disabled — including the
 *     zero-rule empty-state CTA, which opens the same form as the gated header
 *     button (AAASM-5147);
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so failures are
 * injected with `page.route` and the token is seeded with `addInitScript`
 * before any module runs — a fetch shim installed later would never be seen.
 *
 * Screenshots land in dashboard/verify/5150/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5150')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * The app mounts a default `QueryClient`, which retries a failed query three
 * times with exponential backoff before settling into `isError`. That is real
 * product behaviour — a slow request is not a broken one — so the run waits it
 * out rather than reconfiguring the app to fail faster than it really does.
 */
const OUTAGE_SETTLE_MS = 30_000

/**
 * Fixture alerts are stamped relative to the run, because the filter bar's 24h
 * default is now applied client-side (AAASM-5122) — absolute timestamps would
 * make the fixture fall out of the window and the run would pass for the wrong
 * reason.
 */
const NOW = Date.now()
const minutesAgo = (m: number) => new Date(NOW - m * 60_000).toISOString()

const RULES = [
  {
    id: 'r-budget',
    name: 'Budget guardrail',
    description: '',
    metric: 'budget_spent_pct',
    operator: '>',
    threshold: 90,
    evaluationWindowSeconds: 300,
    severity: 'CRITICAL',
    destinationIds: ['dst-slack'],
    dedupWindowSeconds: 600,
    suppressionLabels: {},
    enabled: true,
    createdAt: minutesAgo(6000),
    updatedAt: minutesAgo(6000),
  },
]

function alert(id: string, severity: string, status: string, ageMinutes: number) {
  return {
    id,
    ruleId: 'r-budget',
    ruleName: 'Budget guardrail',
    severity,
    status,
    agentId: `agent-${id}`,
    firstFiredAt: minutesAgo(ageMinutes),
    resolvedAt: null,
    destinationIds: ['dst-slack'],
  }
}

const ALERTS = [
  alert('al-1', 'CRITICAL', 'FIRING', 5),
  alert('al-2', 'CRITICAL', 'FIRING', 20),
  alert('al-3', 'WARNING', 'FIRING', 45),
]

/** A page of 3 rows out of a fleet of 214 — the truncation the mock never had. */
const TRUNCATED_PAGE = { items: ALERTS, page: 1, per_page: 50, total: 214 }
/** The same rows, honestly complete. */
const COMPLETE_PAGE = { items: ALERTS, page: 1, per_page: 50, total: ALERTS.length }

const ALERT_DETAIL = {
  ...ALERTS[0],
  ruleSnapshot: RULES[0],
  eventPayload: { spent_pct: 96.1 },
  routingLog: [],
  silence: null,
  dedupOccurrenceCount: 1,
  dedupWindowExpiresAt: null,
}

interface Harness {
  errors: string[]
  /** Every `GET /api/v1/alerts` URL the app asked for, in order. */
  listRequests: string[]
  /** Every non-GET request, so a write can be proven to have gone out. */
  writes: { url: string; method: string; body: string | null }[]
}

interface Fixture {
  /** Fail the alert-rules query instead of serving it. */
  failRules?: boolean
  /** Fail the alerts list query instead of serving it. */
  failAlerts?: boolean
  /** Serve a page that falls short of the reported total. */
  truncated?: boolean
  /** Serve an empty rules list — the zero-rule install state. */
  noRules?: boolean
  /** Scopes the seeded session token carries. */
  scopes?: string[]
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [], listRequests: [], writes: [] }
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades and the deliberately-failed fixtures are the run's
    // own doing, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', (e) => harness.errors.push(`pageerror: ${e.message}`))

  const scopes = fixture.scopes ?? ['read', 'write', 'admin']
  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(scopes) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/policies**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/alerts/destinations**', (r) => r.fulfill({ json: [] }))

  await page.route('**/api/v1/alerts/rules**', (r: Route) =>
    fixture.failRules
      ? r.fulfill({ status: 503, json: { detail: 'rules backend unavailable' } })
      : r.fulfill({ json: fixture.noRules ? [] : RULES }),
  )

  await page.route('**/api/v1/alerts/*/resolve', (r: Route) => {
    const req = r.request()
    harness.writes.push({ url: req.url(), method: req.method(), body: req.postData() })
    return r.fulfill({ json: { ...ALERTS[0], status: 'RESOLVED' } })
  })

  await page.route('**/api/v1/alerts/al-1', (r) => r.fulfill({ json: ALERT_DETAIL }))

  await page.route('**/api/v1/alerts*', (r: Route) => {
    harness.listRequests.push(r.request().url())
    if (fixture.failAlerts) {
      return r.fulfill({ status: 503, json: { detail: 'alerts backend unavailable' } })
    }
    return r.fulfill({ json: fixture.truncated ? TRUNCATED_PAGE : COMPLETE_PAGE })
  })

  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return harness
}

/**
 * Minimal unsigned JWT.
 *
 * The claim is `scope` (an array), which is what `parseScopesFromJwt` reads;
 * the signature is irrelevant here because the dashboard never verifies it —
 * the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5150', scope: scopes })}.`
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

test.describe('AAASM-5150 review — the Alerts surface tells the truth', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a rules outage never reads as "no alerts" — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failRules: true })
      await navigate(page, '/alerts')
      await expect(page.getByTestId('alerts-stats-strip')).toBeVisible()
      // Wait for the rules query to exhaust its retries and settle into error.
      await expect(page.getByTestId('alerts-rules-error')).toBeVisible({
        timeout: OUTAGE_SETTLE_MS,
      })

      // ── 1. the empty state is never reached while alerts are firing ──────
      await expect(page.getByTestId('alerts-empty-no-alerts')).toHaveCount(0)
      await expect(page.getByTestId('alerts-empty-no-rules')).toHaveCount(0)
      await expect(page.getByTestId('alert-row')).toHaveCount(3)
      await expect(page.getByTestId('alerts-count')).toContainText('3 alerts')

      // ── 2. the rules failure is named, with its own retry ────────────────
      const banner = page.getByTestId('alerts-rules-error')
      await expect(banner).toBeVisible({ timeout: OUTAGE_SETTLE_MS })
      await expect(banner).toContainText('Failed to load alert rules')
      await expect(page.getByTestId('alerts-rules-error-retry')).toBeVisible()

      // ── 3. category counts fold to the shared absence, not to 0 ──────────
      const budgetChip = page.getByTestId('alerts-category-budget')
      await expect(budgetChip).toContainText('—')
      // The chip must carry no count at all. Asserted as "no digit follows the
      // label" rather than "contains no 0", because the absence detail quotes
      // the HTTP status and 503 has a zero in it.
      await expect(budgetChip).not.toHaveText(/budget\s*\d/)
      await expect(
        budgetChip.locator('[data-truth-state="unavailable"]'),
      ).toHaveCount(1)
      await expect(budgetChip).toBeDisabled()
      await expect(page.getByTestId('alerts-category-all')).toBeEnabled()

      await shot(page, `rules-outage-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an alerts outage renders unavailable, never zero — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failAlerts: true })
      await navigate(page, '/alerts')

      const state = page.getByTestId('alerts-unavailable')
      await expect(state).toBeVisible({ timeout: OUTAGE_SETTLE_MS })
      await expect(state).toHaveAttribute('data-truth-state', 'unavailable')
      await expect(page.getByTestId('alerts-empty-no-alerts')).toHaveCount(0)

      // No tile may report a business value it does not have.
      for (const key of ['CRITICAL', 'WARNING', 'INFO', 'FIRING']) {
        await expect(page.getByTestId(`alerts-stat-count-${key}`)).toContainText('—')
        await expect(page.getByTestId(`alerts-stat-tile-${key}`)).toBeDisabled()
      }
      await expect(page.getByTestId('alerts-count')).toContainText('—')

      await shot(page, `alerts-outage-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a truncated page is never presented as the whole fleet — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { truncated: true })
      await navigate(page, '/alerts')

      await expect(page.getByTestId('alerts-truncation-notice')).toContainText(
        'Showing the first 3 of 214 alerts',
      )
      await expect(page.getByTestId('alerts-stats-scope')).toContainText(
        'Counts cover the 3 alerts on this page, not all 214.',
      )
      // The count describes the page; only the truncation notice names the
      // fleet total, so the two numbers can never be read as one ratio.
      await expect(page.getByTestId('alerts-count')).toContainText('3 alerts on this page')
      await expect(page.getByTestId('alerts-count')).not.toContainText('214')

      await shot(page, `truncation-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the filter controls narrow a real feed and send no dropped parameters — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/alerts')
      await expect(page.getByTestId('alert-row')).toHaveCount(3)

      // AAASM-5122: the API declares only page/per_page — nothing else is sent.
      expect(harness.listRequests.length).toBeGreaterThan(0)
      for (const url of harness.listRequests) {
        expect(new URL(url).search).toBe('')
      }

      // The chip that used to return an identical list now narrows the feed.
      await page.getByTestId('alerts-filter-severity-WARNING').click()
      await expect(page.getByTestId('alert-row')).toHaveCount(1)
      // Narrowed: shown and loaded are both page figures, named together.
      await expect(page.getByTestId('alerts-count')).toContainText('1 of 3 alerts')

      await shot(page, `filters-applied-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the resolve affordance posts to the shipped endpoint — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/alerts')
      await page.getByTestId('alert-row').first().click()

      const submit = page.getByTestId('resolve-action-submit')
      await expect(submit).toBeEnabled()
      await submit.click()

      await expect(async () => {
        expect(harness.writes).toHaveLength(1)
      }).toPass()
      expect(harness.writes[0].method).toBe('POST')
      expect(new URL(harness.writes[0].url).pathname).toBe('/api/v1/alerts/al-1/resolve')

      await shot(page, `resolve-action-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a read-scope caller sees every write affordance disabled — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { scopes: ['read'] })
      await navigate(page, '/alerts')

      await expect(page.getByTestId('alerts-open-rule-form')).toBeDisabled()

      await page.getByTestId('alert-row').first().click()
      await expect(page.getByTestId('resolve-action-submit')).toBeDisabled()
      await expect(page.getByTestId('silence-action-submit')).toBeDisabled()
      await shot(page, `rbac-read-only-detail-${theme}`)
      await page.getByTestId('alert-detail-drawer-close').click()

      await page.getByTestId('alerts-open-destinations').click()
      await expect(page.getByTestId('destination-form-submit')).toBeDisabled()
      await shot(page, `rbac-read-only-destinations-${theme}`)

      expect(harness.errors).toEqual([])
    })

    // The zero-rule install is the only state that renders the empty-state CTA,
    // and that CTA opens the same rule form as the gated header button. Every
    // other RBAC case here seeds a rule, so without this the bypass is
    // unreachable end-to-end as well as in unit tests.
    test(`a read-scope caller cannot reach the rule form from a zero-rule install — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { scopes: ['read'], noRules: true })
      await navigate(page, '/alerts')

      await expect(page.getByTestId('alerts-empty-no-rules')).toBeVisible()
      await expect(page.getByTestId('alerts-empty-create-cta')).toBeDisabled()
      await expect(page.getByTestId('alerts-open-rule-form')).toBeDisabled()

      await shot(page, `rbac-zero-rules-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
