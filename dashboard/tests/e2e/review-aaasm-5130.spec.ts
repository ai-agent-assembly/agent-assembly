/**
 * Review pass for the Fleet empty-state lane (AAASM-5130).
 *
 * A headers-only table does not say *why* it has no rows, and the four reasons
 * are different facts with different remedies. Each is driven explicitly here
 * rather than assumed, and each is required to be distinguishable from the
 * other three on screen:
 *
 *  1. **filter-empty** — a real, successful result. Says the filter matched
 *     nothing and offers to clear it; must not borrow the onboarding copy or
 *     the failure banner, and the clear affordance must actually restore the
 *     rows and the URL.
 *  2. **fleet-empty** — also real, but a different message and a different
 *     remedy (onboarding). The table is suppressed: an empty grid beneath the
 *     callout is the ambiguity the callout exists to remove.
 *  3. **unavailable** — the request failed. Never renders as "no agents", and
 *     the counters fold to `—`: "0 of 0 agents" is a business claim the failed
 *     request never established.
 *  4. **loading** — in flight. Skeleton rows, and again no counter asserting a
 *     fleet size that is not yet known.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the failure is
 * injected with `page.route` and the token is seeded with `addInitScript`
 * before any module runs — a fetch shim installed later would never be seen.
 * `tokenStorage.ts` reads sessionStorage only, so that is where it goes.
 *
 * Screenshots land in dashboard/verify/5130/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5130')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query three
 * times with exponential backoff before settling into `isError`. That is real
 * product behaviour — a slow request is not a broken one — so the run waits it
 * out rather than reconfiguring the app to fail faster than it really does.
 */
const OUTAGE_SETTLE_MS = 30_000

const NOW = Date.now()
const minutesAgo = (m: number) => new Date(NOW - m * 60_000).toISOString()

function agent(id: string, name: string, framework: string) {
  return {
    id,
    name,
    framework,
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: minutesAgo(3),
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: { owner: 'ops' },
    pid: null,
  }
}

const AGENTS = [
  agent('a-1', 'billing-copilot', 'langgraph'),
  agent('a-2', 'support-triage', 'crewai'),
  agent('a-3', 'infra-watchdog', 'autogen'),
]

interface Harness {
  errors: string[]
}

interface Fixture {
  /** Fail the agents query instead of serving it. */
  fail?: boolean
  /** Serve an empty — but successful — agent list. */
  empty?: boolean
  /** Hold the agents response open so the in-flight state can be observed. */
  hang?: boolean
}

/**
 * Minimal unsigned JWT.
 *
 * The claim is `scope` (an array), which is what `parseScopesFromJwt` reads;
 * the signature is irrelevant because the dashboard never verifies it — the
 * gateway is the authority. `main` fails closed without a token, so a Fleet
 * run that skipped this would be reviewing the login screen.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5130', scope: scopes })}.`
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
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/policies**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/alerts**', (r) => r.fulfill({ json: { items: [], page: 1, per_page: 50, total: 0 } }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => r.fulfill({ json: [] }))

  await page.route('**/api/v1/agents**', async (r: Route) => {
    if (fixture.fail) {
      return r.fulfill({ status: 503, json: { detail: 'agent registry unavailable' } })
    }
    if (fixture.hang) {
      // Never fulfilled: the assertions run against the genuinely in-flight
      // render, not a fast-forwarded approximation of it.
      return
    }
    // `/api/v1/agents` answers with a paginated envelope (AAASM-4892), which
    // `useAgentsQuery` unwraps — a bare array here would read as zero agents
    // and the run would pass for the wrong reason.
    const items = fixture.empty ? [] : AGENTS
    return r.fulfill({ json: { items, total: items.length, page: 1, per_page: 100 } })
  })

  await page.route('**/api/v1/ws/events**', (r) => r.abort())

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

test.describe('AAASM-5130 review — the Fleet table says why it is empty', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a filter that matched nothing explains itself and can be cleared — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/agents?q=no-such-agent')

      const callout = page.getByTestId('fleet-filter-empty')
      await expect(callout).toBeVisible()
      await expect(callout).toContainText('no agents match these filters')

      // ── 1. it is not dressed up as an absence or as the empty fleet ──────
      await expect(page.getByTestId('agents-empty')).toHaveCount(0)
      await expect(page.getByTestId('agents-error')).toHaveCount(0)
      await expect(page.getByTestId('agent-row')).toHaveCount(0)
      // The filter excluded everything, but the fleet size is still known.
      await expect(page.getByTestId('fleet-page-count')).toContainText('· 0 of 3 agents')

      // ── 2. the column headers survive — the columns still mean something ─
      await expect(page.getByTestId('agents-table')).toBeVisible()

      await shot(page, `filter-empty-${theme}`)

      // ── 3. the remedy works: rows come back and the URL is cleaned ───────
      await page.getByTestId('fleet-filter-empty-clear').click()
      await expect(page.getByTestId('agent-row')).toHaveCount(3)
      await expect(page.getByTestId('fleet-filter-empty')).toHaveCount(0)
      expect(new URL(page.url()).searchParams.get('q')).toBeNull()

      await shot(page, `filter-cleared-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an empty fleet gets onboarding copy and no ghost table — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { empty: true })
      await navigate(page, '/agents')

      await expect(page.getByTestId('agents-empty')).toBeVisible()
      await expect(page.getByTestId('agents-empty')).toContainText('No agents registered yet')
      // A different result from filter-empty, so a different message and no
      // clear-filters affordance.
      await expect(page.getByTestId('fleet-filter-empty')).toHaveCount(0)
      await expect(page.getByTestId('agents-error')).toHaveCount(0)
      // Headers over blank space beneath the callout is the ambiguity the
      // callout exists to remove.
      await expect(page.getByTestId('agents-table')).toHaveCount(0)
      // Zero here is a fact the successful request did establish.
      await expect(page.getByTestId('fleet-page-count')).toContainText('· 0 of 0 agents')

      await shot(page, `fleet-empty-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a failed request never reads as "no agents" — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { fail: true })
      await navigate(page, '/agents')

      await expect(page.getByTestId('agents-error')).toBeVisible({ timeout: OUTAGE_SETTLE_MS })
      await expect(page.getByTestId('agents-error')).toContainText('Failed to load agents')

      // ── neither empty state may be borrowed by a failure ────────────────
      await expect(page.getByTestId('agents-empty')).toHaveCount(0)
      await expect(page.getByTestId('fleet-filter-empty')).toHaveCount(0)
      await expect(page.getByTestId('agents-table')).toHaveCount(0)

      // ── the counters state nothing, rather than stating zero ────────────
      await expect(page.getByTestId('fleet-page-count')).toContainText('· — of — agents')
      await expect(page.getByTestId('fleet-page-count')).not.toContainText('0')
      await expect(page.getByTestId('fleet-tab-agents-count')).toHaveText('—')

      await shot(page, `unavailable-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an in-flight request claims no fleet size — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { hang: true })
      await navigate(page, '/agents')

      await expect(page.getByTestId('agent-row-skeleton').first()).toBeVisible()
      await expect(page.getByTestId('agent-row-skeleton')).toHaveCount(5)
      // "Asked and do not yet know" is not "no agents" and not a failure.
      await expect(page.getByTestId('agents-empty')).toHaveCount(0)
      await expect(page.getByTestId('fleet-filter-empty')).toHaveCount(0)
      await expect(page.getByTestId('agents-error')).toHaveCount(0)
      await expect(page.getByTestId('fleet-page-count')).toContainText('· — of — agents')

      await shot(page, `loading-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
