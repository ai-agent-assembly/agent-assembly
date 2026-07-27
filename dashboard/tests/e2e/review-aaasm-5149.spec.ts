/**
 * Review pass for the app-shell lane (AAASM-5149 / 5134).
 *
 * The regression is driven rather than assumed: the alerts request is failed at
 * the network layer while the rail is asked how many CRITICAL alerts are
 * firing. Before this lane the shell counted `alerts.data ?? []`, so an outage
 * totalled to `0`, the `0` suppressed the badge, and the rail read exactly like
 * a healthy fleet.
 *
 * What each run re-derives:
 *
 *  1. a failed `GET /api/v1/alerts` renders the shared `—` marker in the Alerts
 *     rail slot, tagged `unavailable`, with no digit visible anywhere in the
 *     chip (AAASM-5149);
 *  1b. a *successful* response whose rows are unreadable lands in exactly the
 *     same place — a 200 we cannot parse is not an empty fleet (AAASM-5149);
 *  2. a *loaded* fleet counts only what is still firing — a resolved and a
 *     suppressed CRITICAL do not keep the badge alight (AAASM-5149);
 *  3. a loaded fleet with nothing firing renders no badge and no marker: a
 *     known zero is a real answer and stays silent (AAASM-5149);
 *  4. the rail is the hi-fi near-black with a solid white active pill and no
 *     left-border accent, identically in both themes (AAASM-5134).
 *
 * The alerts hook uses raw `fetch` rather than the generated client, but the
 * interception is `page.route` either way — `openapi-fetch` captures
 * `globalThis.fetch` at module load, so an in-page shim installed after boot
 * would never be consulted by the rest of the dashboard. Auth is seeded with
 * `addInitScript` so the token is in sessionStorage before any module runs.
 *
 * Screenshots land in dashboard/verify/5149/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5149')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query three
 * times with exponential backoff before settling into `isError`. That is real
 * product behaviour — a slow request is not a broken one — so the run waits it
 * out rather than reconfiguring the app to fail faster than it does.
 */
const OUTAGE_SETTLE_MS = 30_000

/** The hi-fi rail ground and active pill (design/v2/hi-fi/styles.css:62-69). */
const RAIL_BG = 'rgb(14, 14, 14)'
const PILL_BG = 'rgb(255, 255, 255)'
const PILL_FG = 'rgb(14, 14, 14)'

const AGENTS = [
  {
    id: 'support-agent',
    name: 'support-agent',
    framework: 'langchain',
    version: '0.1.0',
    status: 'active',
    layer: 'sdk',
    session_count: 1,
    policy_violations_count: 0,
    last_event: '2026-06-01T10:00:00Z',
    tool_names: ['search'],
    recent_events: [],
    metadata: {},
    active_sessions: [],
  },
]

const POLICIES = [
  {
    name: 'default-policy',
    version: '1.0.0',
    rule_count: 5,
    active: true,
    policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
  },
]

/**
 * One alert row exactly as `aa-api` serialises it.
 *
 * Transcribed from `AlertResponse` (aa-api/src/routes/alerts.rs:376-395) and
 * `StoredAlert` (aa-api/src/alerts/mod.rs:29-115): snake_case keys, lower-case
 * `severity` (`info` / `warning` / `critical`), and `status` drawn from
 * `unresolved` / `resolved` / `suppressed`.
 *
 * These fixtures deliberately speak the *backend's* dialect, not the
 * dashboard's. Written the other way round — as they were on the first pass —
 * they cannot detect the defect that mattered most here: the badge predicate
 * compared against a vocabulary the wire never sends, so it counted zero for
 * every live response, and a known zero renders no badge at all. The run is
 * only end-to-end if the payload is the one the server actually returns.
 */
function alert(id: string, severity: string, status: string) {
  return {
    id,
    severity,
    category: 'budget',
    message: 'Budget threshold 90% crossed',
    timestamp: '2026-06-01T10:00:00Z',
    agent_id: 'support-agent',
    team_id: null,
    status,
    updated_at: status === 'resolved' ? '2026-06-01T11:00:00Z' : null,
  }
}

/**
 * One firing CRITICAL beside the two states that must not count.
 *
 * The resolved row is the AAASM-5149 defect proper; the suppressed row is the
 * same claim from the other side — a badge that shouts through a deliberate
 * silence teaches operators to ignore the badge.
 */
const ALERTS_MIXED = {
  items: [
    alert('al-1', 'critical', 'unresolved'),
    alert('al-2', 'critical', 'resolved'),
    alert('al-3', 'critical', 'suppressed'),
    alert('al-4', 'warning', 'unresolved'),
  ],
  total: 4,
  page: 1,
  per_page: 50,
}

/** A fleet that loaded cleanly and genuinely has nothing critical firing. */
const ALERTS_QUIET = {
  items: [alert('al-4', 'warning', 'unresolved')],
  total: 1,
  page: 1,
  per_page: 50,
}

/**
 * A 200 whose rows the client cannot read.
 *
 * Distinct from a 503: the request succeeded, so nothing in the transport layer
 * is wrong — only the payload is unintelligible. That must still land on
 * `unavailable`, never on a confident zero (AAASM-5149).
 */
const ALERTS_UNREADABLE = {
  items: [{ id: 'al-9', severity: 'catastrophic', status: 'acknowledged' }],
}

interface Harness {
  errors: string[]
}

interface Fixture {
  /** Fail `GET /api/v1/alerts` at the network layer. */
  failAlerts?: boolean
  /** Body for a successful alerts list. */
  alerts?: unknown
}

/** Minimal unsigned JWT; the dashboard never verifies it — the gateway does. */
function makeToken(): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5149', scope: ['read', 'write', 'admin'] })}.`
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
    { themeKey: THEME_KEY, theme, token: makeToken() },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (r) => r.fulfill({ json: { items: POLICIES } }))
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) => r.fulfill({ json: { items: AGENTS } }))
  await page.route(/\/api\/v1\/alerts(\?.*)?$/, (r) =>
    fixture.failAlerts
      ? r.fulfill({ status: 503, json: { detail: 'alerts backend unavailable' } })
      : r.fulfill({ json: fixture.alerts ?? ALERTS_MIXED }),
  )

  return harness
}

async function navigate(page: Page, path: string) {
  // Vite `base: './'` workaround — deep-link goto breaks asset resolution, so
  // boot at root and route client-side.
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
  await expect(page.getByTestId('appshell-nav')).toBeVisible()
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

async function railShot(page: Page, name: string) {
  await page.getByTestId('appshell-nav').screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`) })
}

/** The badge chip's text with the screen-reader sentence stripped out. */
function sightedBadgeText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const chip = document.querySelector('[data-testid="nav-badge-alerts"]')
    if (!chip) return '<no badge>'
    const clone = chip.cloneNode(true) as HTMLElement
    clone.querySelectorAll('.truth-sr-only').forEach((el) => el.remove())
    return clone.textContent ?? ''
  })
}

test.describe('AAASM-5149 / 5134 review — the rail claims only what it knows', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a failed alerts request never reads as zero critical — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failAlerts: true })
      await navigate(page, '/agents')

      const marker = page.getByTestId('nav-badge-absent-alerts')
      await expect(marker).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      await expect(marker).toHaveAttribute('title', /Unavailable/)

      // The sighted chip is the shared marker and nothing else — in particular
      // it is not a count, and not the `0` the old `?? []` produced.
      expect(await sightedBadgeText(page)).toBe('—')

      // The absence is audible too: a screen reader must not meet a bare dash.
      await expect(marker).toContainText('the request for this value failed')

      await shot(page, `alerts-outage-${theme}`)
      await railShot(page, `alerts-outage-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a 200 carrying unreadable rows never reads as zero critical — ${theme}`, async ({
      page,
    }) => {
      // The second half of the same defect. A payload in a vocabulary the
      // client cannot parse used to be cast straight to `Alert[]`, match
      // nothing, and total to zero — a successful request quietly asserting a
      // healthy fleet. It must land exactly where a failed request lands.
      const harness = await bootstrap(page, theme, { alerts: ALERTS_UNREADABLE })
      await navigate(page, '/agents')

      const marker = page.getByTestId('nav-badge-absent-alerts')
      await expect(marker).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      expect(await sightedBadgeText(page)).toBe('—')

      await railShot(page, `alerts-unreadable-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`resolved and suppressed CRITICALs drop out of the count — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { alerts: ALERTS_MIXED })
      await navigate(page, '/agents')

      // Three CRITICAL rows, one firing → the badge is 1, not 3.
      await expect(page.getByTestId('nav-badge-alerts')).toHaveText('1')
      await expect(page.getByTestId('nav-badge-absent-alerts')).toHaveCount(0)

      await shot(page, `alerts-firing-only-${theme}`)
      await railShot(page, `alerts-firing-only-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a loaded, quiet fleet renders no badge at all — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { alerts: ALERTS_QUIET })
      await navigate(page, '/agents')

      // A *known* zero is a real answer: it earns silence, not a marker. The
      // Policy badge is present in the same rail, so this is a real wait on a
      // rendered shell rather than an assertion against an unmounted tree.
      await expect(page.getByTestId('nav-link-alerts')).toBeVisible()
      await expect(page.getByTestId('nav-badge-alerts')).toHaveCount(0)

      await railShot(page, `alerts-quiet-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the rail is hi-fi near-black with a white active pill — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { alerts: ALERTS_QUIET })
      await navigate(page, '/agents')

      const rail = page.getByTestId('appshell-nav')
      await expect(rail).toHaveCSS('background-color', RAIL_BG)

      // The rail is deliberately identical in both themes, so this assertion is
      // the same string in the light and dark runs — that is the contract, not
      // a copy-paste.
      const active = page.locator('.appshell__nav-link--active')
      await expect(active).toHaveCount(1)
      await expect(active).toHaveCSS('background-color', PILL_BG)
      await expect(active).toHaveCSS('color', PILL_FG)
      // The 3px blue accent the mock never had.
      await expect(active).toHaveCSS('border-left-width', '0px')

      await railShot(page, `rail-palette-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
