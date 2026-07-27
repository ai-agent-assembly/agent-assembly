/**
 * Verification pass for the shell's Policy badge (AAASM-5186).
 *
 * The regression is driven, not assumed: `GET /api/v1/policies` is failed at
 * the network layer while the rail is asked how many policy versions are
 * inactive. Before this fix the shell counted `policies.data ?? []`, so an
 * outage totalled to `0`, the `0` suppressed the badge, and the Policy rail
 * item read exactly like a healthy one.
 *
 * What each run re-derives:
 *
 *  1. a failed `GET /api/v1/policies` renders the shared `—` marker in the
 *     Policy rail slot, tagged `unavailable`, with no digit anywhere in the
 *     chip — and carries its reason into the nav link's accessible name
 *     without a `role="alert"` (the rail is persistent chrome and would
 *     announce on every cold boot);
 *  2. a *loaded* list still counts: inactive versions produce a real number;
 *  3. a loaded list with nothing inactive renders no badge and no marker — a
 *     known zero is a real answer and stays silent;
 *  4. the response `aa-api` actually returns for the request the shell makes
 *     (one row, `active: true`) produces no badge — see the note below.
 *
 * Wire dialect: unlike the alerts badge, there is no vocabulary gap to bridge
 * here. `PolicyResponse.active` (aa-api/src/routes/policies.rs) is a plain
 * required JSON boolean spelled `active` on both sides, so the predicate reads
 * exactly what the server sends. The fixtures below are transcribed from that
 * struct — snake_case `rule_count` / `policy_yaml`, wrapped in the
 * `{ items, page, per_page, total }` `PaginatedPolicyResponse` (AAASM-4892).
 *
 * There *is* a separate structural defect, pinned by case 4 rather than fixed
 * here and tracked as **AAASM-5196**: `usePoliciesQuery` sends no
 * `include_archived`, and `list_policies` then returns only the most-recent
 * version with `active: true`, so for the admin callers who can reach the
 * endpoint at all the inactive count is 0 for every live response. What the
 * badge should count instead is a product question (the hi-fi rail carries a
 * hardcoded `badge: '1'` with no semantics), so it is reported, not silently
 * redefined.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so interception
 * has to happen at the network layer via `page.route` — an in-page shim
 * installed after boot would never be consulted. Auth is seeded with
 * `addInitScript` so the token is in sessionStorage before any module runs.
 *
 * Screenshots land in dashboard/verify/5186/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5186')
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

/** One row exactly as `aa-api` serialises `PolicyResponse`. */
function policy(name: string, active: boolean) {
  return {
    name,
    version: '2026-06-01T10:00:00Z',
    rule_count: 5,
    active,
    policy_yaml: `metadata:\n  name: ${name}\nrules: []\n`,
  }
}

/** `PaginatedPolicyResponse` around a page of rows. */
function page_(items: ReturnType<typeof policy>[]) {
  return { items, page: 1, per_page: 50, total: items.length }
}

/** An archive-inclusive listing: one live version, two superseded. */
const POLICIES_MIXED = page_([
  policy('a1b2c3d4e5f6', true),
  policy('0f1e2d3c4b5a', false),
  policy('99887766aabb', false),
])

/** A listing that loaded cleanly and genuinely has nothing inactive. */
const POLICIES_ALL_ACTIVE = page_([policy('a1b2c3d4e5f6', true)])

interface Harness {
  errors: string[]
  /** Every `/api/v1/policies` URL the app actually requested. */
  policyRequests: string[]
}

interface Fixture {
  /** Fail `GET /api/v1/policies` at the network layer. */
  failPolicies?: boolean
  /** Body for a successful policies list. */
  policies?: unknown
  /** Scopes on the seeded token. Admin unless a case is about the boundary. */
  scopes?: string[]
}

/** Minimal unsigned JWT; the dashboard never verifies it — the gateway does. */
function makeToken(scopes: string[] = ['read', 'write', 'admin']): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5186', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [], policyRequests: [] }

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
    { themeKey: THEME_KEY, theme, token: makeToken(fixture.scopes) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route(/\/api\/v1\/alerts(\?.*)?$/, (r) =>
    r.fulfill({ json: { items: [], total: 0, page: 1, per_page: 50 } }),
  )
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) => r.fulfill({ json: { items: AGENTS } }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route(/\/api\/v1\/policies(\?.*)?$/, (r) => {
    harness.policyRequests.push(r.request().url())
    return fixture.failPolicies
      ? r.fulfill({ status: 503, json: { detail: 'policy store unavailable' } })
      : r.fulfill({ json: fixture.policies ?? POLICIES_MIXED })
  })

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

/** The Policy chip's text with the screen-reader sentence stripped out. */
function sightedBadgeText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const chip = document.querySelector('[data-testid="nav-badge-policy"]')
    if (!chip) return '<no badge>'
    const clone = chip.cloneNode(true) as HTMLElement
    clone.querySelectorAll('.truth-sr-only').forEach((el) => el.remove())
    return clone.textContent ?? ''
  })
}

test.describe('AAASM-5186 — the Policy badge claims only what it knows', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`a failed policies request never reads as zero inactive — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failPolicies: true })
      await navigate(page, '/agents')

      const marker = page.getByTestId('nav-badge-absent-policy')
      await expect(marker).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      await expect(marker).toHaveAttribute('title', /Unavailable/)

      // The sighted chip is the shared marker and nothing else — in particular
      // not a count, and not the `0` the old `?? []` produced.
      expect(await sightedBadgeText(page)).toBe('—')
      expect(await sightedBadgeText(page)).not.toMatch(/\d/)

      // The absence is audible too: a screen reader must not meet a bare dash.
      await expect(marker).toContainText('the request for this value failed')

      // …but it must not *announce*. The rail mounts with the session, so a
      // live region here would fire on every cold boot; the sentence rides the
      // link's accessible name instead.
      expect(await marker.evaluate((el) => el.closest('[role="alert"]') !== null)).toBe(false)
      await expect(page.getByTestId('nav-link-policy')).toContainText(
        'the request for this value failed',
      )

      await shot(page, `policy-outage-${theme}`)
      await railShot(page, `policy-outage-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a loaded listing still counts its inactive versions — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { policies: POLICIES_MIXED })
      await navigate(page, '/agents')

      const badge = page.getByTestId('nav-badge-policy')
      await expect(badge).toHaveText('2')
      await expect(page.getByTestId('nav-badge-absent-policy')).toHaveCount(0)

      await railShot(page, `policy-count-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a known zero renders no badge at all — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { policies: POLICIES_ALL_ACTIVE })
      await navigate(page, '/agents')

      // Nothing to say, so nothing is said: an unadorned rail item is the
      // honest rendering of a resolved query that found no inactive version.
      await expect(page.getByTestId('nav-link-policy')).toBeVisible()
      await expect(page.getByTestId('nav-badge-policy')).toHaveCount(0)
      await expect(page.getByTestId('nav-badge-absent-policy')).toHaveCount(0)

      await railShot(page, `policy-known-zero-rail-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }

  test('records the live-shaped response the shell actually asks for', async ({ page }) => {
    // Not a fix, a pin — AAASM-5196. `list_policies` returns only the
    // most-recent version unless `include_archived=true`, and marks it
    // `active`. The shell sends no such parameter, so its inactive count is 0
    // for every live response an admin can obtain — the numeric badge is
    // unreachable in production. Captured here so the follow-up has evidence
    // rather than an argument.
    const harness = await bootstrap(page, 'light', { policies: POLICIES_ALL_ACTIVE })
    await navigate(page, '/agents')
    await expect(page.getByTestId('nav-badge-policy')).toHaveCount(0)

    expect(harness.policyRequests.length).toBeGreaterThan(0)
    for (const url of harness.policyRequests) {
      expect(url).not.toContain('include_archived')
    }

    await railShot(page, 'policy-live-shaped-rail')
    expect(harness.errors).toEqual([])
  })

  test('asks for nothing when the operator may not list policies', async ({ page }) => {
    // The authorisation boundary end-to-end. `list_policies` requires
    // cross-tenant admin scope (AAASM-3995(a)), so a read/write operator would
    // otherwise spend a guaranteed 403 on every page load and wear a permanent
    // fault marker announcing "the request for this value failed" — a
    // fail-*wrong* in place of this ticket's fail-open. The honest rendering of
    // a question the operator may not ask is no claim at all.
    const harness = await bootstrap(page, 'light', {
      scopes: ['read', 'write'],
      policies: POLICIES_MIXED,
    })
    await navigate(page, '/agents')

    // Even though the fixture would have supplied two inactive versions.
    expect(harness.policyRequests).toEqual([])
    await expect(page.getByTestId('nav-badge-policy')).toHaveCount(0)
    await expect(page.getByTestId('nav-badge-absent-policy')).toHaveCount(0)
    // The route stays navigable — this withholds a claim, not the nav item.
    await expect(page.getByTestId('nav-link-policy')).toBeVisible()

    await railShot(page, 'policy-no-admin-rail')
    expect(harness.errors).toEqual([])
  })
})
