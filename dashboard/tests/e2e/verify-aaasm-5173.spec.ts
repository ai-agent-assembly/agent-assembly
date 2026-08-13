/**
 * Verification capture for AAASM-5173 — the shared truthfulness primitives.
 *
 * Re-derives, against a running build, the claims the PR makes:
 *
 *  1. **The AAASM-5106 guard holds end to end.** With `policies: []` — the
 *     cascade every shipped deployment resolves — `aa-api`'s `decide()` falls
 *     through to `Allow` for every cell, so the grid asserts `allow` across the
 *     whole matrix. The summary row must nevertheless report **Unconfigured**,
 *     not a permission total and a reassuring `0 denied`.
 *  2. **A real cascade still reports real numbers.** The guard must not be a
 *     blanket suppression: with a policy document loaded the same row asserts
 *     its counts, including an honest `0`.
 *  3. **Absence of evaluation is distinct from absence of findings.** The
 *     flagged-agents column is `Not evaluated` in both cases, because nothing
 *     in the gateway computes over-permission — it is never `0`.
 *  4. **A failed request renders as the converged `unavailable` surface**, with
 *     `role="alert"`, rather than as an empty or healthy-looking page.
 *  5. Neither path produces console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5173/, light and dark.
 *
 * Visual reach is deliberately limited to the states the wired surface can
 * actually reach. `unknown`, `not-supported`, and `demo` have no production
 * path on the Capability page today; they are covered by the unit suites
 * (`src/lib/truthfulness/*.test.ts`, `src/components/truthfulness/*.test.tsx`)
 * and will get in-app evidence from whichever page lane first renders them.
 * Manufacturing a synthetic page to photograph them would be exactly the kind
 * of fabricated evidence this lane exists to remove.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5173')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const ID_A = 'aa'.repeat(16)
const ID_B = 'bb'.repeat(16)

/** Two agents whose every modelled cell resolved to `allow`. */
const AGENTS = [
  {
    id: ID_A,
    name: 'checkout-agent',
    framework: 'langgraph',
    owner: 'team-alpha',
    status: 'active',
    lastSeen: '2026-07-26T11:59:30Z',
    caps: {
      filesystem: { read: 'allow', write: 'allow', delete: 'allow', exec: 'na' },
      terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
    },
  },
  {
    id: ID_B,
    name: 'support-triage',
    framework: 'crewai',
    owner: 'team-beta',
    status: 'active',
    lastSeen: '2026-07-26T11:58:10Z',
    caps: {
      filesystem: { read: 'allow', write: 'allow', delete: 'allow', exec: 'na' },
      terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
    },
  },
]

const RESOURCES = [
  { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
  { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
  { id: 'network_outbound', name: 'Network (outbound)', group: 'infra', paths: [] },
]

/**
 * The AAASM-5106 payload: a complete projection with an empty cascade. Note
 * that nothing about the *cells* signals the problem — every one says `allow`.
 * The only evidence is `policies: []`, which is why the rule has to key off the
 * cascade rather than off the verdicts.
 */
const MATRIX_NO_CASCADE = {
  resources: RESOURCES,
  agents: AGENTS,
  policies: [],
  sampleCalls: [],
  // AAASM-5106: no cascade loaded — the summary must read Unknown, not a real 0.
  cascadeLoaded: false,
}

/** The same fleet, with one policy document actually in force. */
const MATRIX_WITH_CASCADE = {
  ...MATRIX_NO_CASCADE,
  cascadeLoaded: true,
  policies: [
    {
      id: 'global/baseline',
      name: 'baseline',
      scope: 'global',
      status: 'active',
      affects: [ID_A, ID_B],
      rules: [{ resource: 'filesystem', verb: ['delete'], action: 'deny', condition: '' }],
    },
  ],
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades and the deliberate 500 below are the fixture's doing.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5173')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

async function openCapability(page: Page) {
  await page.goto('/capability')
  await page.getByTestId('capability-page').waitFor()
}

async function openPolicies(page: Page) {
  await page.goto('/policies')
  await page.getByTestId('policies-page').waitFor()
}

test.describe('AAASM-5173 — truthfulness primitives', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`an empty cascade renders Unconfigured, never a permission total (${theme})`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await page.route('**/api/v1/capability/matrix**', (r) =>
        r.fulfill({ json: MATRIX_NO_CASCADE }),
      )
      await openCapability(page)

      // AAASM-5187 (ADR 0026 Decision 2) removed the `narrowed` tile: `narrow`
      // is a state `GET /capability/matrix` cannot emit, so there is no
      // `cap-summary-narrow` surface to assert. The unconfigured contract holds
      // for the two tiles the summary actually renders.
      for (const id of ['cap-summary-allow', 'cap-summary-deny']) {
        const stat = page.getByTestId(id)
        await expect(stat).toHaveAttribute('data-truth-state', 'unconfigured')
        await expect(stat).toContainText('—')
        await expect(stat).toContainText('Unconfigured')
        // The whole point: no digit may appear where a count would have been.
        await expect(stat).not.toContainText(/\d/)
      }

      // Absence of evaluation, not absence of findings.
      const flagged = page.getByTestId('cap-summary-flagged')
      await expect(flagged).toHaveAttribute('data-truth-state', 'not-evaluated')
      await expect(flagged).toContainText('Not evaluated')

      await page.screenshot({
        path: `${EVIDENCE_DIR}/summary-unconfigured-${theme}.png`,
        fullPage: true,
      })
      expect(harness.errors).toEqual([])
    })

    test(`a loaded cascade still asserts real counts (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await page.route('**/api/v1/capability/matrix**', (r) =>
        r.fulfill({ json: MATRIX_WITH_CASCADE }),
      )
      await openCapability(page)

      const allow = page.getByTestId('cap-summary-allow')
      await expect(allow).toHaveAttribute('data-truth-state', 'known')
      // Since AAASM-5125 the page lands on the verb the projection populates
      // most, not a hard-coded `write`: these agents each carry exec=allow on
      // Terminal and Network (four cells) against filesystem write's two, so the
      // summary opens on EXEC and counts two agents × two exec-allow resources.
      await expect(allow).toHaveText('4')

      // The guard is not a blanket suppression: a zero backed by loaded rules
      // is a real measurement and is asserted as one.
      const deny = page.getByTestId('cap-summary-deny')
      await expect(deny).toHaveAttribute('data-truth-state', 'known')
      await expect(deny).toHaveText('0')

      // …but the column nothing computes stays absent even here.
      await expect(page.getByTestId('cap-summary-flagged')).toHaveAttribute(
        'data-truth-state',
        'not-evaluated',
      )

      await page.screenshot({
        path: `${EVIDENCE_DIR}/summary-known-${theme}.png`,
        fullPage: true,
      })
      expect(harness.errors).toEqual([])
    })

    test(`a failed request renders the converged unavailable surface (${theme})`, async ({
      page,
    }) => {
      // Captured on Policies, one of the four call sites that used the second,
      // competing state family and now delegates to the shared `StatusState`.
      await bootstrap(page, theme)
      await page.route('**/api/v1/policies**', (r) =>
        r.fulfill({ status: 500, json: { detail: 'gateway error' } }),
      )
      await openPolicies(page)

      const surface = page.getByTestId('error-state')
      // The app's QueryClient keeps TanStack's default 3 retries with
      // exponential backoff, so the terminal failure lands ~7s after the first
      // 500 — past the default expect timeout.
      await expect(surface).toBeVisible({ timeout: 20_000 })
      await expect(surface).toHaveAttribute('data-truth-state', 'unavailable')
      // Reserved for the one state that means something is broken.
      await expect(surface).toHaveAttribute('role', 'alert')
      await expect(surface).toContainText('Unavailable')
      // A failure must not be dressed up as an empty result.
      await expect(page.getByTestId('empty-state')).toHaveCount(0)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/status-state-unavailable-${theme}.png`,
        fullPage: true,
      })
    })

    test(`a genuinely empty result stays a known answer (${theme})`, async ({ page }) => {
      // The other half of the convergence: zero rows is a fact the query
      // actually returned, so it carries no absence badge and no fault tone.
      const harness = await bootstrap(page, theme)
      await page.route('**/api/v1/policies**', (r) =>
        r.fulfill({ json: { items: [], page: 1, per_page: 50, total: 0 } }),
      )
      await openPolicies(page)

      const surface = page.getByTestId('empty-state')
      await expect(surface).toBeVisible()
      await expect(surface).toHaveAttribute('data-truth-state', 'empty')
      await expect(surface).toHaveAttribute('role', 'status')
      await expect(surface).not.toContainText('Unavailable')

      await page.screenshot({
        path: `${EVIDENCE_DIR}/status-state-empty-${theme}.png`,
        fullPage: true,
      })
      expect(harness.errors).toEqual([])
    })
  }
})
