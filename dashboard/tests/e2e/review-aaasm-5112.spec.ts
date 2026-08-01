/**
 * Review pass for AAASM-5112 / AAASM-5156 — the Scrub surface stops announcing
 * a DLP posture nobody measured.
 *
 * Re-derives, in a real browser, the claims a reviewer would otherwise take on
 * trust, so a regression fails here rather than sitting in a screenshot nobody
 * diffs:
 *
 *  1. none of the removed literals — `0 leaks (30d)`, `covers: http egress ·
 *     gmail · slack`, `policy: P-100 · default-allow with scrub` — renders
 *     anywhere on the page;
 *  2. the page has exactly one `aria-live` region, it holds only the fetched
 *     redaction count, and what it announces is screen-reader-visible text
 *     carrying the honest state — never an all-clear;
 *  3. a failed request renders `Unavailable`, not `0` and not a green posture;
 *  4. an empty `agent-enforcement` response renders `Unknown`, because the route
 *     omits agents with no decision and so cannot mean "zero redactions";
 *  5. a populated response renders the real fleet sum;
 *  6. every detector id in the catalogue is a real `CredentialKind`, every
 *     redaction label is `[REDACTED:<kind>]`, and the four phantom detectors
 *     (`AWS_SECRET`, `JWT`, `INTERNAL_URL`, `PHONE`) are gone;
 *  7. the catalogue offers no enable/disable control, and the actions with no
 *     production path are disabled;
 *  8. all of the above holds in light *and* dark, with no console errors.
 *
 * Screenshots land in dashboard/verify/5112/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'
import { routeScrubApi } from './_fixtures/scrub-routes'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5112')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** Literals AAASM-5112 removed. None may render anywhere on the page again. */
const FABRICATIONS = [
  '0 leaks',
  'leaks (30d)',
  'P-100',
  'default-allow with scrub',
  'http egress · gmail · slack',
  '192 stripped',
]

/** Fixture ids AAASM-5156 found had no detector in the shipped scanner. */
const PHANTOM_DETECTORS = ['AWS_SECRET', 'JWT', 'INTERNAL_URL', 'PHONE']

/** Redaction labels the previous fixture taught that aa-security never emits. */
const PHANTOM_LABELS = ['[REDACTED:PEM]', '[REDACTED:AWS_KEY]', '[REDACTED:INT_URL]']

/** A populated window: two agents, nine redactions between them. */
const ENFORCEMENT_POPULATED = [
  { agent_id: 'a1', blocked: 2, scrubbed: 5 },
  { agent_id: 'a2', blocked: 0, scrubbed: 4 },
]

type EnforcementFixture = 'populated' | 'empty' | 'error'

interface Harness {
  errors: string[]
}

async function bootstrap(
  page: Page,
  theme: Theme,
  fixture: EnforcementFixture,
): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades and the deliberately-failed fixture route are the
    // harness's doing, not the app's.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5112')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); the specific fixture registered
  // afterwards wins, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  // AAASM-5347 wired the catalogue, the per-kind tally and the posture to real
  // routes, and `{}` is not a valid body for any of them. The three fixtures are
  // constant across the enforcement variants below on purpose: what each test
  // varies is the `agent-enforcement` answer, so everything else has to hold
  // still for the resulting stat-strip state to be attributable to it.
  await routeScrubApi(page)
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => {
    if (fixture === 'error') return r.fulfill({ status: 503, json: { error: 'unavailable' } })
    return r.fulfill({ json: fixture === 'populated' ? ENFORCEMENT_POPULATED : [] })
  })
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

async function gotoScrub(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/scrub')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await page.getByTestId('scrub-page').waitFor()
}

test.describe('AAASM-5112 review — the Scrub surface stops fabricating a DLP posture', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`no fabricated posture, and one honest live region in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'populated')
      await gotoScrub(page)

      // ── 1. none of the removed literals renders ──────────────────────────
      const pageText = (await page.getByTestId('scrub-page').textContent()) ?? ''
      for (const fabrication of FABRICATIONS) {
        expect(pageText, `"${fabrication}" must not render`).not.toContain(fabrication)
      }
      expect(pageText).not.toContain('undefined')
      expect(pageText).not.toContain('NaN')

      // ── 2. exactly one live region, holding only the fetched figure ──────
      const live = page.locator('[aria-live]')
      await expect(live).toHaveCount(1)
      await expect(live.first()).toHaveAttribute('data-testid', 'scrub-stats-stripped')
      const announced = (await live.first().textContent()) ?? ''
      expect(announced).toContain('redactions / 24h')
      expect(announced).not.toMatch(/\b(safe|healthy|verified|clean|secure|all clear)\b/i)

      // ── 5. a populated window renders the real fleet sum ─────────────────
      const strippedValue = page.getByTestId('scrub-stats-stripped-value')
      await expect(strippedValue).toHaveAttribute('data-truth-state', 'known')
      await expect(strippedValue).toHaveText('9')

      // ── the unsourceable segments are explicit, screen-reader-visible ────
      for (const testId of [
        'scrub-stats-posture-value',
        'scrub-stats-covers-value',
        'scrub-stats-policy-value',
        'scrub-stats-running-value',
      ]) {
        const el = page.getByTestId(testId)
        await expect(el).toHaveAttribute('data-truth-state', 'not-supported')
        // The state is announced, not merely coloured: the sr-only sentence is
        // in the accessibility tree even though the glyph is a bare dash.
        await expect(el.locator('.truth-sr-only')).toContainText(
          'Not supported — the backend cannot provide this value.',
        )
      }

      await page.locator('.scrub-stats').screenshot({
        path: `${EVIDENCE_DIR}/scrub-stats-populated-${theme}.png`,
      })
      await page.screenshot({
        path: `${EVIDENCE_DIR}/scrub-page-populated-${theme}.png`,
        fullPage: true,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`a failed request announces Unavailable, never 0, in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'error')
      await gotoScrub(page)

      // ── 3. the failure stays visible rather than degrading to a default ──
      // The app's QueryClient keeps TanStack's default retry policy (3 attempts
      // with exponential backoff), so the request is legitimately still pending
      // — and correctly rendering `unknown`, not a fault — for several seconds
      // before it finally settles as `unavailable`. Waiting past the retries is
      // the point: the assertion is that the *settled* state is a failure, not
      // a zero.
      const value = page.getByTestId('scrub-stats-stripped-value')
      await expect(value).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: 30_000,
      })
      await expect(value.locator('.truth-absent__glyph')).toHaveText('—')
      await expect(value.locator('.truth-sr-only')).toContainText(
        'Unavailable — the request for this value failed.',
      )

      const announced = (await page.locator('[aria-live]').first().textContent()) ?? ''
      expect(announced).not.toMatch(/\b0\b/)
      expect(announced).not.toMatch(/\b(safe|healthy|clean)\b/i)

      await page.locator('.scrub-stats').screenshot({
        path: `${EVIDENCE_DIR}/scrub-stats-unavailable-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`an empty window announces Unknown, not zero redactions, in ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, 'empty')
      await gotoScrub(page)

      // ── 4. `[]` omits agents with no decision, so it cannot mean zero ────
      const value = page.getByTestId('scrub-stats-stripped-value')
      await expect(value).toHaveAttribute('data-truth-state', 'unknown')
      await expect(value.locator('.truth-sr-only')).toContainText(
        'Unknown — this value could not be determined.',
      )
      const announced = (await page.locator('[aria-live]').first().textContent()) ?? ''
      expect(announced).not.toContain('0 redactions')

      await page.locator('.scrub-stats').screenshot({
        path: `${EVIDENCE_DIR}/scrub-stats-unknown-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`the catalogue is real, read-only and hit-free in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, 'populated')
      await gotoScrub(page)

      const catalogue = page.getByTestId('scrub-patterns')
      await expect(catalogue).toBeVisible()

      // ── 6. no phantom detector, and every label is a real kind ───────────
      const catalogueText = (await catalogue.textContent()) ?? ''
      for (const phantom of PHANTOM_DETECTORS) {
        expect(catalogueText, `${phantom} has no detector and must not render`).not.toContain(
          phantom,
        )
      }
      await expect(page.getByTestId('scrub-patterns-row-AwsAccessKey')).toBeVisible()
      await expect(page.getByTestId('scrub-patterns-row-GenericHighEntropy')).toBeVisible()

      await page.getByTestId('scrub-patterns-row-RsaPrivateKey').click()
      await expect(page.getByTestId('scrub-detail-replace')).toHaveText(
        '[REDACTED:RsaPrivateKey]',
      )
      const detailText = (await page.getByTestId('scrub-detail').textContent()) ?? ''
      for (const phantom of PHANTOM_LABELS) {
        expect(detailText).not.toContain(phantom)
      }

      // ── every 24h cell is an absence, never a fixture integer ────────────
      const hits = page.getByTestId('scrub-patterns-hits-AwsAccessKey')
      await expect(hits).toHaveAttribute('data-truth-state', 'not-supported')
      await expect(hits.locator('.truth-absent__glyph')).toHaveText('—')

      // ── 7. no toggle, and the dead actions are disabled ──────────────────
      await expect(catalogue.locator('input[type="checkbox"]')).toHaveCount(0)
      await expect(page.getByTestId('scrub-detail-test')).toBeDisabled()
      await expect(page.getByTestId('scrub-detail-disable')).toBeDisabled()
      await expect(page.getByTestId('scrub-export-config')).toBeDisabled()

      // The preview does not bless its own output.
      await expect(page.getByTestId('scrub-diff-scope')).toHaveText('approximation')
      await expect(page.getByTestId('scrub-diff-caveat')).toContainText('approximates')

      await catalogue.screenshot({ path: `${EVIDENCE_DIR}/scrub-catalogue-${theme}.png` })
      await page.getByTestId('scrub-diff').screenshot({
        path: `${EVIDENCE_DIR}/scrub-payload-diff-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
