/**
 * Verification for AAASM-5366 — a schema-invalid `200` degrades to an explicit
 * absence instead of taking the Scrub page down.
 *
 * ## What this re-derives in a real browser
 *
 * The defect was found here, not in a unit test: a harness fulfilling every
 * `/api/**` with `{}` made `scrubCatalogueFromQuery` read `patterns.length` off
 * `undefined`, the `TypeError` reached the `AppShell` error boundary, and the
 * operator got "Something went wrong" in place of the product's DLP surface.
 * Unit tests can prove the fold returns an absence; only a browser can prove the
 * *page* survives, that the reason reaches the DOM, and that the boundary never
 * catches anything.
 *
 * Four cases, each a different unreadable answer:
 *
 *  1. `/scrub/patterns` → `{}` — the exact body that unmounted the page.
 *  2. `/scrub/patterns` → a row missing four of its five fields.
 *  3. `/scrub/patterns` unreadable while `agent-enforcement` answers properly —
 *     the measured figure has to stay on screen. One bad route may cost its own
 *     segments and nothing else.
 *  4. the two aggregations unreadable while the catalogue answers properly — the
 *     mirror image, proving the containment is not one-directional.
 *
 * Throughout: no fabricated value anywhere (no `0`, no green posture), and the
 * live region announces the reason rather than an unmeasured all-clear
 * (AAASM-5112).
 *
 * Screenshots land in dashboard/verify/5366/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'
import { SCRUB_CATALOGUE_RESPONSE, SCRUB_PATTERN_COUNTS, SCRUB_POSTURE } from './_fixtures/scrub-routes'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5366')

/** A populated 24h enforcement window: one agent, six redactions. */
const ENFORCEMENT = [{ agent_id: 'a1', blocked: 0, scrubbed: 6 }]
const ENFORCEMENT_TOTAL = '6'

/** Bodies a proxy, a partial deploy or a stubbed route actually produces. */
const NO_PATTERNS_KEY = {}
const MALFORMED_ROW = { patterns: [{ kind: 'AwsAccessKey' }], total: 1 }

interface Harness {
  /** Console errors the app itself emitted. Fixture 404s are excluded. */
  readonly errors: string[]
}

/** What each of the four routes answers, before the permissive fallback. */
interface Fixtures {
  readonly patterns?: unknown
  readonly counts?: unknown
  readonly posture?: unknown
  readonly enforcement?: unknown
}

async function bootstrap(page: Page, fixtures: Fixtures): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // sessionStorage only — the token never goes to localStorage (AAASM-4322).
  await page.addInitScript(() => {
    sessionStorage.setItem('aa_token', 'e2e-verify-5366')
  })

  // Permissive fallback first (least specific); Playwright matches the most
  // recently added route, so the specific fixtures below win.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/scrub/patterns**', (r) =>
    r.fulfill({ json: fixtures.patterns ?? SCRUB_CATALOGUE_RESPONSE }),
  )
  await page.route('**/api/v1/scrub/pattern-counts**', (r) =>
    r.fulfill({ json: fixtures.counts ?? SCRUB_PATTERN_COUNTS }),
  )
  await page.route('**/api/v1/scrub/posture**', (r) =>
    r.fulfill({ json: fixtures.posture ?? SCRUB_POSTURE }),
  )
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) =>
    r.fulfill({ json: fixtures.enforcement ?? ENFORCEMENT }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  // Enter at `/` and navigate in-app rather than deep-linking: the bundle is
  // built with a relative `base`, so a direct `/scrub` load resolves its assets
  // against `/scrub/` and the app never boots.
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/scrub')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('scrub-page')).toBeVisible()
  return { errors }
}

/**
 * The page is still the page.
 *
 * `error-boundary` is the fallback the `AppShell` boundary renders once a render
 * throws — the thing an operator saw instead of the DLP surface. Asserting on
 * its absence is what makes this spec fail if the decoding is removed.
 */
async function expectPageIntact(page: Page, harness: Harness): Promise<void> {
  await expect(page.getByTestId('error-boundary')).toHaveCount(0)
  await expect(page.getByTestId('scrub-page')).toBeVisible()
  expect(harness.errors).toEqual([])
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

test.describe('AAASM-5366 — a schema-invalid 200 renders an absence', () => {
  test('a catalogue body with no patterns key states the reason instead of unmounting', async ({
    page,
  }) => {
    const harness = await bootstrap(page, { patterns: NO_PATTERNS_KEY })

    const marker = page.getByTestId('scrub-catalogue-absent-marker')
    await expect(marker).toBeVisible()
    await expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    // The reason has to name the field, in the DOM, where an operator and a
    // screen reader can both reach it — a bare `—` would be an absence nobody
    // can act on.
    await expect(marker).toContainText('patterns')
    await expect(marker).toContainText('pattern catalogue')

    await expectPageIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'catalogue-missing-patterns.png'),
      fullPage: true,
    })
  })

  test('a malformed pattern row degrades the same way', async ({ page }) => {
    const harness = await bootstrap(page, { patterns: MALFORMED_ROW })

    const marker = page.getByTestId('scrub-catalogue-absent-marker')
    await expect(marker).toBeVisible()
    await expect(marker).toContainText('patterns.0')
    // Not the retry panel: nothing failed, and retrying a well-formed request
    // that returns a malformed body just returns it again.
    await expect(page.getByTestId('error-state-generic')).toHaveCount(0)

    await expectPageIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'catalogue-malformed-row.png'),
      fullPage: true,
    })
  })

  test('the measured strip survives an unreadable catalogue', async ({ page }) => {
    const harness = await bootstrap(page, { patterns: NO_PATTERNS_KEY, enforcement: ENFORCEMENT })

    // The redaction count comes from a different route, and that route answered.
    await expect(page.getByTestId('scrub-stats-stripped-value')).toContainText(ENFORCEMENT_TOTAL)
    await expect(page.getByTestId('scrub-stats-measured')).toBeVisible()

    // The detector count is stated twice and is now unknown in both places —
    // never `0`. "We cannot read the catalogue" is not "the gateway ships no
    // detectors".
    for (const testId of ['scrub-stats-detectors-value', 'scrub-page-sub-detectors']) {
      await expect(page.getByTestId(testId)).toHaveAttribute('data-truth-state', 'unknown')
    }
    await expect(page.getByTestId('scrub-stats-detectors')).not.toContainText('0 detectors')

    // Exactly one live region, and what it announces is a measurement or a
    // reason — never an all-clear nothing measured (AAASM-5112).
    await expect(page.locator('[aria-live]')).toHaveCount(1)
    const announced = (await page.getByTestId('scrub-stats-measured').textContent()) ?? ''
    expect(announced).not.toMatch(/\b(safe|healthy|verified|clean|secure|all clear)\b/i)
    expect(announced).not.toContain('0 leaks')

    await expectPageIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'strip-survives-unreadable-catalogue.png'),
      fullPage: true,
    })
  })

  test('the catalogue survives unreadable aggregations', async ({ page }) => {
    const harness = await bootstrap(page, { counts: {}, posture: 'nope' })

    // The detector table has nothing to do with either aggregation, so it
    // renders in full while both of them report an absence.
    await expect(page.getByTestId('scrub-patterns-row-AwsAccessKey')).toBeVisible()
    await expect(page.getByTestId('scrub-stats-intercepted-value')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )
    await expect(page.getByTestId('scrub-patterns-hits-AwsAccessKey')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )

    await expectPageIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'catalogue-survives-unreadable-windows.png'),
      fullPage: true,
    })
  })
})
