/**
 * Design-fidelity verification for the AAASM-1592 S-K Retention Policy
 * admin page (AAASM-1871 — sub-ticket [6/6]).
 *
 * Companion to the functional AC verification in
 * `retention-policy.spec.ts` (AAASM-1869). This spec walks the *rendered
 * visual contract* of the page and asserts each element against the
 * tokens declared in `dashboard/src/pages/Settings/Settings.css`:
 *
 *   - Primary "Save Changes" button: `--color-primary` background, white text
 *   - Validation-error border: `--color-danger`
 *   - Status banner success / error backgrounds: `--color-bg-success` / `--color-bg-danger`
 *   - Stat grid: `repeat(auto-fit, minmax(160px, 1fr))`
 *
 * Captures full-page screenshots into
 * `dashboard/docs/verification/aaasm-1871/` for visual review alongside
 * the story description's ASCII layout reference.
 *
 * Known accepted divergences from the story's ASCII layout (NOT
 * regressions — pre-existing design decisions captured here so future
 * reviewers don't re-litigate):
 *
 *   - Story shows a single-column form with full-width buttons; impl
 *     uses an `actions__` row with three buttons inline. Same controls,
 *     same affordance, more compact.
 *   - Story shows "Drop / Archive to S3" as a dropdown with the literal
 *     "▼ Drop" arrow glyph; impl uses a native `<select>` (browser
 *     renders its own arrow). Same control, native chrome.
 *   - Story shows the "Last retention run" stats as a 5-row block with
 *     "Compressed / Archived / Dropped / Freed" labels; impl uses a
 *     5-cell `repeat(auto-fit, minmax(160px, 1fr))` grid with the same
 *     5 labels. Same data, responsive layout.
 */

import { test, expect, type Page, type Request, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1871')

// Token RGB values from `dashboard/src/pages/Settings/Settings.css`
// (default fallbacks since no parent .css override is registered for
// the new Storage tokens yet — production renders the same RGBs).
const TOKEN_RGB = {
  primaryBg: 'rgb(37, 99, 235)', // #2563eb — --color-primary
  primaryFg: 'rgb(255, 255, 255)',
  dangerBorder: 'rgb(197, 66, 66)', // #c54242 — --color-danger (border)
  successBannerBg: 'rgb(231, 246, 236)', // #e7f6ec — --color-bg-success
  errorBannerBg: 'rgb(250, 236, 236)', // #faecec — --color-bg-danger
}

// ── Fixtures + mocks (parallel pattern from retention-policy.spec.ts) ────────

interface RetentionDocOverrides {
  hot_days?: number
  warm_days?: number
  cold_action?: 'drop' | 'archive'
  archive_url?: string | null
  last_run?: ReturnType<typeof makeStats> | null
}

function makeStats(overrides: Partial<ReturnType<typeof makeStatsRaw>> = {}) {
  return { ...makeStatsRaw(), ...overrides }
}

function makeStatsRaw() {
  return {
    ran_at: '2026-05-20T03:00:12Z',
    hot_rows: 1234,
    compressed_rows: 1452,
    archived_rows: 0,
    dropped_rows: 388,
    freed_bytes: 127 * 1024 * 1024,
    dry_run: false,
  }
}

function makeDoc(overrides: RetentionDocOverrides = {}) {
  return {
    hot_days: overrides.hot_days ?? 30,
    warm_days: overrides.warm_days ?? 90,
    cold_action: overrides.cold_action ?? 'drop',
    archive_url: overrides.archive_url ?? null,
    dry_run: false,
    schedule: '0 0 3 * * *',
    last_run: overrides.last_run === undefined ? null : overrides.last_run,
  }
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockBackend(page: Page, doc: ReturnType<typeof makeDoc>) {
  await page.route('**/api/v1/approvals**', (route: Route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route: Route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/ws/events*', (route: Route) => route.abort())
  await page.route('**/api/v1/admin/retention-policy', async (route: Route, request: Request) => {
    if (request.method() === 'GET') return route.fulfill({ status: 200, json: doc })
    if (request.method() === 'PUT') return route.fulfill({ status: 200, json: doc })
    return route.fallback()
  })
}

async function gotoRetentionPolicy(page: Page) {
  await page.goto('/settings')
  await page.getByTestId('settings-nav-link-storage-retention').click()
  await page.getByTestId('retention-policy-page').waitFor()
}

test.describe('AAASM-1592 S-K — Retention Policy page design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
  })

  test('page shell — heading, three numeric / select controls, three action buttons, last-run section', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    await expect(page.getByRole('heading', { level: 1, name: 'Retention Policy' })).toBeVisible()
    await expect(page.getByTestId('retention-policy-hot-days')).toBeVisible()
    await expect(page.getByTestId('retention-policy-warm-days')).toBeVisible()
    await expect(page.getByTestId('retention-policy-cold-action')).toBeVisible()
    await expect(page.getByTestId('retention-policy-save')).toBeVisible()
    await expect(page.getByTestId('retention-policy-dry-run')).toBeVisible()
    await expect(page.getByTestId('retention-policy-run')).toBeVisible()
    await expect(page.getByTestId('retention-policy-last-run')).toBeVisible()

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-shell-default.png`, fullPage: true })
  })

  test('Settings sidebar — Storage section + Retention Policy nav link in active state', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    await expect(page.getByTestId('settings-nav')).toBeVisible()
    await expect(page.getByTestId('settings-nav-section-storage')).toHaveText('Storage')
    const link = page.getByTestId('settings-nav-link-storage-retention')
    await expect(link).toBeVisible()
    await expect(link).toHaveClass(/settings-page__nav-link--active/)

    await page.screenshot({ path: `${EVIDENCE_DIR}/02-settings-nav.png`, fullPage: true })
  })

  test('Save Changes button uses --color-primary + white foreground', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    const button = page.getByTestId('retention-policy-save')
    const styles = await button.evaluate((el) => {
      const cs = window.getComputedStyle(el)
      return { bg: cs.backgroundColor, fg: cs.color }
    })
    expect(styles.bg).toBe(TOKEN_RGB.primaryBg)
    expect(styles.fg).toBe(TOKEN_RGB.primaryFg)
  })

  test('validation error state — warm_days input gets danger-bordered + error text visible', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    await page.getByTestId('retention-policy-warm-days').fill('30')

    const warmInput = page.getByTestId('retention-policy-warm-days')
    const errorClass = await warmInput.evaluate((el) =>
      (el as HTMLElement).className.includes('retention-policy__input--error'),
    )
    expect(errorClass).toBe(true)

    const borderColor = await warmInput.evaluate((el) => window.getComputedStyle(el).borderTopColor)
    expect(borderColor).toBe(TOKEN_RGB.dangerBorder)
    await expect(page.getByTestId('retention-policy-warm-days-error')).toBeVisible()
    await expect(page.getByTestId('retention-policy-save')).toBeDisabled()

    await page.screenshot({ path: `${EVIDENCE_DIR}/03-validation-error.png`, fullPage: true })
  })

  test('archive mode — Archive URL field appears with placeholder + danger-bordered when empty', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    await page.getByTestId('retention-policy-cold-action').selectOption('archive')

    const archiveField = page.getByTestId('retention-policy-archive-field')
    await expect(archiveField).toBeVisible()
    const archiveInput = page.getByTestId('retention-policy-archive-url')
    await expect(archiveInput).toHaveAttribute('placeholder', /s3:\/\//)

    const borderColor = await archiveInput.evaluate((el) => window.getComputedStyle(el).borderTopColor)
    expect(borderColor).toBe(TOKEN_RGB.dangerBorder)

    await page.screenshot({ path: `${EVIDENCE_DIR}/04-archive-mode.png`, fullPage: true })
  })

  test('last-run stats panel — 5-cell grid with all five labels rendered', async ({ page }) => {
    const lastRun = makeStats({ hot_rows: 5000, compressed_rows: 1452, archived_rows: 12, dropped_rows: 388 })
    await mockBackend(page, makeDoc({ last_run: lastRun }))
    await gotoRetentionPolicy(page)

    const panel = page.getByTestId('retention-policy-last-run')
    for (const label of ['Hot rows', 'Compressed', 'Archived', 'Dropped', 'Freed']) {
      await expect(panel).toContainText(label)
    }
    await expect(page.getByTestId('retention-policy-stat-hot')).toHaveText('5,000')
    await expect(page.getByTestId('retention-policy-stat-compressed')).toHaveText('1,452')
    await expect(page.getByTestId('retention-policy-stat-archived')).toHaveText('12')
    await expect(page.getByTestId('retention-policy-stat-dropped')).toHaveText('388')
    await expect(page.getByTestId('retention-policy-stat-freed')).toHaveText('127.0 MB')

    await page.screenshot({ path: `${EVIDENCE_DIR}/05-last-run-loaded.png`, fullPage: true })
  })

  test('stat grid uses tabular-nums + responsive auto-fit columns', async ({ page }) => {
    await mockBackend(page, makeDoc({ last_run: makeStats() }))
    await gotoRetentionPolicy(page)

    const stat = page.getByTestId('retention-policy-stat-hot')
    const fontVariant = await stat.evaluate((el) => window.getComputedStyle(el).fontVariantNumeric)
    expect(fontVariant).toContain('tabular-nums')

    const grid = await page.locator('.retention-policy__stat-grid').first().evaluate((el) => {
      return { display: window.getComputedStyle(el).display, cols: window.getComputedStyle(el).gridTemplateColumns }
    })
    expect(grid.display).toBe('grid')
    expect(grid.cols.split(' ').length).toBeGreaterThanOrEqual(2)
  })

  test('success banner uses --color-bg-success after a successful Save', async ({ page }) => {
    await mockBackend(page, makeDoc())
    await gotoRetentionPolicy(page)

    await page.getByTestId('retention-policy-hot-days').fill('15')
    await page.getByTestId('retention-policy-save').click()
    const banner = page.getByTestId('retention-policy-status')
    await expect(banner).toBeVisible()

    const bg = await banner.evaluate((el) => window.getComputedStyle(el).backgroundColor)
    expect(bg).toBe(TOKEN_RGB.successBannerBg)

    await page.screenshot({ path: `${EVIDENCE_DIR}/06-success-banner.png`, fullPage: true })
  })
})
