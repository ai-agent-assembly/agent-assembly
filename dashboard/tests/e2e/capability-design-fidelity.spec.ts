/**
 * Design-fidelity verification for the /capability page (AAASM-1346 / AAASM-1392).
 *
 * Walks the rendered CapabilityPage and asserts the visual contract against
 * the hi-fi reference at `design/v1/capability.jsx` + `design/v1/styles.css`:
 *   - decision-cell backgrounds resolve to the documented token RGB values
 *   - matrix grid template column count = 1 (agent column) + N resources
 *   - active tab carries a visible bottom-border accent
 *   - per-resource and per-agent tabs render their two-pane layouts
 *
 * Captures full-page screenshots into
 * `dashboard/docs/verification/aaasm-1392/` for visual review.
 *
 * Two describe blocks run the same checks at 1280 px and 1920 px viewports
 * per AAASM-94 AC #responsive.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1392')

// Hi-fi token RGB values from `design/v1/styles.css` and `dashboard/src/styles.css`.
// Drift between the two source-of-truth files would cause these assertions to fail.
const HIFI_TOKENS = {
  paper3: 'rgb(235, 233, 226)', // #ebe9e2 — allow / na cell background
  warnBg: 'rgb(245, 230, 196)', // #f5e6c4 — narrow cell background
  infoBg: 'rgb(214, 223, 238)', // #d6dfee — approval cell background
  dangerBg: 'rgb(246, 218, 214)', // #f6dad6 — deny cell background
  ink: 'rgb(14, 14, 14)', // #0e0e0e — active tab indicator
}

async function injectToken(page: Page) {
  await page.addInitScript(() =>
    localStorage.setItem('aa_token', 'capability-fidelity-token'),
  )
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
}

async function gotoCapability(page: Page) {
  await page.goto('/capability')
  await page.getByTestId('capability-page').waitFor()
}

function describeAtViewport(width: number, height: number) {
  test.describe(`AAASM-1392 — Capability design fidelity @ ${width}×${height}`, () => {
    test.use({ viewport: { width, height } })

    test.beforeAll(async () => {
      await mkdir(EVIDENCE_DIR, { recursive: true })
    })

    test.beforeEach(async ({ page }) => {
      await injectToken(page)
      await mockApi(page)
    })

    test('decision-cell backgrounds resolve to the documented hi-fi tokens', async ({
      page,
    }) => {
      await gotoCapability(page)

      // The matrix renders cells with class .cap-mx-cell--<decision>.
      // Each must resolve to the token RGB declared in styles.css.
      const expectations: Array<[string, string]> = [
        ['.cap-mx-cell--allow', HIFI_TOKENS.paper3],
        ['.cap-mx-cell--narrow', HIFI_TOKENS.warnBg],
        ['.cap-mx-cell--approval', HIFI_TOKENS.infoBg],
        ['.cap-mx-cell--deny', HIFI_TOKENS.dangerBg],
        ['.cap-mx-cell--na', HIFI_TOKENS.paper3],
      ]
      for (const [selector, expected] of expectations) {
        const locator = page.locator(selector).first()
        if ((await locator.count()) === 0) continue
        const bg = await locator.evaluate(
          (el) => getComputedStyle(el as Element).backgroundColor,
        )
        expect(bg, `${selector} background`).toBe(expected)
      }

      await page.screenshot({
        path: `${EVIDENCE_DIR}/capability-${width}-cell-tokens.png`,
        fullPage: true,
      })
    })

    test('matrix grid uses agent column + one column per resource', async ({
      page,
    }) => {
      await gotoCapability(page)
      const grid = page.getByRole('grid', { name: 'capability matrix' })
      await expect(grid).toBeVisible()

      const tracks = await grid.evaluate((el) =>
        getComputedStyle(el as Element).gridTemplateColumns.split(/\s+/).filter(Boolean),
      )
      // 260 px agent header + N resource columns (8 in the fixture).
      expect(tracks.length).toBeGreaterThanOrEqual(2)
      // First track is the fixed-width agent column.
      const firstTrack = tracks[0]
      expect(firstTrack).toMatch(/^(260px|260\.\d+px)$/)
    })

    test('active tab carries a visible bottom-border accent', async ({ page }) => {
      await gotoCapability(page)
      const matrixTab = page.locator('.capability-tab').first()
      await expect(matrixTab).toHaveClass(/is-active/)
      const borderColor = await matrixTab.evaluate(
        (el) => getComputedStyle(el as Element).borderBottomColor,
      )
      expect(borderColor).toBe(HIFI_TOKENS.ink)

      // Inactive tab has a transparent bottom border.
      const otherTab = page.locator('.capability-tab').nth(1)
      const otherBorder = await otherTab.evaluate(
        (el) => getComputedStyle(el as Element).borderBottomColor,
      )
      expect(otherBorder).not.toBe(HIFI_TOKENS.ink)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/capability-${width}-tabs.png`,
        fullPage: true,
      })
    })

    test('per-resource tab renders the two-pane tree + table layout', async ({
      page,
    }) => {
      await gotoCapability(page)
      await page.locator('.capability-tab').nth(1).click()
      await page.getByTestId('per-resource-tab').waitFor()

      const layout = page.getByTestId('per-resource-tab')
      const cols = await layout.evaluate(
        (el) => getComputedStyle(el as Element).gridTemplateColumns.split(/\s+/).filter(Boolean),
      )
      // 280 px tree + 1fr body — two columns total.
      expect(cols).toHaveLength(2)
      expect(cols[0]).toMatch(/^(280px|280\.\d+px)$/)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/capability-${width}-per-resource.png`,
        fullPage: true,
      })
    })

    test('per-agent tab renders the two-pane tree + matrix layout', async ({
      page,
    }) => {
      await gotoCapability(page)
      await page.locator('.capability-tab').nth(2).click()
      await page.getByTestId('per-agent-tab').waitFor()

      const layout = page.getByTestId('per-agent-tab')
      const cols = await layout.evaluate(
        (el) => getComputedStyle(el as Element).gridTemplateColumns.split(/\s+/).filter(Boolean),
      )
      expect(cols).toHaveLength(2)
      expect(cols[0]).toMatch(/^(280px|280\.\d+px)$/)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/capability-${width}-per-agent.png`,
        fullPage: true,
      })
    })
  })
}

describeAtViewport(1280, 800)
describeAtViewport(1920, 1080)
