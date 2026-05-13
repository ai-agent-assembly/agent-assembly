/**
 * Design-fidelity verification for the /scrub page (AAASM-1350 / AAASM-1392).
 *
 * Walks the rendered ScrubPage and asserts the visual contract against the
 * hi-fi reference at `design/v1/scrub.jsx` + `design/v1/styles.css`:
 *   - two-pane layout: 420 px patterns library + 1fr right column
 *   - severity chip colours map to the documented token RGB values
 *   - sandbox payload diff: raw-side match uses --danger-bg + line-through
 *   - sandbox payload diff: scrubbed-side placeholder uses --scrub-bg
 *
 * Captures full-page screenshots into `dashboard/docs/verification/aaasm-1392/`.
 *
 * Two describe blocks at 1280 px and 1920 px viewports per AAASM-94 AC.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1392')

const HIFI_TOKENS = {
  danger: 'rgb(184, 41, 30)', // #b8291e — critical severity chip
  warn: 'rgb(138, 90, 0)', // #8a5a00 — high severity chip
  info: 'rgb(29, 58, 122)', // #1d3a7a — medium severity chip
  ink3: 'rgb(90, 90, 90)', // #5a5a5a — low severity chip
  scrub: 'rgb(90, 26, 138)', // #5a1a8a — scrubbed-output placeholder text
  scrubBg: 'rgb(224, 210, 236)', // #e0d2ec — scrubbed-output placeholder background
  dangerBg: 'rgb(246, 218, 214)', // #f6dad6 — raw-side match background
}

async function injectToken(page: Page) {
  await page.addInitScript(() =>
    localStorage.setItem('aa_token', 'scrub-fidelity-token'),
  )
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
}

async function gotoScrub(page: Page) {
  await page.goto('/scrub')
  await page.getByTestId('scrub-page').waitFor()
}

function describeAtViewport(width: number, height: number) {
  test.describe(`AAASM-1392 — Scrub design fidelity @ ${width}×${height}`, () => {
    test.use({ viewport: { width, height } })

    test.beforeAll(async () => {
      await mkdir(EVIDENCE_DIR, { recursive: true })
    })

    test.beforeEach(async ({ page }) => {
      await injectToken(page)
      await mockApi(page)
    })

    test('two-pane layout uses 420 px left + 1fr right', async ({ page }) => {
      await gotoScrub(page)

      const body = page.locator('.scrub-body')
      await expect(body).toBeVisible()
      const cols = await body.evaluate((el) =>
        getComputedStyle(el as Element).gridTemplateColumns.split(/\s+/).filter(Boolean),
      )
      expect(cols).toHaveLength(2)
      expect(cols[0]).toMatch(/^(420px|420\.\d+px)$/)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/scrub-${width}-layout.png`,
        fullPage: true,
      })
    })

    test('severity chips resolve to the documented token RGBs', async ({ page }) => {
      await gotoScrub(page)

      const expectations: Array<[string, string]> = [
        ['.scrub-patterns-sev--critical', HIFI_TOKENS.danger],
        ['.scrub-patterns-sev--high', HIFI_TOKENS.warn],
        ['.scrub-patterns-sev--medium', HIFI_TOKENS.info],
        ['.scrub-patterns-sev--low', HIFI_TOKENS.ink3],
      ]
      for (const [selector, expected] of expectations) {
        const locator = page.locator(selector).first()
        if ((await locator.count()) === 0) continue
        const color = await locator.evaluate(
          (el) => getComputedStyle(el as Element).color,
        )
        expect(color, `${selector} text colour`).toBe(expected)
      }

      await page.screenshot({
        path: `${EVIDENCE_DIR}/scrub-${width}-severity-chips.png`,
        fullPage: true,
      })
    })

    test('sandbox payload diff: raw-side match has danger-bg + line-through', async ({
      page,
    }) => {
      await gotoScrub(page)

      const match = page.locator('.scrub-diff-match').first()
      await expect(match).toBeVisible()
      const bg = await match.evaluate(
        (el) => getComputedStyle(el as Element).backgroundColor,
      )
      expect(bg).toBe(HIFI_TOKENS.dangerBg)
      const decoration = await match.evaluate(
        (el) => getComputedStyle(el as Element).textDecorationLine,
      )
      expect(decoration).toContain('line-through')
    })

    test('sandbox payload diff: scrubbed placeholder uses scrub-bg + scrub colour', async ({
      page,
    }) => {
      await gotoScrub(page)

      const redacted = page.locator('.scrub-diff-redacted').first()
      await expect(redacted).toBeVisible()
      const bg = await redacted.evaluate(
        (el) => getComputedStyle(el as Element).backgroundColor,
      )
      expect(bg).toBe(HIFI_TOKENS.scrubBg)
      const color = await redacted.evaluate(
        (el) => getComputedStyle(el as Element).color,
      )
      expect(color).toBe(HIFI_TOKENS.scrub)

      // Placeholder text follows the [REDACTED:XXX] pattern.
      const text = await redacted.textContent()
      expect(text).toMatch(/^\[REDACTED:[A-Z0-9_]+\]$/)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/scrub-${width}-payload-diff.png`,
        fullPage: true,
      })
    })

    test('match summary lists per-pattern hits with counts', async ({ page }) => {
      await gotoScrub(page)
      // Default sample payload contains hits for several patterns.
      const summaryRows = page.locator('[data-testid^="scrub-diff-summary-"]')
      const count = await summaryRows.count()
      expect(count).toBeGreaterThan(0)
    })
  })
}

describeAtViewport(1280, 800)
describeAtViewport(1920, 1080)
