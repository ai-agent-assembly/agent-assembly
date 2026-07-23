/**
 * AAASM-5030 regression — the onboarding footer (back / skip / continue) must
 * be reachable at BOTH large (1920×1200) and small (1280×720) viewports.
 *
 * Guards against the viewport-capped modal clipping its pinned footer: a hard
 * min-height floor on the scrollable body used to push the flex children past
 * the modal's max-height cap, and the modal's overflow:hidden then clipped the
 * footer off-screen with no way to scroll to it.
 *
 * Drives the wizard to step 3 (issue identity) and asserts the footer action
 * row sits inside the viewport and its buttons are actionable. Also captures
 * evidence screenshots into dashboard/verify/AAASM-5030/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/AAASM-5030')
const ONBOARDING_COMPLETED_KEY = 'aa.onboarding.completed'
const ONBOARDING_SESSION_KEY = 'aa.onboarding.session'

async function setup(page: Page) {
  await page.addInitScript(() =>
    sessionStorage.setItem('aa_token', 'aaasm-5030-token'),
  )
  await page.addInitScript(
    ([c, s]) => {
      localStorage.removeItem(c)
      localStorage.removeItem(s)
    },
    [ONBOARDING_COMPLETED_KEY, ONBOARDING_SESSION_KEY] as [string, string],
  )
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
}

async function gotoStep3(page: Page) {
  await page.goto('/onboarding')
  await page.getByTestId('onboarding-wizard').waitFor()
  // Step 1 framework → continue
  await page.getByTestId('onboarding-framework-langchain').click()
  await page.getByTestId('onboarding-continue').click()
  // Step 2 install → skip
  await page.getByTestId('onboarding-skip-step').click()
  // now on step 3 (identity)
  await expect(page.getByTestId('onboarding-stepper-identity')).toHaveAttribute(
    'data-status',
    'current',
  )
}

function run(width: number, height: number) {
  test.describe(`AAASM-5030 footer reachable @ ${width}×${height}`, () => {
    test.use({ viewport: { width, height } })
    test.beforeAll(async () => {
      await mkdir(EVIDENCE_DIR, { recursive: true })
    })
    test.beforeEach(async ({ page }) => setup(page))

    test('footer buttons are within viewport and clickable', async ({ page }) => {
      await gotoStep3(page)

      const footer = page.locator('.onb-foot')
      const cont = page.getByTestId('onboarding-continue')
      const back = page.getByTestId('onboarding-back')
      const skip = page.getByTestId('onboarding-skip-step')

      await expect(footer).toBeVisible()

      // Screenshot the wizard as rendered (not fullPage — we want the viewport).
      await page.screenshot({
        path: `${EVIDENCE_DIR}/step3-${width}x${height}.png`,
      })

      const vh = page.viewportSize()!.height
      for (const [name, loc] of [
        ['continue', cont],
        ['back', back],
        ['skip', skip],
      ] as const) {
        const box = await loc.boundingBox()
        expect(box, `${name} should have a box`).not.toBeNull()
        // The whole button must sit within the viewport (top ≥ 0, bottom ≤ vh).
        expect(box!.y, `${name}.top within viewport`).toBeGreaterThanOrEqual(0)
        expect(
          box!.y + box!.height,
          `${name}.bottom (${box!.y + box!.height}) within viewport (${vh})`,
        ).toBeLessThanOrEqual(vh)
      }

      // The footer button must actually be clickable (Playwright actionability
      // fails if it's off-screen / covered). `continue` is intentionally
      // disabled on step 3 until an identity is issued, so drive `back`.
      await back.click()
      await expect(
        page.getByTestId('onboarding-stepper-install'),
      ).toHaveAttribute('data-status', 'current')
    })
  })
}

run(1920, 1200)
run(1280, 720)
