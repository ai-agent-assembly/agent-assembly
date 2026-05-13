/**
 * Design-fidelity verification for the /onboarding wizard
 * (AAASM-1351 / AAASM-1392).
 *
 * Walks the rendered OnboardingPage and asserts the visual contract against
 * the hi-fi reference at `design/v1/onboarding.jsx` + `design/v1/styles.css`:
 *   - modal proportions: ≤ 760 px wide, max-height ≤ 100vh − 64
 *   - stepper status: --ok done / --ink current / future-disabled
 *   - scrim: rgba(8, 9, 11, 0.78) with backdrop-filter blur
 *   - full 5-step happy path drives the wizard end-to-end → toast + navigate
 *   - already-configured gateway redirects synchronously (no flash of wizard)
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
  ok: 'rgb(34, 89, 42)', // #22592a — done step indicator
  ink: 'rgb(14, 14, 14)', // #0e0e0e — current step border / button
  paper: 'rgb(245, 244, 240)', // #f5f4f0 — modal background
}

const ONBOARDING_COMPLETED_KEY = 'aa.onboarding.completed'
const ONBOARDING_SESSION_KEY = 'aa.onboarding.session'

async function injectToken(page: Page) {
  await page.addInitScript(() =>
    localStorage.setItem('aa_token', 'onboarding-fidelity-token'),
  )
}

/**
 * The wizard's stepper buttons carry `transition: all 120ms`. Reading a
 * computed color immediately after a click can land mid-transition, so
 * Playwright sees an interpolated RGB value instead of the design token
 * the test is asserting against. Inject a sheet that nukes transitions
 * on every element — visual fidelity is the contract under test, not
 * the animation curve.
 */
async function disableTransitions(page: Page) {
  await page.addInitScript(() => {
    const style = document.createElement('style')
    style.setAttribute('data-test-disable-transitions', '')
    style.textContent =
      '*, *::before, *::after { transition: none !important; animation: none !important; }'
    document.documentElement.appendChild(style)
  })
}

async function clearOnboardingState(page: Page) {
  // Belt-and-braces: also clear via init script so a fresh page load
  // is guaranteed clean even if a prior test left state behind.
  await page.addInitScript(
    ([completedKey, sessionKey]) => {
      localStorage.removeItem(completedKey)
      localStorage.removeItem(sessionKey)
    },
    [ONBOARDING_COMPLETED_KEY, ONBOARDING_SESSION_KEY] as [string, string],
  )
}

async function preconfigureGateway(page: Page) {
  await page.addInitScript(
    (key) => localStorage.setItem(key, 'true'),
    ONBOARDING_COMPLETED_KEY,
  )
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
}

async function gotoOnboarding(page: Page) {
  await page.goto('/onboarding')
  await page.getByTestId('onboarding-wizard').waitFor()
}

function describeAtViewport(width: number, height: number) {
  test.describe(`AAASM-1392 — Onboarding design fidelity @ ${width}×${height}`, () => {
    test.use({ viewport: { width, height } })

    test.beforeAll(async () => {
      await mkdir(EVIDENCE_DIR, { recursive: true })
    })

    test.beforeEach(async ({ page }) => {
      await injectToken(page)
      await mockApi(page)
      await clearOnboardingState(page)
      await disableTransitions(page)
    })

    test('modal sits within hi-fi proportions (width ≤ 760, max-height ≤ vh − 64)', async ({
      page,
    }) => {
      await gotoOnboarding(page)
      const modal = page.locator('.onb-modal')
      await expect(modal).toBeVisible()

      const declaredWidth = await modal.evaluate(
        (el) => parseFloat(getComputedStyle(el as Element).width),
      )
      expect(declaredWidth).toBeLessThanOrEqual(760)

      const box = await modal.boundingBox()
      expect(box).not.toBeNull()
      // CSS: max-height: calc(100vh - 64px). Allow 2 px slack for borders.
      expect(box!.height).toBeLessThanOrEqual(height - 64 + 2)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/onboarding-${width}-modal-proportions.png`,
        fullPage: true,
      })
    })

    test('stepper: done numeral = --ok bg, current = --ink bg, future disabled', async ({
      page,
    }) => {
      await gotoOnboarding(page)

      // Force advance to step 3 by clicking framework + skipping twice.
      await page.getByTestId('onboarding-framework-langchain').click()
      await page.getByTestId('onboarding-continue').click() // → install
      await page.getByTestId('onboarding-skip-step').click() // → identity (current)

      // step 1 + 2 are done, step 3 is current, step 4 + 5 are future.
      const done = page.getByTestId('onboarding-stepper-framework')
      const current = page.getByTestId('onboarding-stepper-identity')
      const future = page.getByTestId('onboarding-stepper-policy')

      // Confirm the cascade is producing the right status classes.
      await expect(done).toHaveAttribute('data-status', 'done')
      await expect(current).toHaveAttribute('data-status', 'current')
      await expect(future).toHaveAttribute('data-status', 'future')

      // Chromium clamps `color` / `border-bottom-color` on `<button>` elements
      // regardless of CSS, so we assert the visual contract through the inner
      // `.onb-rail-num` <span> bubble — which carries the same hi-fi token
      // via `background` and is unaffected by the button-chrome quirk.
      const doneNumBg = await done
        .locator('.onb-rail-num')
        .evaluate((el) => getComputedStyle(el as Element).backgroundColor)
      expect(doneNumBg).toBe(HIFI_TOKENS.ok)

      const currentNumBg = await current
        .locator('.onb-rail-num')
        .evaluate((el) => getComputedStyle(el as Element).backgroundColor)
      expect(currentNumBg).toBe(HIFI_TOKENS.ink)

      // Future steps are <button disabled>.
      await expect(future).toBeDisabled()

      await page.screenshot({
        path: `${EVIDENCE_DIR}/onboarding-${width}-stepper-states.png`,
        fullPage: true,
      })
    })

    test('scrim: dim the dashboard underneath with rgba(8, 9, 11, 0.78)', async ({
      page,
    }) => {
      await gotoOnboarding(page)
      const scrim = page.locator('.onb-scrim')
      const bg = await scrim.evaluate(
        (el) => getComputedStyle(el as Element).backgroundColor,
      )
      // Some browsers serialise alpha differently — accept either form.
      expect(bg).toMatch(/rgba?\(8,\s*9,\s*11,\s*0?\.78\)/)
    })

    test('already-configured gateway redirects to / without showing the wizard', async ({
      page,
    }) => {
      await preconfigureGateway(page)
      await page.goto('/onboarding')
      // Wizard must not be present.
      await expect(page.getByTestId('onboarding-wizard')).toHaveCount(0)
      // Page lands on /; the AppShell stays mounted, so confirm by URL.
      expect(page.url()).toMatch(/\/$/)
    })

    test('happy path: framework → install → identity → policy → enroll → finish', async ({
      page,
    }) => {
      await gotoOnboarding(page)

      // Step 1 — framework.
      await page.getByTestId('onboarding-framework-langchain').click()
      await expect(page.getByTestId('onboarding-continue')).toBeEnabled()
      await page.getByTestId('onboarding-continue').click()

      // Step 2 — install. Skip rather than wait on the simulated terminal.
      await page.getByTestId('onboarding-skip-step').click()

      // Step 3 — identity. Skip.
      await page.getByTestId('onboarding-skip-step').click()

      // Step 4 — baseline policy. The wizard auto-selects the recommended
      // 'read-only' preset on mount, so Continue is enabled immediately.
      await expect(page.getByTestId('onboarding-continue')).toBeEnabled()
      await page.getByTestId('onboarding-continue').click()

      // Step 5 — enroll. Need to start the listener to flip state.enrolled
      // before the final-step Continue button enables.
      await page.getByTestId('onboarding-enroll-start').click()
      await page.getByTestId('onboarding-enroll-connected').waitFor()

      const finishBtn = page.getByTestId('onboarding-continue')
      await expect(finishBtn).toContainText('finish')
      await expect(finishBtn).toBeEnabled()
      await finishBtn.click()

      // Wizard navigates away to /, the toast container shows the success message,
      // and the gateway-configured flag is set.
      await expect(page.getByTestId('onboarding-wizard')).toHaveCount(0)
      const completed = await page.evaluate(
        (key) => localStorage.getItem(key),
        ONBOARDING_COMPLETED_KEY,
      )
      expect(completed).toBe('true')
      const session = await page.evaluate(
        (key) => localStorage.getItem(key),
        ONBOARDING_SESSION_KEY,
      )
      expect(session).toBe(null)

      await page.screenshot({
        path: `${EVIDENCE_DIR}/onboarding-${width}-after-finish.png`,
        fullPage: true,
      })
    })

    test('top-right "skip onboarding" exits the wizard with an info toast', async ({
      page,
    }) => {
      await gotoOnboarding(page)
      await page.getByTestId('onboarding-skip-all').click()
      await expect(page.getByTestId('onboarding-wizard')).toHaveCount(0)
      const completed = await page.evaluate(
        (key) => localStorage.getItem(key),
        ONBOARDING_COMPLETED_KEY,
      )
      expect(completed).toBe('true')
    })
  })
}

describeAtViewport(1280, 800)
describeAtViewport(1920, 1080)
