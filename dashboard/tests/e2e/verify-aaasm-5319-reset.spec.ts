/**
 * End-to-end coverage of the enumeration-safe password-reset flow (AAASM-5319,
 * exercising the UI shipped by AAASM-5307), reachable from the login page's
 * "Forgot?" link (ADR 0031 §Q4).
 *
 * Two forms on one `/forgot-password` route:
 *   1. Request — enter an email → `POST /api/v1/auth/password/reset`. The
 *      response is enumeration-safe by contract (`202` regardless of whether the
 *      email matches an account), so the UI always shows the SAME neutral "if
 *      that email matches an account…" message and never signals existence.
 *   2. Confirm — enter the reset token + a new password →
 *      `POST /api/v1/auth/password/reset/confirm` → the "password has been
 *      reset" confirmation.
 *
 * Both reset endpoints use a raw `fetch` (they are not in the merged OpenAPI
 * spec yet), so — like the openapi-fetch calls — they must be routed at the
 * network layer via `page.route`. All APIs mocked, FE-only, no backend. Harness
 * conventions copied from the existing verify specs; no console errors /
 * pageerrors across the flow.
 */
import { test, expect, type Page } from '@playwright/test'

const NEUTRAL_RESET_MESSAGE = /if that email matches an account/i

interface Harness {
  errors: string[]
  resetRequests: Array<Record<string, unknown>>
  confirmRequests: Array<Record<string, unknown>>
}

async function bootstrap(page: Page): Promise<Harness> {
  const errors: string[] = []
  const resetRequests: Array<Record<string, unknown>> = []
  const confirmRequests: Array<Record<string, unknown>> = []

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // Permissive fallback first; specific fixtures registered afterwards win.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))

  // Register the more-specific `/confirm` route AFTER the base reset route so it
  // wins for the confirm path (most-recently-added match).
  await page.route('**/api/v1/auth/password/reset', (r) => {
    try {
      resetRequests.push(JSON.parse(r.request().postData() ?? '{}'))
    } catch {
      resetRequests.push({})
    }
    // Enumeration-safe: 202 no matter what email was submitted.
    return r.fulfill({ status: 202, json: {} })
  })
  await page.route('**/api/v1/auth/password/reset/confirm', (r) => {
    try {
      confirmRequests.push(JSON.parse(r.request().postData() ?? '{}'))
    } catch {
      confirmRequests.push({})
    }
    return r.fulfill({ status: 200, json: {} })
  })

  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors, resetRequests, confirmRequests }
}

test.describe('AAASM-5319 — enumeration-safe password reset', () => {
  test('request form always shows the neutral message; confirm form accepts token + new password', async ({
    page,
  }) => {
    const harness = await bootstrap(page)
    await page.goto('/forgot-password')

    // --- Step 1: request a reset link. The outcome is enumeration-safe. ---
    await page.getByLabel('Work email').fill('someone@example.com')
    await page.getByRole('button', { name: 'Send reset link' }).click()

    // The neutral status is shown regardless of account existence, and it does
    // NOT disclose whether the email matched (no "sent"/"not found" branch).
    const notice = page.getByRole('status')
    await expect(notice).toBeVisible()
    await expect(notice).toHaveText(NEUTRAL_RESET_MESSAGE)
    expect(harness.resetRequests).toEqual([{ email: 'someone@example.com' }])

    // --- Step 2: move to the confirm form via "Enter it here". ---
    await page.getByRole('button', { name: 'Enter it here' }).click()

    // The confirm form takes a reset token + a new password.
    const tokenField = page.getByLabel('Reset token')
    const newPassword = page.getByLabel('New password')
    await expect(tokenField).toBeVisible()
    await expect(newPassword).toBeVisible()

    await tokenField.fill('reset-token-abc123')
    await newPassword.fill('brand-new-passphrase')
    await page.getByRole('button', { name: 'Reset password' }).click()

    // A successful confirm surfaces the done state with a sign-in link.
    await expect(page.getByRole('status')).toHaveText(/your password has been reset/i)
    await expect(page.getByRole('link', { name: 'Sign in', exact: true })).toBeVisible()
    expect(harness.confirmRequests).toEqual([
      { token: 'reset-token-abc123', new_password: 'brand-new-passphrase' },
    ])

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })

  test('a non-matching email yields the identical neutral message (enumeration-safe)', async ({
    page,
  }) => {
    const harness = await bootstrap(page)
    await page.goto('/forgot-password')

    // A different (presumed non-existent) email must produce the SAME outcome —
    // the UI never branches on account existence.
    await page.getByLabel('Work email').fill('nobody@no-such-domain.invalid')
    await page.getByRole('button', { name: 'Send reset link' }).click()

    const notice = page.getByRole('status')
    await expect(notice).toBeVisible()
    await expect(notice).toHaveText(NEUTRAL_RESET_MESSAGE)
    // Nothing on screen distinguishes a hit from a miss.
    await expect(page.getByText(/no account|not found|does not exist|unknown email/i)).toHaveCount(0)

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })

  test('the confirm form prefills the token from an emailed ?token= link', async ({ page }) => {
    const harness = await bootstrap(page)
    // Following the emailed link lands directly on the confirm form (ADR 0031 §Q4).
    await page.goto('/forgot-password?token=link-token-xyz')

    const tokenField = page.getByLabel('Reset token')
    await expect(tokenField).toBeVisible()
    await expect(tokenField).toHaveValue('link-token-xyz')

    await page.getByLabel('New password').fill('another-strong-passphrase')
    await page.getByRole('button', { name: 'Reset password' }).click()

    await expect(page.getByRole('status')).toHaveText(/your password has been reset/i)
    expect(harness.confirmRequests).toEqual([
      { token: 'link-token-xyz', new_password: 'another-strong-passphrase' },
    ])

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })
})
