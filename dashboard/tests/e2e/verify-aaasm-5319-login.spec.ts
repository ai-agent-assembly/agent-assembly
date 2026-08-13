/**
 * End-to-end coverage of the native-auth login surface (AAASM-5319, exercising
 * the UI shipped by AAASM-5307).
 *
 * The login page reads `GET /api/v1/auth/methods` on mount and renders honestly
 * from that signal (ADR 0031 §Q5), never a guess:
 *   - `["api_key","password"]` → the two-tab email/password UI, with the API-key
 *     path reachable and NO social login (Google/GitHub) and NO "or continue
 *     with email" divider (ADR 0031 D4);
 *   - `["api_key"]` → the API-key-only surface with a "needs Postgres" note and
 *     no password form the backend cannot serve.
 *
 * This spec drives, all APIs mocked via `page.route` (FE-only, no backend):
 *   1. methods-gating — password available → two-tab UI, no social/divider;
 *   2. methods-gating — api_key only → no password form, API-key path + note;
 *   3. the sign-in ↔ sign-up tab switch (sign-up has email + password, no
 *      workspace-name field — OSS is single-workspace);
 *   4. the sign-in happy path — `POST /api/v1/auth/login` → access token, then
 *      navigate into the app with the token committed to sessionStorage.
 *
 * Harness conventions copied from the existing review/verify specs
 * (e.g. review-aaasm-5104): a permissive API fallback route is registered
 * first, specific fixtures after (Playwright matches most-recently-added
 * first); the token is NOT pre-seeded here (these flows are the
 * unauthenticated login surface), and routing happens at the network layer
 * because openapi-fetch captures globalThis.fetch at module load. No console
 * errors / pageerrors across any flow.
 */
import { test, expect, type Page } from '@playwright/test'

type AuthMethod = 'api_key' | 'password'

interface Harness {
  errors: string[]
}

const TOKEN_KEY = 'aa_token'

/** A JWT-shaped access token so `parseScopesFromJwt` has three dot-segments to split. */
const ACCESS_TOKEN =
  'eyJhbGciOiJIUzI1NiJ9.eyJzY29wZXMiOltdfQ.e2e-5319-signature'

async function bootstrap(page: Page, methods: AuthMethod[]): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades / unmocked resources are the fixture's doing, not the app's.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  // The honest-degradation signal the login page renders from (ADR 0031 §Q5).
  await page.route('**/api/v1/auth/methods**', (r) => r.fulfill({ json: { methods } }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

test.describe('AAASM-5319 — native-auth login surface', () => {
  test('methods-gating: password available renders the two-tab UI and no social/divider', async ({
    page,
  }) => {
    const harness = await bootstrap(page, ['api_key', 'password'])
    await page.goto('/login')

    // The two-tab email/password UI is the password-enabled shape.
    const tablist = page.getByRole('tablist', { name: 'Sign in or sign up' })
    await expect(tablist).toBeVisible()
    await expect(page.getByRole('tab', { name: 'Sign in' })).toBeVisible()
    await expect(page.getByRole('tab', { name: 'Sign up' })).toBeVisible()
    await expect(page.getByLabel('Work email')).toBeVisible()
    await expect(page.getByLabel('Password', { exact: true })).toBeVisible()

    // ADR 0031 D4: no social login and no "or continue with email" divider.
    await expect(page.getByRole('button', { name: /google/i })).toHaveCount(0)
    await expect(page.getByRole('button', { name: /github/i })).toHaveCount(0)
    await expect(page.getByText(/continue with email/i)).toHaveCount(0)

    // The API-key path is still reachable (but not the default surface).
    await expect(
      page.getByRole('button', { name: 'Sign in with an API key instead' }),
    ).toBeVisible()

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })

  test('methods-gating: api_key only renders the API-key path with a needs-Postgres note', async ({
    page,
  }) => {
    const harness = await bootstrap(page, ['api_key'])
    await page.goto('/login')

    // No two-tab password UI at all when the deployment advertises only api_key.
    await expect(page.getByRole('tablist', { name: 'Sign in or sign up' })).toHaveCount(0)
    await expect(page.getByRole('tab', { name: 'Sign up' })).toHaveCount(0)

    // The honest-degradation note explains why account login is unavailable.
    await expect(page.getByText(/needs a Postgres-backed deployment/i)).toBeVisible()

    // The API-key form (the OSS path that always survives) is present.
    await expect(page.getByLabel('API key')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign in with API key' })).toBeVisible()

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })

  test('the sign-in ↔ sign-up tab switch: sign-up has email + password, no workspace field', async ({
    page,
  }) => {
    const harness = await bootstrap(page, ['api_key', 'password'])
    await page.goto('/login')

    const signIn = page.getByRole('tab', { name: 'Sign in' })
    const signUp = page.getByRole('tab', { name: 'Sign up' })

    // Sign-in is the default selected tab and offers the "Forgot?" link.
    await expect(signIn).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByRole('link', { name: 'Forgot?' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible()

    // Switch to sign-up.
    await signUp.click()
    await expect(signUp).toHaveAttribute('aria-selected', 'true')
    await expect(signIn).toHaveAttribute('aria-selected', 'false')
    await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible()

    // Sign-up collects exactly email + password.
    await expect(page.getByLabel('Work email')).toBeVisible()
    await expect(page.getByLabel('Password', { exact: true })).toBeVisible()

    // OSS is single-workspace: there is NO workspace/tenant/organisation field.
    await expect(page.getByLabel(/workspace|tenant|organi[sz]ation|company name/i)).toHaveCount(0)
    await expect(page.getByPlaceholder(/workspace|tenant|organi[sz]ation/i)).toHaveCount(0)

    // Switch back to sign-in restores the "Forgot?" affordance.
    await signIn.click()
    await expect(signIn).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByRole('link', { name: 'Forgot?' })).toBeVisible()

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })

  test('sign-in happy path: valid credentials commit a token and navigate into the app', async ({
    page,
  }) => {
    const harness = await bootstrap(page, ['api_key', 'password'])

    // `POST /api/v1/auth/login` → the access-token envelope (ADR 0031 §5). The
    // refresh token would ride an HttpOnly cookie the FE never reads.
    await page.route('**/api/v1/auth/login**', (r) =>
      r.fulfill({ json: { access_token: ACCESS_TOKEN, expires_in: 900 } }),
    )
    // Landing on the protected app after auth pulls the overview surface; keep
    // those calls quiet so the flow doesn't error post-navigation.
    await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
    await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
    await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: [], total: 0 } }))

    await page.goto('/login')

    await page.getByLabel('Work email').fill('operator@example.com')
    await page.getByLabel('Password', { exact: true }).fill('correct-horse-battery')
    await page.getByRole('button', { name: 'Sign in', exact: true }).click()

    // Success navigates off /login. `/` redirects to /overview (App.tsx).
    await page.waitForURL((url) => !url.pathname.endsWith('/login'))
    await expect(page).not.toHaveURL(/\/login$/)

    // The app signals success by committing the access token to sessionStorage
    // via the tokenStorage tier (key `aa_token`, AAASM-4322).
    const stored = await page.evaluate((key) => sessionStorage.getItem(key), TOKEN_KEY)
    expect(stored).toBe(ACCESS_TOKEN)

    // The login card is gone — we are inside the authenticated shell.
    await expect(page.getByRole('tablist', { name: 'Sign in or sign up' })).toHaveCount(0)

    expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
  })
})
