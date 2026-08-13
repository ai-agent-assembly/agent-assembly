// Story-level Playwright e2e for the Identity Access Log tab.
//
// Originally written for AAASM-1398, when the tab was driven by a ten-event
// in-memory seed: it walked filtering, custom time ranges, pagination and the
// per-row `/audit/event/<id>` cross-link across rows that were entirely
// fabricated (named identities, invented source IPs, failed logins whose
// timestamps re-based themselves on every page load).
//
// AAASM-5111 removed that seed. No endpoint reports identity-attributed access
// events — `GET /api/v1/logs` is the per-agent governance log and carries no
// identity, source address or outcome — so the tab now reports `not-supported`
// and renders nothing. The walk below is rewritten against that: the tab is
// still reachable and still explains itself, but there is no row, no address
// and no verdict anywhere on it.

import { test, expect, type Page } from '@playwright/test'

/** Anything IPv4-shaped, so a freshly invented address fails this too. */
const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

/** Identities that only ever existed in the deleted seed. */
const SEED_IDENTITIES = [
  'alice@agent-assembly.dev',
  'bob@agent-assembly.dev',
  'carol@agent-assembly.dev',
  'gateway-ci',
  'observability-exporter',
  'retired-runner',
]

/**
 * Seed the JWT the way the app actually reads it.
 *
 * Two pre-existing breakages in this file are fixed alongside the rewrite,
 * because neither is reachable past the first assertion:
 *
 *  - the token lives in `sessionStorage`, not `localStorage` (AAASM-4322), so
 *    the previous seeding was inert;
 *  - it has to be written before any module executes, since `openapi-fetch`
 *    captures `globalThis.fetch` at module load.
 */
async function injectToken(page: Page) {
  await page.addInitScript(() => {
    sessionStorage.setItem('aa_token', 'e2e-test-token')
  })
}

/**
 * Reach a route without a deep-link request.
 *
 * `vite preview` answers `/identity?...` with a 404 rather than the SPA shell,
 * so every deep `page.goto` in this file previously landed on a blank page.
 * The repo's other review specs navigate client-side for the same reason.
 */
async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function stubShellProbes(page: Page) {
  // Permissive fallback first (least specific); the specific fixtures below win,
  // since Playwright matches most-recently-added first. Without it the shell's
  // other probes reach for a backend that is not running and the page never
  // settles — the third pre-existing reason nothing in this file could pass.
  await page.route('**/api/**', (route) => route.fulfill({ json: {} }))
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/alerts/ws**', (route) => route.abort())
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (route) =>
    route.request().method() === 'GET' ? route.fulfill({ json: [] }) : route.fallback(),
  )
}

test.describe('Identity & Access — Access Log tab (AAASM-5111)', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await stubShellProbes(page)
  })

  test('the tab is still reachable and states why it has nothing to show', async ({ page }) => {
    await navigate(page, '/identity?tab=access-log')

    await expect(page.getByTestId('identity-page')).toBeVisible()
    await expect(page.getByTestId('iam-tab-access-log')).toHaveAttribute('aria-selected', 'true')
    await expect(page.getByTestId('iam-panel-access-log')).toBeVisible()

    const state = page.getByTestId('access-log-unsupported')
    await expect(state).toBeVisible()
    await expect(state).toHaveAttribute('data-truth-state', 'not-supported')
    await expect(state).toContainText('AAASM-5176')
    await expect(state).toContainText('AAASM-5177')
  })

  test('no event row, table or pagination renders', async ({ page }) => {
    await navigate(page, '/identity?tab=access-log')
    await expect(page.getByTestId('access-log-unsupported')).toBeVisible()

    await expect(page.getByTestId('access-log-table')).toHaveCount(0)
    await expect(page.getByTestId('access-log-page-indicator')).toHaveCount(0)
    await expect(page.locator('[data-testid^="access-log-row-"]')).toHaveCount(0)
  })

  test('no seed identity and no address-shaped text survives on the tab', async ({ page }) => {
    await navigate(page, '/identity?tab=access-log')
    const panel = page.getByTestId('iam-panel-access-log')
    await expect(panel).toBeVisible()

    for (const identity of SEED_IDENTITIES) {
      await expect(panel).not.toContainText(identity)
    }
    expect(await panel.innerText()).not.toMatch(IPV4)
  })

  test('the filter bar is present but inert, so no empty result reads as "no match"', async ({
    page,
  }) => {
    await navigate(page, '/identity?tab=access-log')
    const bar = page.getByTestId('access-log-filter-bar')
    await expect(bar).toBeVisible()
    await expect(bar).toHaveAttribute('data-disabled', 'true')

    await expect(page.getByTestId('access-log-filter-identity')).toBeDisabled()
    await expect(page.getByTestId('access-log-filter-event-type')).toBeDisabled()
    await expect(page.getByTestId('access-log-filter-time-range')).toBeDisabled()
  })

  test('the working governance audit log is offered instead', async ({ page }) => {
    await navigate(page, '/identity?tab=access-log')
    await expect(page.getByTestId('access-log-audit-link')).toHaveAttribute('href', '/audit')

    // The header cross-link (AAASM-1160 AC #11) is unaffected.
    const header = page.getByTestId('iam-audit-link')
    await expect(header).toBeVisible()
    await expect(header).toHaveAttribute('href', '/audit')
  })
})
