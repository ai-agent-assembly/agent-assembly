// Story-level Playwright e2e for AAASM-1398 — Filterable Access Log tab.
//
// Drives the real `/identity?tab=access-log` page in Chromium and walks the
// AC: panel renders → filter narrows rows → custom time range narrows
// further → each row carries a stable `/audit/event/<id>` cross-link →
// the existing header cross-link (AAASM-1160 partial AC #11) is intact.
//
// Click-through to /audit/event/<id> is intentionally NOT exercised. The
// /audit route is still a ComingSoon page (`/audit/event/:id` doesn't
// route to a real page until the Audit Log Story lands next sprint), so
// the cross-link contract is verified via href assertions only.

import { test, expect, type Page } from '@playwright/test'

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function stubShellProbes(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (route) =>
    route.request().method() === 'GET' ? route.fulfill({ json: [] }) : route.fallback(),
  )
}

test.describe('Identity & Access — Access Log tab (AAASM-1398)', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await stubShellProbes(page)
  })

  test('Access Log tab renders the filterable panel with seeded rows', async ({
    page,
  }) => {
    await page.goto('/identity?tab=access-log')

    await expect(page.getByTestId('identity-page')).toBeVisible()
    await expect(page.getByTestId('iam-tab-access-log')).toHaveAttribute(
      'aria-selected',
      'true',
    )
    await expect(page.getByTestId('iam-panel-access-log')).toBeVisible()
    await expect(page.getByTestId('access-log-filter-bar')).toBeVisible()
    await expect(page.getByTestId('access-log-table')).toBeVisible()

    // The default seed has 10 events; all sit on page 1.
    const rows = page.locator('[data-testid^="access-log-row-evt-"]')
    await expect(rows).toHaveCount(10)
    await expect(page.getByTestId('access-log-page-indicator')).toHaveText(
      'Page 1 of 1',
    )
  })

  test('Event-type filter narrows rows to that type only', async ({ page }) => {
    await page.goto('/identity?tab=access-log')
    await expect(page.getByTestId('access-log-row-evt-1')).toBeVisible()

    await page
      .getByTestId('access-log-filter-event-type')
      .selectOption('key_rotate')

    // Seed has exactly two key_rotate events: evt-3 and evt-9.
    const rows = page.locator('[data-testid^="access-log-row-evt-"]')
    await expect(rows).toHaveCount(2)
    await expect(page.getByTestId('access-log-row-evt-3')).toBeVisible()
    await expect(page.getByTestId('access-log-row-evt-9')).toBeVisible()
    await expect(page.getByTestId('access-log-row-evt-1')).toHaveCount(0)
  })

  test('Custom time range reveals from/to date inputs and narrows rows', async ({
    page,
  }) => {
    await page.goto('/identity?tab=access-log')
    await expect(page.getByTestId('access-log-row-evt-1')).toBeVisible()

    await page
      .getByTestId('access-log-filter-time-range')
      .selectOption('custom')

    await expect(page.getByTestId('access-log-filter-custom-from')).toBeVisible()
    await expect(page.getByTestId('access-log-filter-custom-to')).toBeVisible()

    // Set the from to today and the to to today — should drop most rows.
    const today = new Date().toISOString().slice(0, 10)
    await page.getByTestId('access-log-filter-custom-from').fill(today)
    await page.getByTestId('access-log-filter-custom-to').fill(today)

    // evt-1 (-1h) typically falls on "today"; older events drop.
    // We assert visible row count is at most a few (down from 10).
    const rows = page.locator('[data-testid^="access-log-row-evt-"]')
    await expect.poll(async () => await rows.count(), { timeout: 5_000 }).toBeLessThan(10)
  })

  test('Each row exposes a stable /audit/event/<id> cross-link', async ({
    page,
  }) => {
    await page.goto('/identity?tab=access-log')
    const link = page.getByTestId('access-log-row-link-evt-1')
    await expect(link).toBeVisible()
    await expect(link).toHaveAttribute('href', '/audit/event/evt-1')

    // Sanity-check a second row to prove the link template is per-row, not
    // hard-coded.
    await expect(page.getByTestId('access-log-row-link-evt-3')).toHaveAttribute(
      'href',
      '/audit/event/evt-3',
    )
  })

  test('Header "View full audit log" link is still present (AAASM-1160 AC #11)', async ({
    page,
  }) => {
    await page.goto('/identity?tab=access-log')
    const header = page.getByTestId('iam-audit-link')
    await expect(header).toBeVisible()
    await expect(header).toHaveAttribute('href', '/audit')
  })
})
