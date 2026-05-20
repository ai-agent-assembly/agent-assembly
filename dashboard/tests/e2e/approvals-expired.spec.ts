// E2E acceptance for AAASM-1478. Verifies the per-row auto-expire countdown
// and the collapsible Expired section on ApprovalsPage:
//
//   1. The pending row renders the countdown at the high-severity tier (red)
//      when remaining time is under 60s.
//   2. When the timer hits zero, the row vanishes from the pending table.
//   3. The Expired section appears with count 1 and, once expanded, shows
//      the row in its read-only (no Approve/Reject) variant.
//
// Backend endpoints are stubbed via page.route(); the WebSocket is aborted
// (the disconnected banner is expected). Screenshots land in
// tests/__screenshots__/AAASM-1478/.

import { test, expect, type Page, type Route } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1478'

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function stubBackend(page: Page, approvals: unknown[]) {
  // Abort the events WebSocket — the disconnected banner is expected and
  // out of scope for this spec; client-side countdown is the trigger here.
  await page.route('**/api/v1/ws/events*', (route: Route) => route.abort())

  await page.route('**/api/v1/approvals*', (route: Route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({ json: approvals })
    }
    return route.fallback()
  })

  // Other landing chatter — harmless empty stubs.
  await page.route('**/api/v1/policies/active', (route: Route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/alerts**', (route: Route) =>
    route.fulfill({ json: [] }),
  )
}

test.describe('Approvals — AAASM-1478 expired countdown + section', () => {
  test('row hits zero locally and is moved to the Expired section', async ({ page }) => {
    await injectToken(page)

    const SHORT_TIMEOUT_SECS = 3
    const now = Date.now()
    const approval = {
      id: 'req-aaasm-1478',
      agent_id: 'agent-test',
      action: 'send_email',
      reason: 'external-comms',
      status: 'pending',
      created_at: new Date(now).toISOString(),
      expires_at: new Date(now + SHORT_TIMEOUT_SECS * 1000).toISOString(),
      routing_status: null,
      team_id: null,
    }

    await stubBackend(page, [approval])
    await page.goto('/approvals')

    // (1) The pending row is visible and renders the countdown.
    await expect(page.getByTestId('approval-row')).toBeVisible()
    const countdown = page.getByTestId('approval-countdown')
    await expect(countdown).toBeVisible()
    await expect(countdown).toHaveAttribute('data-tier', 'high')
    await page.screenshot({ path: `${SCREENSHOT_DIR}/01-pending-with-countdown.png`, fullPage: true })

    // (2) Wait for the timer to fire. The row disappears from pending.
    await expect(page.getByTestId('approval-row')).toHaveCount(0, { timeout: 10_000 })

    // (3) The Expired section appears with the count badge at 1.
    const badge = page.getByTestId('expired-count-badge')
    await expect(badge).toBeVisible()
    await expect(badge).toHaveText('1')
    await page.screenshot({ path: `${SCREENSHOT_DIR}/02-expired-collapsed.png`, fullPage: true })

    // (4) Expand the section and verify the row is inside, read-only.
    await page.getByTestId('expired-toggle').click()
    await expect(page.getByTestId('expired-approvals-table')).toBeVisible()
    await expect(page.getByTestId('expired-row')).toHaveCount(1)
    // No Approve / Reject controls survive in the expired view.
    await expect(page.getByTestId('approve-btn')).toHaveCount(0)
    await expect(page.getByTestId('reject-btn')).toHaveCount(0)
    await page.screenshot({ path: `${SCREENSHOT_DIR}/03-expired-expanded.png`, fullPage: true })
  })
})
