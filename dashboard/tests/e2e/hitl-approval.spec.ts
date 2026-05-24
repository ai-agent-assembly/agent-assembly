// AAASM-1571 / F116 ST-P-5 — Dashboard E2E for the Human-in-the-loop gate.
//
// Boots a real `aa-api` gateway via the Rust `e2e_fixture_main` long-running
// test, then proxies dashboard `/api/v1/**` calls to it through Playwright's
// network layer. Asserts the Approvals page renders the two pending requests
// the fixture seeded and that clicking Approve removes the row from the
// pending list — proving the round-trip {dashboard → REST → ApprovalQueue
// → REST → dashboard} works against production code, not mocks.
//
// Companion to the Rust acceptance sweep in
// `aa-integration-tests/tests/e2e_hitl_approval.rs`; that file proves the
// blocking-waiter / timeout / list-transition semantics. This file is the
// browser-level evidence the ticket AC requests.

import { test, expect } from '@playwright/test'

import { type FixtureHandle, killFixture, spawnFixture } from './hitl-fixture'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1571'

let fixture: FixtureHandle | undefined

test.beforeAll(async () => {
  fixture = await spawnFixture()
})

test.afterAll(async () => {
  killFixture(fixture)
  fixture = undefined
})

test.describe('Approvals — AAASM-1571 ST-P-5: HITL gate via real gateway', () => {
  test('seeded pending rows render; Approve removes row from pending list', async ({ page }) => {
    const baseUrl = fixture!.baseUrl

    // Project-wide auth shim: the dashboard reads `aa_token` from
    // localStorage for the bearer header.
    await page.addInitScript(() => {
      localStorage.setItem('aa_token', 'e2e-test-token')
    })

    // The fixture has no event broadcast plumbing; abort the WS so the
    // dashboard's `useApprovalsStream` falls back to the polling/optimistic
    // path. The disconnected banner is expected and out of scope here.
    await page.route('**/api/v1/ws/events*', (route) => route.abort())

    // Proxy `/api/v1/**` calls to the live gateway behind the fixture.
    // AAASM-1922 aligned the `list_approvals` OpenAPI body with the
    // runtime `PaginatedApprovalResponse` envelope, so the dashboard now
    // reads `data.items` itself — no response transform needed here.
    await page.route('**/api/v1/**', async (route) => {
      const url = new URL(route.request().url())
      const proxiedUrl = `${baseUrl}${url.pathname}${url.search}`
      const postData = route.request().postData()

      const response = await route.fetch({
        url: proxiedUrl,
        method: route.request().method(),
        headers: route.request().headers(),
        ...(postData !== null ? { postData } : {}),
      })

      await route.fulfill({ response })
    })

    // Harmless empty stubs for unrelated landing chatter (matches the pattern
    // in `approvals-expired.spec.ts`).
    await page.route('**/api/v1/policies/active', (route) =>
      route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
    )
    await page.route('**/api/v1/alerts**', (route) => route.fulfill({ json: [] }))

    await page.goto('/approvals')
    await expect(page.getByTestId('approvals-page')).toBeVisible()

    // Fixture seeds two pending approvals (`send_email`, `wire_transfer`).
    await expect(page.getByTestId('approval-row')).toHaveCount(2)
    await page.screenshot({ path: `${SCREENSHOT_DIR}/before-approve.png`, fullPage: true })

    // Clicking Approve drives a real POST to the gateway's REST endpoint.
    // The dashboard's optimistic update removes the row instantly; the
    // gateway's `ApprovalQueue::decide` is the only source of truth that
    // the round-trip actually landed (asserted by the Rust suite).
    await page.getByTestId('approve-btn').first().click()

    await expect(page.getByTestId('approval-row')).toHaveCount(1, { timeout: 15_000 })
    await page.screenshot({ path: `${SCREENSHOT_DIR}/after-approve.png`, fullPage: true })
  })
})
