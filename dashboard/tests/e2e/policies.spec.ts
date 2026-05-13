// E2E acceptance for AAASM-1281 (Dashboard PR 8: Policy list + Policy Editor
// overlay). Walks the golden path described in AAASM-1372 (ST-6):
//
//   1. Visit /policies → list renders.
//   2. Click a row → editor overlay opens; URL stays at /policies.
//   3. Change a field → "draft · unsaved" dirty chip appears.
//   4. Press Esc → ConfirmDialog appears → Cancel keeps overlay → re-Esc →
//      Discard closes overlay.
//   5. Reopen → Save → "Policy saved" toast appears → overlay closes.
//
// Each major state is captured via page.screenshot() into
// tests/__screenshots__/AAASM-1281/ so reviewers + the parent Story
// (AAASM-1281) have visual evidence attached to the closing comment.

import { test, expect, type Page } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1281'

const ACTIVE_POLICY = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
  policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
}

const PROPOSED_POLICY = {
  name: 'experimental',
  version: '0.9.0',
  rule_count: 2,
  active: false,
  policy_yaml: 'metadata:\n  name: experimental\nrules: []\n',
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockBackend(page: Page) {
  // Block the WebSocket the AppShell tries to open.
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  // Stub the approvals fetch the AppShell / landing page may issue.
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  // Return 404 for the "active policy" probe — we don't need it for these
  // flows and the dashboard tolerates the miss.
  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  // GET → list of two policies; POST → echo back the created policy.
  await page.route('**/api/v1/policies', (route) => {
    const method = route.request().method()
    if (method === 'GET') {
      return route.fulfill({ json: [ACTIVE_POLICY, PROPOSED_POLICY] })
    }
    if (method === 'POST') {
      return route.fulfill({
        status: 201,
        json: { ...ACTIVE_POLICY, version: '1.0.1', active: false },
      })
    }
    return route.fallback()
  })
}

test.describe('Policies — AAASM-1281 acceptance (golden path)', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockBackend(page)
  })

  test('list → row click → overlay → dirty edit → Esc discard → reopen → Save → success toast', async ({
    page,
  }) => {
    // ── 1. List renders ──────────────────────────────────────────────
    await page.goto('/policies')
    await expect(page.getByTestId('policies-page')).toBeVisible()
    const rows = page.getByTestId('policy-row')
    await expect(rows).toHaveCount(2)
    await expect(rows.first()).toContainText('default-policy')
    await page.screenshot({ path: `${SCREENSHOT_DIR}/01-list.png`, fullPage: true })

    // ── 2. Row click opens overlay; URL stays /policies ──────────────
    await rows.first().click()
    await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
    await expect(page).toHaveURL(/\/policies$/)
    await expect(page.getByTestId('editor-meta-chips')).toContainText('default-policy')
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/02-overlay-open.png`,
      fullPage: true,
    })

    // ── 3. Edit a field → dirty chip appears ─────────────────────────
    await expect(page.getByTestId('editor-dirty-chip')).toBeHidden()
    const scopeInput = page.getByTestId('editor-scope-input')
    await scopeInput.fill('team:platform')
    await expect(page.getByTestId('editor-dirty-chip')).toBeVisible()
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/03-dirty.png`,
      fullPage: true,
    })

    // ── 4. Esc → ConfirmDialog appears → Cancel keeps overlay ────────
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'Discard unsaved changes?' }),
    ).toBeVisible()
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/04-discard-prompt.png`,
      fullPage: true,
    })
    await page.getByTestId('confirm-dialog-cancel').click()
    await expect(page.getByTestId('confirm-dialog')).toBeHidden()
    await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()

    // ── 4b. Re-Esc + Discard closes the overlay ──────────────────────
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('confirm-dialog')).toBeVisible()
    await page.getByTestId('confirm-dialog-confirm').click()
    await expect(page.getByTestId('policy-editor-overlay')).toBeHidden()
    await expect(page.getByTestId('confirm-dialog')).toBeHidden()

    // ── 5. Reopen → Save → success toast → overlay closes ────────────
    await page.getByTestId('policy-row').first().click()
    await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
    await expect(page.getByTestId('editor-save-btn')).toBeEnabled()
    await page.getByTestId('editor-save-btn').click()
    await expect(page.getByText('Policy saved')).toBeVisible({ timeout: 5000 })
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/05-save-toast.png`,
      fullPage: true,
    })
    await expect(page.getByTestId('policy-editor-overlay')).toBeHidden()
  })
})

test.describe('Policies — AAASM-1281 acceptance (filter tabs)', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockBackend(page)
  })

  test('filter tabs split the list into Active and Proposed buckets', async ({ page }) => {
    await page.goto('/policies')
    const tabAll = page.getByTestId('policies-tab-all')
    const tabActive = page.getByTestId('policies-tab-active')
    const tabProposed = page.getByTestId('policies-tab-proposed')

    await expect(tabAll).toContainText('2')
    await expect(tabActive).toContainText('1')
    await expect(tabProposed).toContainText('1')

    await tabActive.click()
    await expect(page.getByTestId('policy-row')).toHaveCount(1)
    await expect(page.getByTestId('policy-row').first()).toContainText('default-policy')

    await tabProposed.click()
    await expect(page.getByTestId('policy-row')).toHaveCount(1)
    await expect(page.getByTestId('policy-row').first()).toContainText('experimental')
  })
})
