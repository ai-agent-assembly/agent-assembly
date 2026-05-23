// E2E acceptance for AAASM-1918 (Enable-live-enforcement dialog).
//
// Walks the happy path of the Enable-live-enforcement flow:
//
//   1. /policies renders with one observe-mode policy seeded.
//   2. SandboxSummaryCard banner is visible (gated on observe-mode
//      policy existence, not on counts).
//   3. Click "Enable live enforcement →" → ConfirmDialog appears with
//      the single-policy prompt.
//   4. Click "Enable live enforcement" → POST /api/v1/policies fires
//      with a YAML body that carries enforcement_mode: enforce →
//      success toast appears → dialog closes.
//
// Screenshots land in tests/__screenshots__/AAASM-1918/.

import { test, expect, type Page } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1918'

const OBSERVE_POLICY = {
  name: 'sandbox-policy',
  version: '1.0.0',
  rule_count: 3,
  active: true,
  policy_yaml:
    'metadata:\n  name: sandbox-policy\nenforcement_mode: observe\nrules: []\n',
}

const SANDBOX_SUMMARY_RESPONSE = {
  counts: {
    would_be_denies: 4,
    would_be_redactions: 0,
    would_be_pending_approvals: 0,
  },
  top_rule: { id: 'block-secrets', count: 3 },
  window_secs: 86_400,
  generated_at: '2026-05-23T00:00:00Z',
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

test.describe('AAASM-1918 — Enable live enforcement happy path', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await page.route('**/api/v1/ws/events**', (route) => route.abort())
    await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
    await page.route('**/api/v1/policies/active', (route) =>
      route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
    )
    await page.route('**/api/v1/audit/sandbox-summary**', (route) =>
      route.fulfill({ json: SANDBOX_SUMMARY_RESPONSE }),
    )
  })

  test('banner → button → confirm → POST with enforce YAML → success toast', async ({ page }) => {
    let createBody: { policy_yaml?: string } | null = null

    await page.route('**/api/v1/policies', (route) => {
      const method = route.request().method()
      if (method === 'GET') {
        return route.fulfill({ json: [OBSERVE_POLICY] })
      }
      if (method === 'POST') {
        createBody = route.request().postDataJSON() as { policy_yaml?: string }
        return route.fulfill({
          status: 201,
          json: { ...OBSERVE_POLICY, version: '1.0.1', active: true },
        })
      }
      return route.fallback()
    })

    // ── 1. /policies renders with the SandboxSummaryCard banner ─────────
    await page.goto('/policies')
    await expect(page.getByTestId('policies-page')).toBeVisible()
    const banner = page.getByTestId('policies-sandbox-banner')
    await expect(banner).toBeVisible()
    await expect(banner).toContainText('4') // would_be_denies
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/01-banner-visible.png`,
      fullPage: true,
    })

    // ── 2. Click "Enable live enforcement →" opens the dialog ──────────
    await banner.getByRole('button', { name: /Enable live enforcement/i }).click()
    const prompt = page.getByTestId('sandbox-enable-live-single')
    await expect(prompt).toBeVisible()
    await expect(prompt).toContainText('sandbox-policy')
    await page.screenshot({
      path: `${SCREENSHOT_DIR}/02-dialog-open.png`,
      fullPage: true,
    })

    // ── 3. Confirm → POST fires with enforce YAML → success toast ──────
    await page
      .getByRole('button', { name: 'Enable live enforcement', exact: true })
      .click()

    await expect(page.getByText(/Live enforcement enabled for sandbox-policy/i)).toBeVisible({
      timeout: 5000,
    })
    expect(createBody?.policy_yaml).toBeDefined()
    expect(createBody!.policy_yaml).toContain('enforcement_mode: enforce')
    expect(createBody!.policy_yaml).not.toContain('enforcement_mode: observe')

    await page.screenshot({
      path: `${SCREENSHOT_DIR}/03-success-toast.png`,
      fullPage: true,
    })
  })
})
