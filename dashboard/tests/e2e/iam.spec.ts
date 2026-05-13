// E2E acceptance for AAASM-1087 (custom-role locked state + upsell) plus
// the upstream flows the AC requires the spec to walk: invite a member
// (AAASM-1084) and generate-and-reveal an API key (AAASM-1085).
//
// The dashboard reads from an in-memory IAM store (no /v1/iam/* gateway
// endpoints exist yet) so this spec doesn't need backend mocking — it
// just intercepts the gateway probes the AppShell issues on boot.
//
// Screenshots land in tests/__screenshots__/AAASM-1087/ for the PR body.

import { test, expect, type Page } from '@playwright/test'

const SCREENSHOT_DIR = 'tests/__screenshots__/AAASM-1087'

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

test.describe('Identity & Access — AAASM-1087 acceptance', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await stubShellProbes(page)
  })

  test('Members tab — invite dialog accepts a new member and the row appears', async ({ page }) => {
    await page.goto('/identity')
    await expect(page.getByTestId('identity-page')).toBeVisible()
    await expect(page.getByTestId('member-row-me')).toBeVisible()

    await page.getByTestId('invite-member-button').click()
    await page.getByTestId('invite-email-input').fill('e2e-new-hire@agent-assembly.dev')
    await page.screenshot({ path: `${SCREENSHOT_DIR}/01-invite-dialog.png`, fullPage: true })
    await page.getByTestId('invite-submit').click()

    await expect(page.getByTestId('invite-member-dialog')).toBeHidden()
    await expect(
      page.locator('[data-testid="toast"]', { hasText: 'e2e-new-hire@agent-assembly.dev' }),
    ).toBeVisible()
    await expect(
      page.getByTestId('member-list').getByText('e2e-new-hire@agent-assembly.dev'),
    ).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/02-invite-success.png`, fullPage: true })
  })

  test('Service Identities tab — generate key reveals secret once and pre-copy close prompts', async ({
    page,
  }) => {
    await page.goto('/identity?tab=services')
    await expect(page.getByTestId('iam-panel-services')).toBeVisible()
    await expect(page.getByTestId('api-keys-shown-once-banner')).toBeVisible()

    await page.getByTestId('generate-key-button').click()
    await page.getByTestId('generate-key-label-input').fill('e2e-runner')
    await page.getByTestId('generate-key-scope-read:members').check()
    await page.getByTestId('generate-key-scope-read:policies').check()
    await page.getByTestId('generate-key-submit').click()

    const reveal = page.getByTestId('reveal-once-modal')
    await expect(reveal).toBeVisible()
    const secret = await page.getByTestId('reveal-once-secret').inputValue()
    expect(secret).toMatch(/^aa_live_/)
    await page.screenshot({ path: `${SCREENSHOT_DIR}/03-reveal-once.png`, fullPage: true })

    // Close without copying → destroy-unseen confirm appears.
    await page.getByTestId('reveal-once-close').click()
    await expect(page.getByTestId('confirm-destroy-unseen-key')).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/04-destroy-confirm.png`, fullPage: true })
    await page.getByTestId('destroy-unseen-discard').click()
    await expect(page.getByTestId('reveal-once-modal')).toBeHidden()
    await expect(page.getByTestId('confirm-destroy-unseen-key')).toBeHidden()
  })

  test('Roles & Permissions tab — upsell CTA fires analytics event and links to docs', async ({
    page,
  }) => {
    const consoleEvents: string[] = []
    page.on('console', (msg) => {
      if (msg.type() === 'info') consoleEvents.push(msg.text())
    })

    await page.goto('/identity?tab=roles')
    await expect(page.getByTestId('iam-panel-roles')).toBeVisible()
    await expect(page.getByTestId('iam-custom-roles')).toBeVisible()
    await expect(page.getByTestId('custom-roles-locked')).toBeVisible()
    await expect(page.getByTestId('builtin-role-admin')).toBeVisible()
    await expect(page.getByTestId('builtin-role-agent.readonly')).toBeVisible()
    await page.screenshot({ path: `${SCREENSHOT_DIR}/05-locked-custom-roles.png`, fullPage: true })

    // The CTA opens a new tab — intercept before navigation rather than
    // following the docs link in CI.
    const cta = page.getByTestId('upgrade-cta')
    await expect(cta).toHaveAttribute('href', 'https://docs.agent-assembly.dev/cloud/custom-roles')
    await expect(cta).toHaveAttribute('target', '_blank')

    // Stop the click from navigating; still fires the onClick handler.
    await page.evaluate(() => {
      const el = document.querySelector('[data-testid="upgrade-cta"]') as HTMLAnchorElement
      el.addEventListener('click', (e) => e.preventDefault(), { capture: true })
    })

    await cta.click()
    await expect.poll(() => consoleEvents.some((m) => m.includes('iam.custom_roles.upsell_clicked'))).toBe(true)
  })
})
