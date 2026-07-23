// Verification harness for AAASM-5023 — policy-editor DSL/Rego preview view
// + per-rule dirty indicators. Walks the editor overlay in both light and
// dark themes, exercises:
//   - the DSL tab rendering dslFor(draft) as a read-only Rego preview,
//   - editing a rule so its per-rule dirty-dot appears,
// capturing a screenshot at each state into verify/AAASM-5023/ as visual
// evidence against design/v1/hi-fi/policy-editor.jsx.

import { test, expect, type Page } from '@playwright/test'

const OUT = 'verify/AAASM-5023'

const ACTIVE_POLICY = {
  name: 'research-bot-04',
  version: '1.2.0',
  rule_count: 1,
  active: true,
  policy_yaml: 'metadata:\n  name: research-bot-04\nrules: []\n',
}

async function seedSession(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript(
    ([t]) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem('aa-dashboard-theme', t)
    },
    [theme],
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (route) => {
    if (route.request().method() === 'GET') {
      // AAASM-4892: /policies returns a paginated { items, total } object.
      return route.fulfill({ json: { items: [ACTIVE_POLICY], total: 1 } })
    }
    return route.fallback()
  })
}

for (const theme of ['light', 'dark'] as const) {
  test(`AAASM-5023 — DSL preview + dirty-dot (${theme})`, async ({ page }) => {
    await seedSession(page, theme)
    await mockBackend(page)

    // Open the editor overlay off the policy list.
    await page.goto('/policies')
    await page.getByTestId('policy-row').first().click()
    await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()

    // Form view — clean, no per-rule dirty-dot yet.
    await expect(page.getByTestId('editor-rule-0-dirty-dot')).toBeHidden()
    await page.screenshot({ path: `${OUT}/${theme}-01-form-clean.png`, fullPage: true })

    // DSL tab — read-only Rego preview derived from the draft.
    await page.getByTestId('editor-view-dsl').click()
    const preview = page.getByTestId('editor-dsl-preview')
    await expect(preview).toBeVisible()
    await expect(preview).toContainText('policy "pol-research-bot-04" {')
    await expect(preview).toContainText('rule R1 {')
    await page.screenshot({ path: `${OUT}/${theme}-02-dsl-preview.png`, fullPage: true })

    // Back to the form, edit a rule → its dirty-dot appears.
    await page.getByTestId('editor-view-form').click()
    await page.getByTestId('editor-rule-0-verb-write').click()
    await expect(page.getByTestId('editor-rule-0-dirty-dot')).toBeVisible()
    await expect(page.getByTestId('editor-dirty-chip')).toBeVisible()
    await page.screenshot({ path: `${OUT}/${theme}-03-rule-dirty.png`, fullPage: true })

    // The edit is reflected live in the DSL preview too.
    await page.getByTestId('editor-view-dsl').click()
    await expect(page.getByTestId('editor-dsl-preview')).toContainText(
      'verb in ["read", "write"]',
    )
    await page.screenshot({ path: `${OUT}/${theme}-04-dsl-after-edit.png`, fullPage: true })
  })
}
