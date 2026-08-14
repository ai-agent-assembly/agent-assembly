// Evidence capture for AAASM-5059 + AAASM-5060 (Bucket-C design fixes).
//
//   AAASM-5059 — opening an existing policy must load its REAL rules / status /
//   scope from the policy_yaml, not a fabricated gmail/read/allow stub, and a
//   proposed policy must show the "⚠ draft policy" callout + a `proposed`
//   status chip.
//
//   AAASM-5060 — switching a rule to the `approval` action must NOT raise the
//   old "Approval action requires an approver configuration" error (the editor
//   shows, and serializeDraft persists, a default approver).
//
// Screenshots land in dashboard/verify/qa-policy-editor/ in both themes.

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
const OUT = 'verify/qa-policy-editor'

// A proposed, multi-rule policy in the editor's own `spec.rules` schema, so the
// editor can recover its rules (gmail read/write allow, s3 write approval,
// shell exec deny) rather than inventing a default.
const PROPOSED_POLICY = {
  name: 'research-bot',
  version: '0.3.0',
  rule_count: 3,
  active: false,
  policy_yaml: [
    'apiVersion: agent-assembly/v1',
    'kind: Policy',
    'metadata:',
    '  name: research-bot',
    '  scope: team:research',
    '  version: 0.3.0',
    'spec:',
    '  rules:',
    '    - id: R1-gmail-allow',
    '      match:',
    '        actions:',
    '          - gmail:read',
    '          - gmail:write',
    '      effect: allow',
    '      audit: true',
    '    - id: R2-s3-approval',
    '      match:',
    '        actions:',
    '          - s3:write',
    '      effect: require_approval',
    '      approval:',
    '        timeout_seconds: 1800',
    '        approvers:',
    '          - security-oncall',
    '      audit: true',
    '    - id: R3-shell-deny',
    '      match:',
    '        actions:',
    '          - shell:exec',
    '      effect: block',
    '      audit: true',
    '',
  ].join('\n'),
}

async function seed(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      // Post-AAASM-4322 the auth token lives in sessionStorage; the legacy
      // localStorage key is ignored.
      sessionStorage.setItem('aa_token', 'e2e-5059-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/audit/sandbox-summary**', (r) =>
    r.fulfill({ json: { counts: { would_be_denies: 0, would_be_redactions: 0, would_be_pending_approvals: 0 }, top_rule: null, window_secs: 86400, generated_at: '2026-05-23T00:00:00Z' } }),
  )
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  // GET /policies returns a paginated { items, total } envelope (AAASM-4892).
  await page.route('**/api/v1/policies', (r) =>
    r.request().method() === 'GET'
      ? r.fulfill({ json: { items: [PROPOSED_POLICY], total: 1, page: 1, per_page: 50 } })
      : r.fallback(),
  )
}

for (const theme of ['light', 'dark'] as const) {
  test(`AAASM-5059/5060 — real load + approval validity (${theme})`, async ({ page }) => {
    await seed(page, theme)
    await mockBackend(page)

    await page.goto('/policies')
    await expect(page.getByTestId('policies-page')).toBeVisible()
    await page.getByTestId('policy-row').first().click()
    await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()

    // AAASM-5059: real status + draft callout + real scope + real rules.
    await expect(page.getByTestId('editor-status-chip')).toHaveText('proposed')
    await expect(page.getByTestId('editor-draft-callout')).toBeVisible()
    await expect(page.getByTestId('editor-scope-input')).toHaveValue('team:research')
    await expect(page.getByTestId('editor-rule-0-resource')).toHaveValue('gmail')
    await expect(page.getByTestId('editor-rule-1-resource')).toHaveValue('s3')
    await expect(page.getByTestId('editor-rule-2-resource')).toHaveValue('shell')
    await page.screenshot({ path: `${OUT}/edit-real-${theme}.png`, fullPage: true })

    // AAASM-5060: the loaded approval rule (R2) raises no error, and switching
    // R1 to `approval` likewise stays clean — the default approver satisfies
    // validation.
    await expect(page.getByTestId('editor-validation-error-count')).toHaveText('0 errors')
    await page
      .getByTestId('editor-rule-0')
      .getByTestId('editor-action-approval')
      .click()
    await expect(page.getByTestId('editor-validation-error-count')).toHaveText('0 errors')
    await expect(page.getByTestId('editor-save-btn')).toBeEnabled()
    await page.screenshot({ path: `${OUT}/approval-valid-${theme}.png`, fullPage: true })
  })
}
