// AAASM-3510 — light/dark screenshot check for the new Audit Log page (/audit).
//
// Stubs `/api/v1/logs` with a deterministic seed and captures the rendered
// table in both themes so a token-regression (light-on-light text, broken
// surface re-theme) is visible. Mirrors the navigation + seeding approach of
// `theme-visual.spec.ts`. Not part of any CI lane — local visual gate only.

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const LOGS = [
  {
    seq: 1048,
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    event_type: 'PolicyViolation',
    payload: JSON.stringify({
      decision: 'DENY',
      blocked_action: 'gmail/send → ext@vendor.com',
      reason: 'External recipient requires explicit approval',
    }),
  },
  {
    seq: 1047,
    timestamp: '2026-05-11T14:01:58Z',
    agent_id: 'research-bot-04',
    session_id: 'sess-9a4f',
    event_type: 'LLMCall',
    payload: JSON.stringify({
      decision: 'ALLOW',
      model: 'claude-3-5-sonnet',
      prompt_tokens: 2840,
      completion_tokens: 412,
      latency_ms: 1840,
    }),
  },
  {
    seq: 1044,
    timestamp: '2026-05-11T14:01:09Z',
    agent_id: 'support-triage',
    session_id: 'sess-6d44',
    event_type: 'ToolCall',
    payload: JSON.stringify({
      decision: 'ALLOW',
      tool_name: 'zendesk_search',
      tool_source: 'mcp',
      latency_ms: 142,
      succeeded: true,
    }),
  },
]

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      localStorage.setItem('aa_token', 'audit-e2e-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: LOGS }))
}

async function navToAudit(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/audit')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('audit-table')).toBeVisible()
  await expect(page.getByTestId('audit-row-1048')).toBeVisible()
}

test.describe('AAASM-3510 — Audit Log page theming', () => {
  for (const theme of THEMES) {
    test(`renders the audit table cleanly in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToAudit(page)

      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(
        theme,
      )
      await page.screenshot({ path: `test-results/audit-log-${theme}.png`, fullPage: true })
    })
  }
})
