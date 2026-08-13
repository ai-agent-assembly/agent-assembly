// AAASM-5022 — verification capture for the Audit Log type-filter row,
// CSV export, compliance-report action, and restored trace metadata row.
//
// Seeds `sessionStorage.aa_token` (per AAASM-4322) and stubs `/api/v1/logs`
// with the paginated `{ items, total }` shape (per AAASM-4892). Captures
// light + dark, exercises the type-filter button row, an expanded row (trace
// row), and both header exports. Local visual gate only — not a CI lane.
//
// AAASM-5117: retargeted onto the real schema. The fixture below used to carry
// the hi-fi mock's invented `event_type`s (`LLMCall` / `ToolCall`) and a string
// `decision`, and clicked `audit-type-btn-ToolCall` — a filter keyed to a type
// the backend never emits. The capture is unchanged in intent; it now drives
// the `aa_core::audit::AuditEventType` variants the gateway actually writes and
// the integer `assembly.common.v1.Decision` discriminant, so the screenshots
// show what an operator really sees.

import { test, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const
const OUT = 'verify/AAASM-5022'

const LOGS = [
  {
    seq: 1048,
    timestamp: '2026-05-11T14:02:11Z',
    agent_id: '9f2c1a7b4d8e0f3a6b5c4d3e2f1a0b9c',
    session_id: 'a41f9c22',
    event_type: 'PolicyViolation',
    payload: JSON.stringify({
      action_type: 2,
      decision: 2,
      trace_id: 'trc-7f3a91',
      reason: 'External recipient requires explicit approval',
      policy_rule: 'deny-external-mail',
    }),
  },
  {
    seq: 1047,
    timestamp: '2026-05-11T14:01:58Z',
    agent_id: '9f2c1a7b4d8e0f3a6b5c4d3e2f1a0b9c',
    session_id: 'a41f9c22',
    event_type: 'ApprovalRequested',
    payload: JSON.stringify({
      action_type: 1,
      decision: 3,
      trace_id: 'trc-7f3a90',
      reason: 'Spend above the per-call ceiling',
      policy_rule: 'approve-high-cost-llm',
    }),
  },
  {
    seq: 1044,
    timestamp: '2026-05-11T14:01:09Z',
    agent_id: '00112233445566778899aabbccddeeff',
    session_id: '6d44be01',
    event_type: 'ToolCallIntercepted',
    payload: JSON.stringify({
      action_type: 'TOOL_CALL',
      decision: 1,
      source: 'sdk',
      trace_id: 'trc-6d4401',
      detail: {
        kind: 'tool_call',
        tool_name: 'zendesk_search',
        tool_source: 'mcp',
        succeeded: true,
      },
    }),
  },
]

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'audit-e2e-token')
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
  await page.route('**/api/v1/logs**', (r) =>
    r.fulfill({ json: { items: LOGS, page: 1, per_page: 50, total: LOGS.length } }),
  )
}

async function navToAudit(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/audit')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await page.getByTestId('audit-table').waitFor()
  await page.getByTestId('audit-row-1048').waitFor()
}

test.beforeAll(() => mkdirSync(OUT, { recursive: true }))

test.describe('AAASM-5022 — Audit Log filters + exports verification', () => {
  for (const theme of THEMES) {
    test(`captures the audit-log surface in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToAudit(page)

      // Full page — header exports + type-filter button row visible.
      await page.screenshot({ path: `${OUT}/audit-${theme}-01-overview.png`, fullPage: true })

      // Exercise the type-filter button row: narrow to the Tool Calls family.
      await page.getByTestId('audit-type-btn-tool').click()
      await page.getByTestId('audit-row-1044').waitFor()
      await page.screenshot({
        path: `${OUT}/audit-${theme}-02-type-filter-toolcall.png`,
        fullPage: true,
      })

      // Reset and expand a row to show the restored trace metadata row.
      await page.getByTestId('audit-type-btn-all').click()
      await page.getByTestId('audit-row-1048').click()
      await page.getByTestId('audit-trace-1048').waitFor()
      await page.screenshot({
        path: `${OUT}/audit-${theme}-03-expanded-trace.png`,
        fullPage: true,
      })
    })
  }

  test('triggers the CSV export and compliance report', async ({ page }) => {
    await seed(page, 'light')
    await mockBackend(page)
    await navToAudit(page)

    const [csvDl] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('audit-export-csv').click(),
    ])
    test.info().annotations.push({ type: 'csv-export', description: csvDl.suggestedFilename() })

    const [reportDl] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('audit-compliance-report').click(),
    ])
    test.info().annotations.push({
      type: 'compliance-report',
      description: reportDl.suggestedFilename(),
    })

    await page.screenshot({ path: `${OUT}/audit-light-04-exports-fired.png`, fullPage: true })
  })
})
