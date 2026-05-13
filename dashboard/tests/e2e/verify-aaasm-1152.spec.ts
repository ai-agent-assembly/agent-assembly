/**
 * Evidence-capture spec for AAASM-1152 (trace functional verification).
 *
 * Walks every trace-related acceptance-criteria bullet from AAASM-95,
 * takes a full-page screenshot at each step, and saves the Export
 * download alongside. Output lives under
 * `docs/verification/aaasm-1152/` so the artifacts are reviewable
 * in the merged PR without re-running the spec.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { traceExportSchema } from '../../src/features/trace/exportSchema'

// Playwright runs from dashboard/. Evidence lives in dashboard/docs/verification/aaasm-1152/.
const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1152')

const AGENT_ID = 'agent-aaasm-1152'
const SESSION_ID = 'session-aaasm-1152'

const AGENT = {
  id: AGENT_ID,
  name: 'support-agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 1,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search', 'process_refund'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

const TRACE_EVENTS = [
  {
    id: 'evt-llm',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'llm_call',
    agent: 'support-agent',
    durationMs: 834,
    payloadPreview: 'GPT-4o · "查詢用戶 #4521 的帳單"',
    payload: { model: 'gpt-4o', prompt: 'lookup billing for user 4521' },
    severity: 'info',
  },
  {
    id: 'evt-tool',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'tool_call',
    agent: 'support-agent',
    durationMs: 45,
    payloadPreview: 'query_db | SELECT * FROM billing...',
    payload: { table: 'billing', user_id: 4521 },
  },
  {
    id: 'evt-violation',
    timestamp: '2026-04-23T14:23:16Z',
    type: 'policy_violation',
    agent: 'support-agent',
    durationMs: 12,
    payloadPreview: 'process_refund | amount=250',
    payload: { action: 'process_refund', amount: 250, user_id: 4521 },
    severity: 'critical',
    redactedFields: ['user_id'],
    violationReason: 'refund > $100 requires human approval',
  },
  {
    id: 'evt-leak',
    timestamp: '2026-04-23T14:23:30Z',
    type: 'credential_leak',
    agent: 'support-agent',
    durationMs: 5,
    payloadPreview: 'detected AWS_SECRET_ACCESS_KEY in outbound payload',
    payload: { matched_rule: 'aws-secret-access-key' },
    severity: 'warning',
  },
]

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'verify-token'))
}

async function mockApi(page: Page) {
  await page.route(`**/api/v1/agents/${AGENT_ID}`, r => r.fulfill({ json: AGENT }))
  await page.route(
    `**/api/v1/agents/${AGENT_ID}/sessions/${SESSION_ID}/trace`,
    r => r.fulfill({ json: TRACE_EVENTS }),
  )
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', r => r.abort())
}

async function gotoTrace(page: Page) {
  // Vite `base: './'` workaround — see tests/e2e/trace.spec.ts.
  await page.goto('/')
  await page.evaluate(
    ([id, sid]) => window.history.pushState({}, '', `/agents/${id}/trace/${sid}`),
    [AGENT_ID, SESSION_ID],
  )
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('trace-event').first().waitFor()
}

test.describe('AAASM-1152 — Trace AC evidence capture', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('AC1 + AC4: timeline renders all events with timestamp/icon/agent/duration/preview', async ({ page }) => {
    await gotoTrace(page)
    const rows = page.getByTestId('trace-event')
    await expect(rows).toHaveCount(TRACE_EVENTS.length)

    // Verify row anatomy on the first row.
    const first = rows.first()
    await expect(first.locator('.trace-event__time')).toBeVisible()
    await expect(first.locator('.trace-event__icon')).toBeVisible()
    await expect(first.locator('.trace-event__agent')).toContainText('support-agent')
    await expect(first.locator('.trace-event__preview')).toBeVisible()
    await expect(first.locator('.trace-event__duration')).toContainText('ms')

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-timeline-full.png`, fullPage: true })
  })

  test('AC2: policy violation row uses red background + violation reason tooltip', async ({ page }) => {
    await gotoTrace(page)
    const violationRow = page.locator('[data-event-type="policy_violation"]')
    await expect(violationRow).toHaveAttribute('data-severity', 'critical')

    await violationRow.locator('.trace-event__icon').hover()
    const tooltip = page.getByRole('tooltip')
    await expect(tooltip).toHaveText('refund > $100 requires human approval')
    await page.screenshot({ path: `${EVIDENCE_DIR}/02-policy-violation-tooltip.png`, fullPage: true })
  })

  test('AC3: credential leak row uses warn (orange) tone via data-event-type', async ({ page }) => {
    await gotoTrace(page)
    const leakRow = page.locator('[data-event-type="credential_leak"]')
    await expect(leakRow).toBeVisible()
    // Severity stays as warning so the filter can still find/hide it;
    // CSS rule on data-event-type forces warn-bg regardless of severity.
    await expect(leakRow).toHaveAttribute('data-severity', 'warning')
    await leakRow.scrollIntoViewIfNeeded()
    await page.screenshot({ path: `${EVIDENCE_DIR}/03-credential-leak.png`, fullPage: true })
  })

  test('AC5: clicking an event opens PayloadModal with redacted field sentinel', async ({ page }) => {
    await gotoTrace(page)
    await page.locator('[data-event-type="policy_violation"]').click()
    const modal = page.getByTestId('payload-modal')
    await expect(modal).toBeVisible()

    const redacted = page.getByTestId('redacted-field')
    await expect(redacted.first()).toContainText('"<redacted: user_id>"')
    // Original value must NOT leak.
    await expect(page.getByTestId('payload-modal-json')).not.toContainText('4521')

    await page.screenshot({ path: `${EVIDENCE_DIR}/05-payload-modal-redacted.png`, fullPage: true })
  })

  test('AC6: filter bar hides matching severity rows', async ({ page }) => {
    await gotoTrace(page)
    await page.screenshot({ path: `${EVIDENCE_DIR}/06a-filter-before.png`, fullPage: true })

    // Uncheck info + neutral to focus on violations.
    await page.getByTestId('trace-filter-info').click()
    await page.getByTestId('trace-filter-neutral').click()

    // Remaining rows: critical + warning.
    const remaining = page.getByTestId('trace-event')
    await expect(remaining).toHaveCount(2)
    await page.screenshot({ path: `${EVIDENCE_DIR}/06b-filter-after.png`, fullPage: true })
  })

  test('AC7: Export button downloads schema-valid trace JSON', async ({ page }) => {
    await gotoTrace(page)
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('export-trace').click(),
    ])

    const expectedName = `trace-${AGENT_ID}-${SESSION_ID}.json`
    expect(download.suggestedFilename()).toBe(expectedName)

    // Persist the export inside the evidence dir.
    const path = await download.path()
    const content = await readFile(path, 'utf-8')
    await writeFile(`${EVIDENCE_DIR}/07-export-trace.json`, content)

    const parsed = JSON.parse(content)
    const result = traceExportSchema.safeParse(parsed)
    expect(result.success).toBe(true)
    expect(parsed.events).toHaveLength(TRACE_EVENTS.length)

    await page.screenshot({ path: `${EVIDENCE_DIR}/07-export-toolbar.png`, fullPage: true })
  })
})
