/**
 * Verification capture for AAASM-5027 — trace decision-explainer visuals.
 *
 * Renders the trace view against a fixture that exercises every derivable
 * verdict (ALLOWED / DENIED / SCRUBBED / PENDING) in both themes, opens the
 * decision explainer on the scrubbed event, and captures screenshots into
 * `dashboard/verify/AAASM-5027/` for VIEW-vs-spec review against
 * `design/v1/hi-fi/trace.jsx`.
 *
 * NARROWED is intentionally absent: no current trace-API field distinguishes a
 * narrowed call, so the deriver never emits it (the chip vocabulary supports it
 * for when the backend decision field lands — AAASM-5029).
 */

import { test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/AAASM-5027')

const AGENT_ID = 'agent-5027'
const SESSION_ID = 'session-5027'

const AGENT = {
  id: AGENT_ID,
  name: 'support-agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 2,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

// One event per derivable verdict, ordered so the scrubbed row is first
// (its explainer is opened for the drawer screenshots).
const EVENTS = [
  {
    id: 'evt-scrubbed',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'policy_violation',
    agent: 'support-agent',
    durationMs: 12,
    payloadPreview: 'process_refund | amount=250',
    payload: { action: 'process_refund', amount: 250, user_id: 4521, email: 'a@b.com' },
    severity: 'critical',
    redactedFields: ['user_id', 'email'],
    violationReason: 'PII fields redacted before tool call',
  },
  {
    id: 'evt-pending',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'policy_violation',
    agent: 'support-agent',
    durationMs: 9,
    payloadPreview: 'wire_transfer | amount=9000',
    payload: { action: 'wire_transfer', amount: 9000 },
    severity: 'warning',
    violationReason: 'transfer > $5k requires human approval',
  },
  {
    id: 'evt-denied',
    timestamp: '2026-04-23T14:23:03Z',
    type: 'credential_leak',
    agent: 'support-agent',
    durationMs: 5,
    payloadPreview: 'detected AWS_SECRET_ACCESS_KEY',
    payload: { matched_rule: 'aws-secret-access-key' },
    severity: 'warning',
  },
  {
    id: 'evt-allowed',
    timestamp: '2026-04-23T14:23:04Z',
    type: 'llm_call',
    agent: 'support-agent',
    durationMs: 834,
    payloadPreview: 'GPT-4o · lookup billing',
    payload: { model: 'gpt-4o' },
    severity: 'info',
  },
]

async function setup(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript(
    ([t]) => {
      sessionStorage.setItem('aa_token', 'verify-token')
      localStorage.setItem('aa-dashboard-theme', t)
    },
    [theme],
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}`, r => r.fulfill({ json: AGENT }))
  await page.route(
    `**/api/v1/agents/${AGENT_ID}/sessions/${SESSION_ID}/trace`,
    r => r.fulfill({ json: EVENTS }),
  )
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', r => r.abort())
}

async function gotoTrace(page: Page) {
  await page.goto('/')
  await page.evaluate(
    ([id, sid]) => window.history.pushState({}, '', `/agents/${id}/trace/${sid}`),
    [AGENT_ID, SESSION_ID],
  )
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('trace-event').first().waitFor()
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

for (const theme of ['light', 'dark'] as const) {
  test(`AAASM-5027 decision-explainer visuals — ${theme}`, async ({ page }) => {
    await setup(page, theme)
    await gotoTrace(page)

    // Timeline with verdict chips on every row.
    await page.screenshot({ path: `${EVIDENCE_DIR}/01-timeline-verdict-chips-${theme}.png`, fullPage: true })

    // Open the decision explainer on the scrubbed event.
    await page.getByTestId('trace-event').first().click()
    await page.getByTestId('decision-explainer').waitFor()
    await page.getByTestId('payload-modal').screenshot({
      path: `${EVIDENCE_DIR}/02-explainer-scrubbed-${theme}.png`,
    })
  })
}
