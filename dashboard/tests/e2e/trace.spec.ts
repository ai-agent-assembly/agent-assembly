import { test, expect, type Page } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { traceExportSchema } from '../../src/features/trace/exportSchema'

// ── Fixtures ───────────────────────────────────────────────────────────────────

const AGENT_ID = 'agent-e2e-001'
const SESSION_ID = 'session-e2e-abc'

const AGENT = {
  id: AGENT_ID,
  name: 'e2e-support-agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 1,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

const TRACE_EVENTS = [
  {
    id: 'evt-critical',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'policy_violation',
    agent: 'e2e-support-agent',
    durationMs: 12,
    payloadPreview: 'refund > $100',
    payload: { action: 'process_refund', amount: 250, user_id: 4521 },
    severity: 'critical',
    redactedFields: ['user_id'],
    violationReason: 'refund > $100 requires human approval',
  },
  {
    id: 'evt-warning',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'credential_leak',
    agent: 'e2e-support-agent',
    durationMs: 5,
    payloadPreview: 'detected AWS_SECRET_ACCESS_KEY',
    payload: { source: 'tool_call' },
    severity: 'warning',
  },
  {
    id: 'evt-info',
    timestamp: '2026-04-23T14:23:03Z',
    type: 'llm_call',
    agent: 'e2e-support-agent',
    durationMs: 834,
    payloadPreview: 'GPT-4o · query billing',
    payload: { model: 'gpt-4o' },
    severity: 'info',
  },
  {
    id: 'evt-neutral',
    timestamp: '2026-04-23T14:23:04Z',
    type: 'tool_call',
    agent: 'e2e-support-agent',
    durationMs: 50,
    payloadPreview: 'query_db',
    payload: { table: 'billing' },
  },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockTraceApi(page: Page) {
  await page.route(`**/api/v1/agents/${AGENT_ID}`, route =>
    route.fulfill({ json: AGENT }),
  )
  await page.route(
    `**/api/v1/agents/${AGENT_ID}/sessions/${SESSION_ID}/trace`,
    route => route.fulfill({ json: TRACE_EVENTS }),
  )
  // Shell-level chatter we don't care about for this spec.
  await page.route('**/api/v1/approvals**', route => route.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', route => route.abort())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('TraceViewPage E2E', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockTraceApi(page)
  })

  test('renders ≥ 1 trace event, toggles filter, opens modal, exports JSON', async ({ page }) => {
    // Vite is configured with `base: './'` so deep routes 404 on asset
    // loads when navigating directly. Land on `/` first so assets resolve
    // from the root, then SPA-navigate to the trace route.
    await page.goto('/')
    await page.evaluate(
      ([id, sessionId]) => window.history.pushState({}, '', `/agents/${id}/trace/${sessionId}`),
      [AGENT_ID, SESSION_ID],
    )
    await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))

    // 1) At least one event renders.
    const rows = page.getByTestId('trace-event')
    await expect(rows.first()).toBeVisible()
    await expect(rows).toHaveCount(TRACE_EVENTS.length)

    // 2) Toggle Info filter off — the info-severity row should disappear.
    await page.getByTestId('trace-filter-info').click()
    const remaining = await rows.count()
    expect(remaining).toBeLessThan(TRACE_EVENTS.length)
    // Re-enable Info to keep the rest of the test using the full set.
    await page.getByTestId('trace-filter-info').click()

    // 3) Open the payload modal on the redacted row and confirm the sentinel.
    await page.getByTestId('trace-event').first().click()
    await expect(page.getByTestId('payload-modal')).toBeVisible()
    const redacted = page.getByTestId('redacted-field')
    await expect(redacted.first()).toBeVisible()
    await expect(redacted.first()).toContainText('"<redacted: user_id>"')
    // Original value (4521) must not leak into the rendered modal.
    await expect(page.getByTestId('payload-modal-json')).not.toContainText('4521')
    await page.getByTestId('payload-modal-close').click()

    // 4) Click Export and verify the downloaded file parses against the schema.
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByTestId('export-trace').click(),
    ])
    expect(download.suggestedFilename()).toBe(`trace-${AGENT_ID}-${SESSION_ID}.json`)

    const path = await download.path()
    const content = await readFile(path, 'utf-8')
    const parsed = JSON.parse(content)
    const result = traceExportSchema.safeParse(parsed)
    expect(result.success).toBe(true)
    expect(parsed.events).toHaveLength(TRACE_EVENTS.length)
    expect(parsed.agentId).toBe(AGENT_ID)
    expect(parsed.sessionId).toBe(SESSION_ID)
  })
})
