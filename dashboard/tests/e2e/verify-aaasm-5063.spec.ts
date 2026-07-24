// AAASM-5063 / 5064 / 5065 — design-QA visual-polish evidence capture.
//
// Renders the real app (only the network is stubbed) for the Audit Log,
// Capability, and Overview pages in BOTH themes and writes full-page artifacts
// to `verify/qa-visual/{audit,capability,overview}-{light,dark}.png`. Not part
// of any CI lane — local visual gate only. Run with:
//
//   pnpm exec playwright test --config playwright.4532.config.ts

import { test, expect, type Page } from '@playwright/test'
import { CAPABILITY_MATRIX_FIXTURE } from '../../src/features/capability/fixtures'

// Cold vite-preview start + full-page renders can exceed the 30s default.
test.setTimeout(90_000)

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// Rich audit seed: one PolicyViolation (violation-row wash), one REDACT verdict
// (purple scrub chip), plus allow/pending across event types.
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
    agent_id: 'sales-outreach',
    session_id: 'sess-11c2',
    event_type: 'NetworkCall',
    payload: JSON.stringify({
      decision: 'REDACT',
      protocol: 'https',
      host: 'api.stripe.com',
      status_code: 200,
      latency_ms: 210,
    }),
  },
  {
    seq: 1046,
    timestamp: '2026-05-11T14:01:41Z',
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
  {
    seq: 1041,
    timestamp: '2026-05-11T14:00:32Z',
    agent_id: 'finance-bot',
    session_id: 'sess-6d44',
    event_type: 'ApprovalEvent',
    payload: JSON.stringify({
      decision: 'PENDING',
      approval_id: 'apr-77',
      approved: false,
      approver_id: 'ops@acme',
      wait_time_ms: 360000,
    }),
  },
]

const AGENTS = [
  {
    id: 'research-bot-04',
    name: 'research-bot-04',
    framework: 'langchain',
    version: '0.1.0',
    status: 'active',
    layer: 'sdk',
    session_count: 3,
    policy_violations_count: 4,
    last_event: '2026-06-01T10:00:00Z',
    tool_names: ['search'],
    recent_events: [],
  },
  {
    id: 'support-triage',
    name: 'support-triage',
    framework: 'crewai',
    version: '0.2.0',
    status: 'active',
    layer: 'proxy',
    session_count: 2,
    policy_violations_count: 0,
    last_event: '2026-06-01T10:01:00Z',
    tool_names: ['zendesk'],
    recent_events: [],
  },
  {
    id: 'sales-outreach',
    name: 'sales-outreach',
    framework: 'llamaindex',
    version: '0.3.0',
    status: 'shadow',
    layer: 'sdk',
    session_count: 1,
    policy_violations_count: 0,
    last_event: '2026-06-01T10:02:00Z',
    tool_names: ['gmail'],
    recent_events: [],
  },
]

const BASE_TS = Date.UTC(2026, 5, 1, 0, 0, 0)
const ENFORCEMENT_TIMELINE = {
  window: '24h',
  bucketSecs: 3600,
  buckets: Array.from({ length: 24 }, (_, i) => ({
    ts: BASE_TS + i * 3_600_000,
    allow: 12 + ((i * 7) % 22),
    narrow: 3 + ((i * 3) % 11),
    deny: (i * 2) % 6,
    scrub: 2 + ((i * 5) % 9),
  })),
}

const ALERTS = {
  items: [
    {
      id: 'al-1',
      ruleName: 'research-bot-04 over-permissioned',
      severity: 'CRITICAL',
      status: 'FIRING',
      agentId: 'research-bot-04',
      firstFiredAt: '2026-06-01T14:02:08Z',
    },
    {
      id: 'al-2',
      ruleName: 'pg.users narrowed',
      severity: 'HIGH',
      status: 'FIRING',
      agentId: 'support-triage',
      firstFiredAt: '2026-06-01T14:01:54Z',
    },
    {
      id: 'al-3',
      ruleName: 'gmail/send scrubbed',
      severity: 'MEDIUM',
      status: 'FIRING',
      agentId: 'sales-outreach',
      firstFiredAt: '2026-06-01T14:01:41Z',
    },
  ],
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      // Token has lived in sessionStorage since AAASM-4322; set localStorage too
      // to be robust across shell versions. Theme lives in localStorage.
      sessionStorage.setItem('aa_token', 'qa-visual-token')
      localStorage.setItem('aa_token', 'qa-visual-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) =>
    r.fulfill({ json: [{ id: 'apr-77' }, { id: 'apr-78' }] }),
  )
  // AAASM-4892: /logs returns a paginated { items, total } envelope.
  await page.route('**/api/v1/logs**', (r) =>
    r.fulfill({ json: { items: LOGS, total: LOGS.length } }),
  )
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (r) =>
    r.request().method() === 'GET' ? r.fulfill({ json: [] }) : r.fallback(),
  )
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) =>
    r.fulfill({ json: { items: AGENTS, total: AGENTS.length } }),
  )
  await page.route('**/api/v1/alerts**', (r) => r.fulfill({ json: ALERTS }))
  await page.route('**/api/v1/overview/enforcement-timeline**', (r) =>
    r.fulfill({ json: ENFORCEMENT_TIMELINE }),
  )
  // The production build's capabilityClient hits the live matrix endpoint;
  // serve the same fixture the mock client uses so the grid populates.
  await page.route('**/api/v1/capability/matrix', (r) =>
    r.fulfill({ json: CAPABILITY_MATRIX_FIXTURE }),
  )
}

async function navTo(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((p) => {
    window.history.pushState({}, '', p)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

test.describe('AAASM-5063/5064/5065 — design-QA visual polish', () => {
  for (const theme of THEMES) {
    test(`audit log — ${theme}`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navTo(page, '/audit')
      await expect(page.getByTestId('audit-table')).toBeVisible()
      await page.getByTestId('audit-row-1048').click() // expand payload (dark terminal)
      await page.screenshot({ path: `verify/qa-visual/audit-${theme}.png`, fullPage: true })
    })

    test(`capability — ${theme}`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navTo(page, '/capability')
      await expect(page.getByTestId('capability-page')).toBeVisible()
      await expect(page.getByRole('grid', { name: 'capability matrix' })).toBeVisible()
      await page.screenshot({ path: `verify/qa-visual/capability-${theme}.png`, fullPage: true })
    })

    test(`overview — ${theme}`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navTo(page, '/overview')
      await expect(page.getByTestId('overview-page')).toBeVisible()
      await expect(page.getByTestId('overview-snapshot')).toBeVisible()
      await page.screenshot({ path: `verify/qa-visual/overview-${theme}.png`, fullPage: true })
    })
  }
})
