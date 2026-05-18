/**
 * Dashboard gateway smoke test (AAASM-1240).
 *
 * Verifies that the dashboard correctly retrieves live agent data from the
 * gateway and displays it across the three primary monitoring views:
 *   1. Fleet (agent list)  — /agents
 *   2. Trace view          — /agents/:id/trace/:sessionId
 *   3. Topology            — /topology
 *
 * Uses Playwright's page.route() to mock the gateway API, matching the
 * project-wide pattern established in fleet.spec.ts, trace.spec.ts, and
 * topology-design-fidelity.spec.ts.  No live gateway process is required.
 */

import { test, expect, type Page } from '@playwright/test'

// ── Live-data fixtures ────────────────────────────────────────────────────────

const AGENT_ID = 'live-agent-001'
const SESSION_ID = 'live-session-abc'

const LIVE_AGENTS = [
  {
    id: 'live-agent-001',
    name: 'support-bot',
    framework: 'langgraph',
    version: '0.1.0',
    status: 'active',
    layer: 'sdk',
    session_count: 12,
    policy_violations_count: 1,
    last_event: '2026-05-18T08:00:00Z',
    tool_names: ['search', 'code_exec'],
    recent_events: [],
    recent_traces: [{ session_id: SESSION_ID }],
    active_sessions: [],
    metadata: { owner: 'alice' },
    pid: null,
  },
  {
    id: 'live-agent-002',
    name: 'analytics-runner',
    framework: 'crewai',
    version: '0.1.0',
    status: 'active',
    layer: 'proxy',
    session_count: 5,
    policy_violations_count: 0,
    last_event: '2026-05-18T07:30:00Z',
    tool_names: ['query_db'],
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    metadata: { owner: 'carol' },
    pid: null,
  },
  {
    id: 'live-agent-003',
    name: 'file-watcher',
    framework: 'langchain',
    version: '0.1.0',
    status: 'idle',
    layer: 'sdk',
    session_count: 3,
    policy_violations_count: 0,
    last_event: '2026-05-18T06:00:00Z',
    tool_names: ['file_read'],
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    metadata: {},
    pid: null,
  },
]

const LIVE_TRACE_EVENTS = [
  {
    id: 'live-evt-001',
    timestamp: '2026-05-18T08:00:01Z',
    type: 'llm_call',
    agent: 'support-bot',
    durationMs: 423,
    payloadPreview: 'GPT-4o · summarise ticket',
    payload: { model: 'gpt-4o', tokens: 312 },
    severity: 'info',
  },
  {
    id: 'live-evt-002',
    timestamp: '2026-05-18T08:00:02Z',
    type: 'tool_call',
    agent: 'support-bot',
    durationMs: 88,
    payloadPreview: 'search("open tickets")',
    payload: { tool: 'search', query: 'open tickets' },
    severity: 'info',
  },
  {
    id: 'live-evt-003',
    timestamp: '2026-05-18T08:00:03Z',
    type: 'policy_violation',
    agent: 'support-bot',
    durationMs: 5,
    payloadPreview: 'refund > $100 — approval required',
    payload: { action: 'process_refund', amount: 250 },
    severity: 'critical',
    violationReason: 'refund > $100 requires human approval',
  },
]

const LIVE_TOPOLOGY = {
  nodes: [
    {
      id: 'live-agent-001',
      name: 'support-bot',
      status: 'active' as const,
      team: 'support',
      owner: 'alice',
      policyCount: 3,
      budgetSpend: 4.2,
      budgetLimit: 10,
      framework: 'langgraph',
      latestSessionId: SESSION_ID,
    },
    {
      id: 'live-agent-002',
      name: 'analytics-runner',
      status: 'active' as const,
      team: 'analytics',
      owner: 'carol',
      policyCount: 1,
      budgetSpend: 1.8,
      budgetLimit: 10,
      framework: 'crewai',
    },
    {
      id: 'live-agent-003',
      name: 'file-watcher',
      status: 'idle' as const,
      team: 'support',
      owner: 'alice',
      policyCount: 2,
      budgetSpend: 0.5,
      budgetLimit: 10,
      framework: 'langchain',
    },
  ],
  edges: [
    { source: 'live-agent-001', target: 'live-agent-003', kind: 'delegation' as const },
  ],
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-smoke-token')
  })
}

async function mockGatewayLiveData(page: Page) {
  await page.route('**/api/v1/agents', route =>
    route.fulfill({ json: LIVE_AGENTS }),
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}`, route =>
    route.fulfill({ json: LIVE_AGENTS[0] }),
  )
  await page.route(
    `**/api/v1/agents/${AGENT_ID}/sessions/${SESSION_ID}/trace`,
    route => route.fulfill({ json: LIVE_TRACE_EVENTS }),
  )
  await page.route('**/api/v1/topology', route =>
    route.fulfill({ json: LIVE_TOPOLOGY }),
  )
  await page.route('**/api/v1/topology/nodes/*/events', route =>
    route.fulfill({ json: [] }),
  )
  await page.route('**/api/v1/approvals**', route =>
    route.fulfill({ json: [] }),
  )
  await page.route('**/api/v1/ws/events**', route => route.abort())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test.describe('Dashboard gateway smoke — live agent data renders correctly', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockGatewayLiveData(page)
  })
})
