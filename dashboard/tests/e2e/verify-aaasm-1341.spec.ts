/**
 * Evidence-capture spec for AAASM-1341 (topology functional verification).
 *
 * Walks every topology-related acceptance-criteria bullet from AAASM-95
 * (the S22 parent Story) plus the cross-cutting "View trace" pivot wired
 * in AAASM-1340. Takes a full-page screenshot at each step and lands
 * artifacts under `docs/verification/aaasm-1341/` so they are reviewable
 * in the merged PR without re-running the spec.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

// Playwright runs from dashboard/.
const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1341')

// ── Fixture: a small graph that exercises every AC bullet at once ───────────
//
// - 4 nodes across 2 teams (support, analytics) → 2 clusters
// - Statuses: active / idle / error → AC2 status colour check
// - Budget ratios: 0.10 (small), 0.55 (medium), 0.92 (large→warn) → AC2 size
//   encoding + AC4 team budget thresholds
// - One node has `latestSessionId` set → AC-cross-cut View-trace pivot
// - 2 edges → AC1 link rendering

const NODES = [
  {
    id: 'agent-support-1',
    name: 'support-bot',
    framework: 'langgraph',
    owner: 'alice',
    team: 'support',
    status: 'active' as const,
    policyCount: 3,
    budgetSpend: 9.2,
    budgetLimit: 10,
    latestSessionId: 'sess-aaasm-1341',
  },
  {
    id: 'agent-support-2',
    name: 'support-tool',
    framework: 'langchain',
    owner: 'alice',
    team: 'support',
    status: 'idle' as const,
    policyCount: 2,
    budgetSpend: 1.0,
    budgetLimit: 10,
  },
  {
    id: 'agent-analytics-1',
    name: 'analyst',
    framework: 'crewai',
    owner: 'carol',
    team: 'analytics',
    status: 'error' as const,
    policyCount: 1,
    budgetSpend: 5.5,
    budgetLimit: 10,
  },
  {
    id: 'agent-analytics-2',
    name: 'reporter',
    framework: 'crewai',
    owner: 'carol',
    team: 'analytics',
    status: 'active' as const,
    policyCount: 1,
    budgetSpend: 0.5,
    budgetLimit: 10,
  },
]

const EDGES = [
  { source: 'agent-support-1', target: 'agent-support-2', kind: 'delegation' as const },
  { source: 'agent-analytics-1', target: 'agent-analytics-2', kind: 'call' as const },
]

const TOPOLOGY = { nodes: NODES, edges: EDGES }

const RECENT_EVENTS = [
  {
    id: 'evt-1',
    timestamp: '2026-05-13T10:00:00Z',
    type: 'tool_call',
    message: 'query_db users',
  },
  {
    id: 'evt-2',
    timestamp: '2026-05-13T10:01:00Z',
    type: 'policy_violation',
    message: 'refund > $100',
  },
]

const AGENT = {
  id: 'agent-support-1',
  name: 'support-bot',
  framework: 'langgraph',
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
    id: 'evt-llm',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'llm_call',
    agent: 'support-bot',
    durationMs: 834,
    payloadPreview: 'GPT-4o lookup',
    payload: { model: 'gpt-4o' },
    severity: 'info',
  },
  {
    id: 'evt-violation',
    timestamp: '2026-04-23T14:23:16Z',
    type: 'policy_violation',
    agent: 'support-bot',
    durationMs: 12,
    payloadPreview: 'process_refund | amount=250',
    payload: { action: 'process_refund', amount: 250 },
    severity: 'critical',
    violationReason: 'refund > $100 requires human approval',
  },
]

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'verify-token'))
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/topology', r => r.fulfill({ json: TOPOLOGY }))
  await page.route('**/api/v1/topology/nodes/*/events', r =>
    r.fulfill({ json: RECENT_EVENTS }),
  )
  await page.route(`**/api/v1/agents/${AGENT.id}`, r => r.fulfill({ json: AGENT }))
  await page.route(
    `**/api/v1/agents/${AGENT.id}/sessions/sess-aaasm-1341/trace`,
    r => r.fulfill({ json: TRACE_EVENTS }),
  )
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', r => r.abort())
}

async function gotoTopology(page: Page) {
  // Vite `base: './'` workaround — see tests/e2e/trace.spec.ts.
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/topology'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('topology-graph').waitFor()
  // d3 ticks asynchronously — wait one tick before screenshotting so the
  // SVG isn't captured mid-layout.
  await page.waitForTimeout(150)
}

test.describe('AAASM-1341 — Topology AC evidence capture', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('AC1: graph renders nodes + edges per /api/v1/topology', async ({ page }) => {
    await gotoTopology(page)

    // Header: "<N> agents · <K> teams"
    await expect(page.getByTestId('topology-meta')).toHaveText(/4 agents · 2 teams/)

    // One svg <g.topology-node> per fixture node.
    await expect(page.getByTestId('topology-node')).toHaveCount(NODES.length)

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-graph-overview.png`, fullPage: true })
  })

  test('AC2: status colour + budget-spend size encoding', async ({ page }) => {
    await gotoTopology(page)

    // Every documented status surfaces in the graph and is encoded via
    // `data-status` on the <g.topology-node>. CSS rules in TopologyGraph.css
    // bind these to the status colour tokens (--ok / --ink-4 / --danger).
    const activeNodes = page.locator('[data-testid="topology-node"][data-status="active"]')
    const idleNodes = page.locator('[data-testid="topology-node"][data-status="idle"]')
    const errorNodes = page.locator('[data-testid="topology-node"][data-status="error"]')
    await expect(activeNodes).toHaveCount(2)
    await expect(idleNodes).toHaveCount(1)
    await expect(errorNodes).toHaveCount(1)

    // Size encoding: bucket by budget-spend ratio (small <0.5, medium 0.5-0.8, large >0.8).
    // support-1 ratio = 0.92 → large; support-2 = 0.10 → small.
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="large"]'),
    ).toHaveCount(1)
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="small"]'),
    ).toHaveCount(2) // support-2 + analytics-2 (0.05)
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="medium"]'),
    ).toHaveCount(1) // analytics-1 (0.55)

    await page.screenshot({ path: `${EVIDENCE_DIR}/02-status-and-size-encoding.png`, fullPage: true })
  })

  test('AC3: node click opens detail panel with identity / policies / recent / budget', async ({ page }) => {
    await gotoTopology(page)

    await page.locator('[data-testid="topology-node"]').first().click()
    const panel = page.getByTestId('node-detail-panel')
    await expect(panel).toBeVisible()

    // Identity section: id, owner, team, framework.
    const identity = page.getByTestId('node-detail-identity')
    await expect(identity).toContainText('agent-support-1')
    await expect(identity).toContainText('alice')
    await expect(identity).toContainText('support')
    await expect(identity).toContainText('langgraph')

    // Policies section ("permissions" in AC) — policyCount = 3 → "3 policies".
    await expect(page.getByTestId('node-detail-policy-count')).toContainText('3 policies')

    // Recent events from /api/v1/topology/nodes/{id}/events.
    const events = page.getByTestId('node-detail-event')
    await expect(events).toHaveCount(RECENT_EVENTS.length)
    await expect(events.first()).toContainText('tool_call')
    await expect(events.last()).toContainText('refund > $100')

    // Budget section: 9.2 / 10 → 92 % → warn bucket fill (danger is ≥ 95 %).
    await expect(page.getByTestId('node-detail-progress')).toHaveAttribute(
      'aria-valuenow',
      '92',
    )
    await expect(
      page.locator('.node-detail-panel__progress-fill'),
    ).toHaveAttribute('data-ratio-bucket', 'warn')

    await page.screenshot({ path: `${EVIDENCE_DIR}/03-node-detail-panel.png`, fullPage: true })
  })

  test('AC4: team grouping with team-level budget bar per team', async ({ page }) => {
    await gotoTopology(page)

    // Two distinct teams in the fixture → two cluster outlines + two team budget bars.
    const clusters = page.getByTestId('team-cluster')
    await expect(clusters).toHaveCount(2)
    await expect(page.locator('[data-testid="team-cluster"][data-team="support"]')).toBeVisible()
    await expect(page.locator('[data-testid="team-cluster"][data-team="analytics"]')).toBeVisible()

    const budgetBars = page.getByTestId('team-budget-bar')
    await expect(budgetBars).toHaveCount(2)

    // Support team aggregate spend = 9.2 + 1.0 = 10.2 of 20 → 0.51 → ok.
    // Analytics team aggregate spend = 5.5 + 0.5 = 6.0 of 20 → 0.30 → ok.
    await expect(
      page.locator('[data-testid="team-budget-bar"][data-threshold-bucket]'),
    ).toHaveCount(2)

    await page.screenshot({ path: `${EVIDENCE_DIR}/04-team-grouping-budget.png`, fullPage: true })
  })

  test('AC-cross-cut: View trace pivots into shell-level trace drawer with correct ids', async ({
    page,
  }) => {
    await gotoTopology(page)

    // Click the node that has `latestSessionId` set (support-1).
    await page
      .locator('[data-testid="topology-node"]')
      .filter({ hasText: 'support-bot' })
      .first()
      .click()
    const panel = page.getByTestId('node-detail-panel')
    await expect(panel).toBeVisible()

    // View trace must be enabled (latestSessionId is present).
    const viewTrace = page.getByTestId('node-detail-view-trace')
    await expect(viewTrace).toBeEnabled()
    await viewTrace.click()

    // Drawer mounts at the shell level (sibling of the topology page).
    const drawer = page.getByTestId('trace-drawer')
    await expect(drawer).toBeVisible()

    // Trace content uses the agent's session — the trace agent label
    // should resolve to AGENT.name and a trace row must render.
    await expect(page.getByTestId('trace-agent-label')).toHaveText(AGENT.name)
    await expect(page.getByTestId('trace-event').first()).toBeVisible()

    await page.screenshot({ path: `${EVIDENCE_DIR}/05-view-trace-drawer.png`, fullPage: true })

    // Esc closes the drawer.
    await page.keyboard.press('Escape')
    await expect(drawer).not.toBeVisible()
  })
})
