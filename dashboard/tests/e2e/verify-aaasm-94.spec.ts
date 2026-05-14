/**
 * Story-level e2e verification for AAASM-94 (S21 — web governance dashboard).
 *
 * The dashboard is composed of many independently-tested pages and features.
 * This spec walks the Story as a coherent whole:
 *   - AC5/AC6: AppShell renders + every one of the 12 canonical nav routes
 *     returns either an implemented page or a `ComingSoon` placeholder (no
 *     `NotFoundPage`, no 404s).
 *   - AC7: global overlay mount points exist at shell level (per
 *     OVERLAY_NAMES).
 *   - Cross-cut integration flows: login landing, topology → trace drawer
 *     pivot, Fleet → AgentDetail drill, Teams → TeamDetail drill, sidebar
 *     swap between two routes.
 *
 * Each test captures a full-page PNG into `dashboard/docs/verification/aaasm-94/`
 * so the evidence can be reviewed in the PR alongside the Story-level report.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'
import { CANONICAL_ROUTES } from '../../src/routes'
import { OVERLAY_NAMES } from '../../src/components/OverlayContext'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-94')

// ── Fixtures ───────────────────────────────────────────────────────────────────

const APPROVALS = [
  {
    id: 'aaasm94-appr-1',
    agent_id: 'agent-aaasm94',
    action: 'shell.exec ls',
    reason: 'inspection',
    status: 'pending',
    created_at: '2026-05-14T08:00:00Z',
    routing_status: null,
    team_id: null,
  },
]

const TOPOLOGY = {
  nodes: [
    {
      id: 'agent-support-1',
      name: 'support-bot',
      framework: 'langgraph',
      owner: 'alice',
      team: 'support',
      status: 'active' as const,
      policyCount: 3,
      budgetSpend: 5.5,
      budgetLimit: 10,
      latestSessionId: 'sess-aaasm94',
    },
    {
      id: 'agent-support-2',
      name: 'router',
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
      status: 'active' as const,
      policyCount: 1,
      budgetSpend: 2.5,
      budgetLimit: 10,
    },
  ],
  edges: [
    { source: 'agent-support-1', target: 'agent-support-2', kind: 'delegation' as const },
  ],
}

// Conforms to the OpenAPI `AgentResponse` schema (active_sessions,
// recent_events, recent_traces, metadata, tool_names are all required).
const AGENT_LIST = [
  {
    id: 'agent-support-1',
    name: 'support-bot',
    framework: 'langgraph',
    status: 'active',
    layer: 'sdk',
    session_count: 4,
    policy_violations_count: 1,
    last_event: '2026-05-14T07:55:00Z',
    tool_names: ['search', 'process_refund'],
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    metadata: { owner: 'alice', mode: 'enforce' },
    pid: null,
  },
  {
    id: 'agent-analytics-1',
    name: 'analyst',
    framework: 'crewai',
    status: 'active',
    layer: 'sdk',
    session_count: 2,
    policy_violations_count: 0,
    last_event: '2026-05-14T07:30:00Z',
    tool_names: ['query_db'],
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    metadata: { owner: 'carol', mode: 'enforce' },
    pid: null,
  },
]

const AGENT_DETAIL = {
  ...AGENT_LIST[0],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

const TRACE_EVENTS = [
  {
    id: 'evt-aaasm94',
    timestamp: '2026-05-14T08:00:00Z',
    type: 'llm_call',
    agent: 'support-bot',
    durationMs: 312,
    payloadPreview: 'GPT-4o · lookup',
    payload: { model: 'gpt-4o' },
    severity: 'info',
  },
]

// `/api/v1/topology/overview` shape (TopologyOverview schema).
const TOPOLOGY_OVERVIEW = {
  team_count: 2,
  total_agent_count: 3,
  root_agent_count: 2,
  teams: [
    { team_id: 'team-support', agent_count: 2, root_agent_count: 1 },
    { team_id: 'team-analytics', agent_count: 1, root_agent_count: 1 },
  ],
  standalone_root_agents: [],
}

// `/api/v1/costs` shape (CostSummary schema — note USD as string).
const COST_SUMMARY = {
  date: '2026-05-14',
  daily_spend_usd: '9.00',
  daily_limit_usd: '30.00',
  per_team: [
    { team_id: 'team-support', daily_spend_usd: '6.50', date: '2026-05-14' },
    { team_id: 'team-analytics', daily_spend_usd: '2.50', date: '2026-05-14' },
  ],
}

const POLICIES = [
  { name: 'refund-cap', version: '1.0.0', rule_count: 2, active: true },
]

const ALERTS: unknown[] = []

const CAPABILITIES_MATRIX = { tools: [], totals: { allow: 0, narrow: 0, deny: 0, approval: 0 } }

const SCRUB_CONFIG = {
  detectors: [],
  redaction_mode: 'mask',
  preview_text: '',
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'aaasm94-token'))
}

async function mockApi(page: Page) {
  // Shell-level + ubiquitous calls
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: APPROVALS }))
  await page.route('**/api/v1/ws/events**', r => r.abort())

  // Fleet / agents — accept any pagination query string suffix.
  await page.route(/\/api\/v1\/agents(\?|$)/, r => r.fulfill({ json: AGENT_LIST }))
  await page.route('**/api/v1/agents/agent-support-1', r => r.fulfill({ json: AGENT_DETAIL }))
  await page.route('**/api/v1/agents/agent-support-1/sessions/*/trace', r =>
    r.fulfill({ json: TRACE_EVENTS }),
  )

  // Topology
  await page.route('**/api/v1/topology', r => r.fulfill({ json: TOPOLOGY }))
  await page.route('**/api/v1/topology/nodes/*/events', r => r.fulfill({ json: [] }))

  // Teams page is driven by topology overview + costs (per-team rollup).
  await page.route('**/api/v1/topology/overview', r => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route('**/api/v1/costs', r => r.fulfill({ json: COST_SUMMARY }))
  // Team detail page hits /api/v1/topology/team/{team_id}.
  await page.route('**/api/v1/topology/team/*', r =>
    r.fulfill({ json: { team_id: 'team-support', agents: [], total_agents: 0 } }),
  )

  // Other pages — return empty/defaults so pages render their empty/loaded state.
  await page.route('**/api/v1/policies', r => r.fulfill({ json: POLICIES }))
  await page.route('**/api/v1/alerts**', r => r.fulfill({ json: ALERTS }))
  await page.route('**/api/v1/capabilities', r => r.fulfill({ json: CAPABILITIES_MATRIX }))
  await page.route('**/api/v1/scrub/config', r => r.fulfill({ json: SCRUB_CONFIG }))
  await page.route('**/api/v1/analytics/**', r => r.fulfill({ json: {} }))
  await page.route('**/api/v1/iam/**', r => r.fulfill({ json: [] }))

  // Auth
  await page.route('**/api/v1/auth/token', r => r.fulfill({ json: { token: 'aaasm94-token' } }))
}

/**
 * Navigate to a deep route via history.pushState to work around the Vite
 * `base: './'` config that returns the SPA shell only at `/`. Mirrors the
 * pattern used by `verify-aaasm-1152.spec.ts` and `verify-aaasm-1341.spec.ts`.
 */
async function gotoRoute(page: Page, path: string) {
  await page.goto('/')
  await page.evaluate(p => window.history.pushState({}, '', p), path)
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('appshell').waitFor()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

test.describe('AAASM-94 — Story-level dashboard e2e verification', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('AC5: AppShell renders with sidebar + topbar + all 12 canonical nav entries', async ({
    page,
  }) => {
    await gotoRoute(page, '/approvals')

    await expect(page.getByTestId('appshell')).toBeVisible()
    await expect(page.getByTestId('appshell-nav')).toBeVisible()
    await expect(page.getByTestId('appshell-topbar')).toBeVisible()

    // Three section headers from the canonical route catalog.
    for (const group of ['monitor', 'control', 'manage']) {
      await expect(page.getByTestId(`nav-section-${group}`)).toBeVisible()
    }

    // 12 nav links — one per canonical route.
    for (const route of CANONICAL_ROUTES) {
      await expect(page.getByTestId(`nav-link-${route.id}`)).toBeVisible()
    }
    expect(CANONICAL_ROUTES).toHaveLength(12)

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-shell-nav.png`, fullPage: true })
  })

  test('AC6: every one of the 12 canonical routes renders a real page or ComingSoon — no 404', async ({
    page,
  }) => {
    for (const route of CANONICAL_ROUTES) {
      await gotoRoute(page, route.path)

      // NotFoundPage uses data-testid="not-found-page"; assert we never hit it.
      await expect(page.getByTestId('not-found-page')).toHaveCount(0)

      // Confirm we're on the AppShell (proves the route resolved to a page).
      await expect(page.getByTestId('appshell')).toBeVisible()
    }

    // Snapshot the last route we visited (Members & Access) as evidence.
    await page.screenshot({ path: `${EVIDENCE_DIR}/02-all-routes-no-404.png`, fullPage: true })
  })

  test('AC7: global overlay mount points exist at shell level (one per OVERLAY_NAMES entry)', async ({
    page,
  }) => {
    await gotoRoute(page, '/approvals')

    for (const name of OVERLAY_NAMES) {
      const mount = page.locator(`[data-testid="overlay-mount-${name}"]`)
      await expect(mount).toHaveCount(1)
      await expect(mount).toHaveAttribute('data-overlay', name)
    }

    await page.screenshot({ path: `${EVIDENCE_DIR}/03-overlay-mounts.png`, fullPage: true })
  })

  test('login flow: API key form → /approvals landing renders inside AppShell', async ({
    page,
  }) => {
    // Drop the injected token for this test so we hit /login.
    await page.addInitScript(() => localStorage.removeItem('aa_token'))

    await page.goto('/login')
    await expect(page.getByLabel('API Key')).toBeVisible()
    await page.getByLabel('API Key').fill('aaasm94-key')
    await page.getByRole('button', { name: 'Sign in' }).click()

    await expect(page).toHaveURL('/')
    await expect(page.getByTestId('appshell')).toBeVisible()
    await page.screenshot({ path: `${EVIDENCE_DIR}/04-login-landing.png`, fullPage: true })
  })

  test('cross-cut: Topology → click node → "View trace" opens shell-level trace drawer', async ({
    page,
  }) => {
    await gotoRoute(page, '/topology')
    await page.getByTestId('topology-graph').waitFor()
    // Let d3-force settle.
    await page.waitForTimeout(150)

    await page
      .locator('[data-testid="topology-node"]')
      .filter({ hasText: 'support-bot' })
      .first()
      .click()
    await expect(page.getByTestId('node-detail-panel')).toBeVisible()

    const viewTrace = page.getByTestId('node-detail-view-trace')
    await expect(viewTrace).toBeEnabled()
    await viewTrace.click()

    await expect(page.getByTestId('trace-drawer')).toBeVisible()
    await expect(page.getByTestId('trace-event').first()).toBeVisible()

    await page.screenshot({
      path: `${EVIDENCE_DIR}/05-topology-to-trace-drawer.png`,
      fullPage: true,
    })
  })

  test('cross-cut: Fleet → click agent → AgentDetail drawer opens over Fleet page', async ({
    page,
  }) => {
    await gotoRoute(page, '/agents')
    await expect(page.getByTestId('fleet-page')).toBeVisible()
    await expect(page.locator('[data-testid="fleet-row-name"]').first()).toBeVisible()

    await page.locator('[data-testid="fleet-row-name"]').first().click()
    await expect(page).toHaveURL(/\/agents\/agent-support-1/)

    // AgentDetailPage renders inside a <Drawer> over Fleet; assert the identity
    // section is visible (proves the drawer mounted and the agent data loaded).
    await expect(page.getByTestId('agent-detail-identity')).toBeVisible()

    // Fleet stays mounted underneath the drawer — proves the shell nested-route
    // pattern keeps the parent page alive while the child drawer overlays it.
    await expect(page.getByTestId('fleet-page')).toBeVisible()

    await page.screenshot({
      path: `${EVIDENCE_DIR}/06-fleet-to-agent-detail.png`,
      fullPage: true,
    })
  })

  test('cross-cut: Teams → click team link → TeamDetail page', async ({ page }) => {
    await gotoRoute(page, '/teams')
    await expect(page.getByTestId('teams-table')).toBeVisible()
    const firstRow = page.locator('[data-testid="team-row"]').first()
    await expect(firstRow).toBeVisible()

    // The team-id cell is wrapped in a <Link to={`/teams/${team_id}`}> per
    // TeamsPage.tsx. Click the link, not the surrounding <tr>.
    await firstRow.locator('a[href^="/teams/"]').first().click()

    await expect(page).toHaveURL(/\/teams\/team-support/)
    await page.screenshot({
      path: `${EVIDENCE_DIR}/07-teams-to-team-detail.png`,
      fullPage: true,
    })
  })

  test('cross-cut: sidebar swaps Outlet between two routes without remounting AppShell', async ({
    page,
  }) => {
    await gotoRoute(page, '/alerts')
    const initialShell = await page.getByTestId('appshell').elementHandle()
    expect(initialShell).not.toBeNull()

    // Click into Policies via the sidebar.
    await page.getByTestId('nav-link-policy').click()
    await expect(page).toHaveURL(/\/policies$/)

    // The SAME AppShell DOM node should still be present — proves the shell never
    // unmounted and only the routed `<Outlet>` swapped.
    const afterShell = await page.getByTestId('appshell').elementHandle()
    expect(afterShell).not.toBeNull()
    const sameNode = await page.evaluate(
      ([a, b]) => a === b,
      [initialShell, afterShell],
    )
    expect(sameNode).toBe(true)

    await page.screenshot({
      path: `${EVIDENCE_DIR}/08-sidebar-route-swap.png`,
      fullPage: true,
    })
  })
})
