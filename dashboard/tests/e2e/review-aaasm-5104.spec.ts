/**
 * Review pass for AAASM-5104 — the unified `trust` type and null contract.
 *
 * `trust` used to be `Option<u8>` on `CapabilityAgent` (key omitted when
 * absent) and `Option<f64>` on `AgentNode` / `AgentTree` (explicit `null`).
 * AAASM-5104 settles on one representation — an integer 0–100 — and one null
 * contract — required-but-nullable, so the key is always on the wire.
 *
 * Making the key always present is the risky half of that change: every render
 * site that previously guarded on `trust !== undefined` would now take the
 * "has a score" branch for a `null`, drawing a zero-width bar that reads as
 * "this agent scored zero". This run drives the four surfaces that render a
 * trust value against a payload shaped like the new contract and re-derives:
 *
 *  1. the Capability matrix grid folds `trust: null` to `—` and draws no bar;
 *  2. the Per-resource and Per-agent tabs do the same;
 *  3. the Fleet Trust column folds to `—` with no bar;
 *  4. the Agent-detail trust gauge folds to `—` — no gauge, no numeral;
 *  5. the Topology node's trust badge stays hidden and carries no `data-trust`;
 *  6. no surface leaks a `0`, `NaN`, `undefined`, or a literal `null` where an
 *     unmeasured score belongs;
 *  7. none of it produces console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5104/.
 */
import { test, expect, type Page, type Locator } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5104')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** Anything that would read as a real measurement where `—` belongs. */
const FAKE_SCORE = /\b(0|NaN|undefined|null)\b/

const ID_A = 'a1'.repeat(16)
const ID_B = 'b2'.repeat(16)

/**
 * `GET /api/v1/capability/matrix` under the new contract: `trust` is present on
 * every agent and is `null`. Before AAASM-5104 this key was simply missing.
 */
const MATRIX = {
  resources: [
    { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
    { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
  ],
  agents: [
    {
      id: ID_A,
      name: 'checkout-agent',
      framework: 'langgraph',
      owner: 'team-alpha',
      status: 'active',
      mode: 'enforce',
      lastSeen: new Date(Date.now() - 120_000).toISOString(),
      trust: null,
      caps: {
        filesystem: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      },
    },
    {
      id: ID_B,
      name: 'refund-agent',
      framework: 'crewai',
      owner: 'team-beta',
      status: 'active',
      mode: 'enforce',
      lastSeen: new Date(Date.now() - 3_600_000).toISOString(),
      trust: null,
      caps: {
        filesystem: { read: 'allow', write: 'allow', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
      },
    },
  ],
  policies: [],
  sampleCalls: [],
}

function agentRecord(id: string, name: string, framework: string) {
  return {
    id,
    name,
    framework,
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: new Date().toISOString(),
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: 0,
    tool_names: [],
    metadata: { owner: 'platform-team', mode: 'enforce' },
    pid: null,
  }
}

const AGENTS = [
  agentRecord(ID_A, 'checkout-agent', 'langgraph'),
  agentRecord(ID_B, 'refund-agent', 'crewai'),
]

/** `GET /api/v1/topology` graph nodes, each carrying the explicit `null`. */
const TOPOLOGY_NODES = [
  { id: 'planner', name: 'planner', framework: 'langgraph', owner: 'alice', team: 'support', status: 'active', policyCount: 3, budgetSpend: 1, budgetLimit: 10, mode: 'enforce', flagged: false, trust: null },
  { id: 'worker-a', name: 'worker-a', framework: 'langchain', owner: 'alice', team: 'support', status: 'idle', policyCount: 2, budgetSpend: 6, budgetLimit: 10, mode: 'shadow', flagged: false, trust: null },
]
const TOPOLOGY_EDGES = [{ source: 'planner', target: 'worker-a', kind: 'delegation' }]

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades are the fixture's doing, not the app's.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5104')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/capability/matrix**', (r) => r.fulfill({ json: MATRIX }))
  await page.route('**/api/v1/topology', (r) => r.fulfill({ json: { nodes: TOPOLOGY_NODES, edges: TOPOLOGY_EDGES } }))
  await page.route('**/api/v1/topology/nodes/*/events', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/agents**', (r) => {
    const url = new URL(r.request().url())
    const m = /\/api\/v1\/agents\/([0-9a-f]+)/.exec(url.pathname)
    if (m) return r.fulfill({ json: AGENTS.find((a) => a.id === m[1]) ?? AGENTS[0] })
    return r.fulfill({ json: { items: AGENTS, total: AGENTS.length } })
  })
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

/**
 * Vite `base: './'` workaround — a hard load of a nested route resolves assets
 * relative to that path and 404s, so navigate client-side instead.
 */
async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

/** An unmeasured score renders the placeholder and nothing that reads as data. */
async function expectNoDataOnly(locator: Locator) {
  await expect(locator).toContainText('—')
  expect(await locator.textContent()).not.toMatch(FAKE_SCORE)
}

test.describe('AAASM-5104 review — unified trust type and null contract', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`capability surfaces fold an explicit null trust to — in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/capability')
      await page.getByTestId('capability-page').waitFor()

      // ── 1. matrix grid: `—`, and no bar at all ──────────────────────────
      const grid = page.getByRole('grid', { name: 'capability matrix' })
      await expect(grid).toBeVisible()
      const trustMeta = grid.locator('.cap-mx-row-h-trust')
      await expect(trustMeta).toHaveCount(MATRIX.agents.length)
      for (let i = 0; i < MATRIX.agents.length; i += 1) {
        await expect(trustMeta.nth(i)).toHaveText('trust —')
      }
      // A zero-width bar is not "no bar" — it reads as a score of zero.
      await expect(grid.locator('.cap-trust-bar')).toHaveCount(0)
      await grid.screenshot({ path: `${EVIDENCE_DIR}/capability-matrix-${theme}.png` })

      // ── 2a. per-resource tab ────────────────────────────────────────────
      await page.getByRole('button', { name: 'Per-resource' }).click()
      const prtNum = page.locator('.cap-prt-trust-num')
      await expect(prtNum.first()).toBeVisible()
      const prtCount = await prtNum.count()
      for (let i = 0; i < prtCount; i += 1) {
        await expect(prtNum.nth(i)).toHaveText('—')
      }
      await expect(page.locator('.cap-prt-trust-bar')).toHaveCount(0)
      await page.getByTestId('capability-page').screenshot({
        path: `${EVIDENCE_DIR}/capability-per-resource-${theme}.png`,
      })

      // ── 2b. per-agent tab ───────────────────────────────────────────────
      await page.getByRole('button', { name: 'Per-agent' }).click()
      const meta = page.locator('.cap-pat-meta').first()
      await expect(meta).toContainText('trust —')
      expect(await meta.textContent()).not.toMatch(/trust (0|NaN|undefined|null)/)
      await page.getByTestId('capability-page').screenshot({
        path: `${EVIDENCE_DIR}/capability-per-agent-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`fleet and agent-detail fold an explicit null trust to — in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/agents')
      await page.getByTestId('agents-table').waitFor()

      // ── 3. Fleet Trust column ───────────────────────────────────────────
      const trustCells = page.getByTestId('fleet-trust')
      await expect(trustCells).toHaveCount(AGENTS.length)
      for (let i = 0; i < AGENTS.length; i += 1) {
        await expectNoDataOnly(trustCells.nth(i))
      }
      // The empty state is the em-dash span, not a zero-length track.
      await expect(page.locator('.fleet-trust__track')).toHaveCount(0)
      await expect(page.locator('.fleet-trust__value')).toHaveCount(0)
      await page.getByTestId('agents-table').screenshot({
        path: `${EVIDENCE_DIR}/fleet-trust-${theme}.png`,
      })

      // ── 4. Agent-detail gauge ───────────────────────────────────────────
      const rowA = page.locator('[data-testid="agent-row"]', { hasText: 'checkout-agent' })
      await rowA.getByTestId('fleet-row-name').click()
      const identity = page.getByTestId('agent-detail-identity')
      await identity.waitFor()
      await expectNoDataOnly(identity.locator('.ad-identity__trust'))
      // No gauge means no numeral and no standing phrase invented from a zero.
      await expect(identity.locator('.ad-identity__trust svg')).toHaveCount(0)
      await expect(identity).not.toContainText('low — needs review')
      await identity.screenshot({ path: `${EVIDENCE_DIR}/agent-detail-trust-${theme}.png` })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`topology hides the trust badge for an explicit null in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/topology')
      await page.getByTestId('topology-graph').waitFor()
      // Let d3-force settle so the layout arranges before capture.
      await page.waitForTimeout(600)

      // ── 5. no badge, and no `data-trust` for a downstream reader ────────
      const nodes = page.getByTestId('topology-node')
      await expect(nodes).toHaveCount(TOPOLOGY_NODES.length)
      await expect(page.getByTestId('topology-node-trust')).toHaveCount(0)
      await expect(page.locator('[data-testid="topology-node"][data-trust]')).toHaveCount(0)
      // The nodes still rendered — this is a hidden badge, not a dead graph.
      await expect(nodes.first()).toBeVisible()
      await expect(page.getByTestId('topology-graph')).not.toContainText('◈')

      await page.getByTestId('topology-graph').screenshot({
        path: `${EVIDENCE_DIR}/topology-trust-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
