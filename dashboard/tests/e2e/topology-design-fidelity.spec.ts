/**
 * Design-fidelity verification for the topology UI (AAASM-1384).
 *
 * Walks the rendered TopologyPage and asserts the *visual* contract against
 * the hi-fi reference at `design/v1/hi-fi/topology.jsx` + the impl's CSS
 * comments which document the design contract explicitly:
 *
 *   - status stripe colors resolve to the exact CSS variable tokens
 *   - node size bucket matches the documented budget-ratio thresholds
 *   - NodeDetailPanel layout (header / status / sections / View trace)
 *     mirrors the hi-fi proportions
 *   - team cluster outlines render dashed with an uppercase label at top
 *   - team budget bar crosses ok / warn / danger thresholds at 0.80 / 0.95
 *   - node hover changes the card stroke (highlight contract)
 *
 * Captures full-page screenshots into `dashboard/docs/verification/aaasm-1384/`
 * for visual review alongside the hi-fi.
 *
 * Known accepted divergences (NOT regressions — these were merged
 * intentionally and signed off in the implementation tickets):
 *   - impl uses status enum `active / idle / error`; hi-fi uses
 *     `active / suspended / idle` (data-model concern, not visual).
 *   - impl idle stripe colour is `--ink-4` (mid grey) where hi-fi paints
 *     idle in `--warn` orange; choice merged under AAASM-1335 to align
 *     with the "muted background, status forwards" idea.
 *   - impl nodes are size-bucketed by budget spend per the parent Story
 *     AC ("size encodes budget spend"); hi-fi uses fixed TL_NW × TL_NH.
 *   - hi-fi's depth badge, mode/trust line, cycle warning, and live-update
 *     pulse ring are not yet wired (data not yet exposed by the API).
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1384')

// Token values — from dashboard/src/styles.css. Asserted as RGB because
// getComputedStyle returns colours in that form.
const TOKEN_RGB = {
  ok: 'rgb(34, 89, 42)',      // --ok    = #22592a
  inkMid: 'rgb(138, 138, 138)', // --ink-4 = #8a8a8a
  danger: 'rgb(184, 41, 30)', // --danger = #b8291e
  warn: 'rgb(138, 90, 0)',    // --warn  = #8a5a00
  ink2: 'rgb(42, 42, 42)',    // --ink-2 = #2a2a2a (hover stroke)
}

// ── Base fixture: 5 nodes across 2 teams, mixed statuses + budget levels ──
//
// Numbers picked so each bucket and threshold is exercised:
//   - support team aggregate spend = 1.5 / 30 → 0.05 → ok (low)
//   - analytics team aggregate spend = 1.5 / 30 → 0.05 → ok
//   - individual node ratios: 0.10 (small), 0.55 (medium), 0.92 (large)
//
// `latestSessionId` set on the mid-budget node so the View-trace
// screenshot is taken on a representative card.

const BASE_NODES = [
  {
    id: 'a-support-1',
    name: 'support-bot',
    framework: 'langgraph',
    owner: 'alice',
    team: 'support',
    status: 'active' as const,
    policyCount: 3,
    budgetSpend: 9.2,
    budgetLimit: 10,
  },
  {
    id: 'a-support-2',
    name: 'router',
    framework: 'langchain',
    owner: 'alice',
    team: 'support',
    status: 'idle' as const,
    policyCount: 2,
    budgetSpend: 1.0,
    budgetLimit: 10,
    latestSessionId: 'sess-aaasm-1384',
  },
  {
    id: 'a-support-3',
    name: 'tools',
    framework: 'crewai',
    owner: 'alice',
    team: 'support',
    status: 'active' as const,
    policyCount: 1,
    budgetSpend: 5.5,
    budgetLimit: 10,
  },
  {
    id: 'a-analytics-1',
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
    id: 'a-analytics-2',
    name: 'reporter',
    framework: 'crewai',
    owner: 'carol',
    team: 'analytics',
    status: 'idle' as const,
    policyCount: 1,
    budgetSpend: 0.5,
    budgetLimit: 10,
  },
]

const BASE_EDGES = [
  { source: 'a-support-1', target: 'a-support-2', kind: 'delegation' as const },
  { source: 'a-support-1', target: 'a-support-3', kind: 'delegation' as const },
  { source: 'a-analytics-1', target: 'a-analytics-2', kind: 'call' as const },
]

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

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'fidelity-token'))
}

interface TopologyShape {
  nodes: typeof BASE_NODES
  edges: typeof BASE_EDGES
}

async function mockTopology(page: Page, topology: TopologyShape) {
  await page.route('**/api/v1/topology', r => r.fulfill({ json: topology }))
  await page.route('**/api/v1/topology/nodes/*/events', r =>
    r.fulfill({ json: RECENT_EVENTS }),
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
  // Let d3-force settle one tick before snapshotting.
  await page.waitForTimeout(150)
}

test.describe('AAASM-1384 — Topology UI design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
  })

  test('status stripe colours resolve to the exact CSS tokens', async ({ page }) => {
    await mockTopology(page, { nodes: BASE_NODES, edges: BASE_EDGES })
    await gotoTopology(page)

    // Active stripe → --ok.
    const activeFill = await page
      .locator('[data-testid="topology-node"][data-status="active"] .topology-node__stripe')
      .first()
      .evaluate(el => getComputedStyle(el).fill)
    expect(activeFill).toBe(TOKEN_RGB.ok)

    // Idle stripe → --ink-4. Documented impl divergence from hi-fi (which
    // uses --warn for idle); this assertion locks in the impl's intent.
    const idleFill = await page
      .locator('[data-testid="topology-node"][data-status="idle"] .topology-node__stripe')
      .first()
      .evaluate(el => getComputedStyle(el).fill)
    expect(idleFill).toBe(TOKEN_RGB.inkMid)

    // Error stripe → --danger. (Hi-fi calls the equivalent state "suspended"
    // with the same red colour — semantic naming differs, visual matches.)
    const errorFill = await page
      .locator('[data-testid="topology-node"][data-status="error"] .topology-node__stripe')
      .first()
      .evaluate(el => getComputedStyle(el).fill)
    expect(errorFill).toBe(TOKEN_RGB.danger)

    await page.screenshot({
      path: `${EVIDENCE_DIR}/01-status-stripe-tokens.png`,
      fullPage: true,
    })
  })

  test('node size buckets match documented budget-ratio thresholds', async ({ page }) => {
    await mockTopology(page, { nodes: BASE_NODES, edges: BASE_EDGES })
    await gotoTopology(page)

    // small (<0.5): support-2 (0.10) + analytics-2 (0.05) = 2
    // medium (0.5-0.8): support-3 (0.55) + analytics-1 (0.55) = 2
    // large (>0.8): support-1 (0.92) = 1
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="small"]'),
    ).toHaveCount(2)
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="medium"]'),
    ).toHaveCount(2)
    await expect(
      page.locator('[data-testid="topology-node"][data-size-bucket="large"]'),
    ).toHaveCount(1)

    // Geometric ordering — a "large" card's drawn rect must be wider than a
    // "small" card's. The impl uses SIZE_VARIANT { small: 76, medium: 96, large: 116 }.
    const smallW = await page
      .locator('[data-testid="topology-node"][data-size-bucket="small"] .topology-node__card')
      .first()
      .evaluate(el => parseFloat(el.getAttribute('width') ?? '0'))
    const largeW = await page
      .locator('[data-testid="topology-node"][data-size-bucket="large"] .topology-node__card')
      .first()
      .evaluate(el => parseFloat(el.getAttribute('width') ?? '0'))
    expect(largeW).toBeGreaterThan(smallW)

    await page.screenshot({
      path: `${EVIDENCE_DIR}/02-node-size-buckets.png`,
      fullPage: true,
    })
  })

  test('NodeDetailPanel layout matches hi-fi structure on a mid-budget agent', async ({ page }) => {
    await mockTopology(page, { nodes: BASE_NODES, edges: BASE_EDGES })
    await gotoTopology(page)

    // Click the mid-budget analytics-1 (0.55 → medium bucket).
    await page
      .locator('[data-testid="topology-node"]')
      .filter({ hasText: 'analyst' })
      .first()
      .click()

    const panel = page.getByTestId('node-detail-panel')
    await expect(panel).toBeVisible()

    // Required structural sections must all be present and ordered top-down.
    const identity = page.getByTestId('node-detail-identity')
    const policies = page.getByTestId('node-detail-policies')
    const budget = page.getByTestId('node-detail-budget')
    const recent = page.getByTestId('node-detail-recent')
    const actions = page.getByTestId('node-detail-actions')

    const sections = [identity, policies, budget, recent, actions]
    for (const s of sections) await expect(s).toBeVisible()

    const ys = await Promise.all(
      sections.map(async s => (await s.boundingBox())!.y),
    )
    // Strict top-to-bottom ordering: identity → policies → budget → recent → actions.
    for (let i = 1; i < ys.length; i++) {
      expect(ys[i]).toBeGreaterThan(ys[i - 1])
    }

    // Status badge sits in the panel header (visible & to the right of the title).
    const status = page.getByTestId('node-detail-status')
    await expect(status).toBeVisible()

    // View trace is the primary action (carries the --primary modifier).
    const viewTrace = page.getByTestId('node-detail-view-trace')
    await expect(viewTrace).toBeVisible()
    await expect(viewTrace).toHaveClass(/node-detail-panel__action--primary/)

    await page.screenshot({
      path: `${EVIDENCE_DIR}/03-node-detail-panel-layout.png`,
      fullPage: true,
    })
  })

  test('team clusters render dashed outlines with uppercase team labels at top', async ({ page }) => {
    await mockTopology(page, { nodes: BASE_NODES, edges: BASE_EDGES })
    await gotoTopology(page)

    const clusters = page.getByTestId('team-cluster')
    await expect(clusters).toHaveCount(2)

    // Cluster outline must use the documented dashed stroke.
    const dash = await page
      .locator('[data-testid="team-cluster"] .topology-cluster__outline')
      .first()
      .evaluate(el => getComputedStyle(el).strokeDasharray)
    expect(dash).toBe('4 3')

    // Team label sits in the foreignObject at the top of the cluster — pick
    // the first label and assert it is above the first node card.
    const labelBox = await page.getByTestId('team-cluster-label').first().boundingBox()
    const nodeBox = await page.getByTestId('topology-node').first().boundingBox()
    expect(labelBox).not.toBeNull()
    expect(nodeBox).not.toBeNull()
    expect(labelBox!.y).toBeLessThan(nodeBox!.y)

    // Text transform is uppercase per the design rule.
    const transform = await page
      .getByTestId('team-cluster-label')
      .first()
      .evaluate(el => getComputedStyle(el).textTransform)
    expect(transform).toBe('uppercase')

    await page.screenshot({
      path: `${EVIDENCE_DIR}/04-team-cluster-labels.png`,
      fullPage: true,
    })
  })

  test('team budget bar crosses thresholds at 0.80 (ok→warn) and 0.95 (warn→danger)', async ({
    page,
  }) => {
    // Fixture A — every team at ratio 0.30 → ok (green).
    await mockTopology(page, {
      nodes: BASE_NODES.map(n => ({ ...n, budgetSpend: 3.0, budgetLimit: 10 })),
      edges: BASE_EDGES,
    })
    await gotoTopology(page)
    const okFill = await page
      .locator('[data-testid="team-budget-bar"] .team-budget-bar__fill')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(okFill).toBe(TOKEN_RGB.ok)
    await expect(
      page.locator('[data-testid="team-budget-bar"][data-threshold-bucket="ok"]').first(),
    ).toBeVisible()
    await page.screenshot({
      path: `${EVIDENCE_DIR}/05a-budget-bar-ok.png`,
      fullPage: true,
    })

    // Fixture B — every team at ratio 0.85 → warn (amber).
    await page.unrouteAll({ behavior: 'ignoreErrors' })
    await mockTopology(page, {
      nodes: BASE_NODES.map(n => ({ ...n, budgetSpend: 8.5, budgetLimit: 10 })),
      edges: BASE_EDGES,
    })
    await gotoTopology(page)
    const warnFill = await page
      .locator('[data-testid="team-budget-bar"] .team-budget-bar__fill')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(warnFill).toBe(TOKEN_RGB.warn)
    await expect(
      page.locator('[data-testid="team-budget-bar"][data-threshold-bucket="warn"]').first(),
    ).toBeVisible()
    await page.screenshot({
      path: `${EVIDENCE_DIR}/05b-budget-bar-warn.png`,
      fullPage: true,
    })

    // Fixture C — every team at ratio 0.97 → danger (red).
    await page.unrouteAll({ behavior: 'ignoreErrors' })
    await mockTopology(page, {
      nodes: BASE_NODES.map(n => ({ ...n, budgetSpend: 9.7, budgetLimit: 10 })),
      edges: BASE_EDGES,
    })
    await gotoTopology(page)
    const dangerFill = await page
      .locator('[data-testid="team-budget-bar"] .team-budget-bar__fill')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(dangerFill).toBe(TOKEN_RGB.danger)
    await expect(
      page.locator('[data-testid="team-budget-bar"][data-threshold-bucket="danger"]').first(),
    ).toBeVisible()
    await page.screenshot({
      path: `${EVIDENCE_DIR}/05c-budget-bar-danger.png`,
      fullPage: true,
    })
  })

  test('node hover changes card stroke to --ink-2 (highlight contract)', async ({ page }) => {
    await mockTopology(page, { nodes: BASE_NODES, edges: BASE_EDGES })
    await gotoTopology(page)

    const node = page.locator('[data-testid="topology-node"]').first()
    const card = node.locator('.topology-node__card')

    // Move the mouse off any node first, then hover. Read the stroke during the hover.
    await page.mouse.move(0, 0)
    await node.hover()
    const strokeOnHover = await card.evaluate(el => getComputedStyle(el).stroke)
    expect(strokeOnHover).toBe(TOKEN_RGB.ink2)

    await page.screenshot({
      path: `${EVIDENCE_DIR}/06-node-hover-highlight.png`,
      fullPage: true,
    })
  })
})
