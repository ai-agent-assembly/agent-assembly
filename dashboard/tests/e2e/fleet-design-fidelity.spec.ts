/**
 * Design-fidelity verification for the Fleet page + Agent Detail drawer
 * shipped under parent Story AAASM-217 (sub-tasks 1047/1048/1050/1052/1151).
 *
 * Walks the rendered surfaces and asserts the visual contract against the
 * hi-fi prototype:
 *   - `design/v1/hi-fi/fleet.jsx`         — Fleet page chrome, table, bulk bar
 *   - `design/v1/hi-fi/agent-detail.jsx`  — Drawer head, identity strip, tabs
 *   - `design/v1/hi-fi/styles.css`        — Token RGB values
 *
 * Captures `locator.screenshot()` per section into
 * `verification-reports/AAASM-217-design-fidelity/` so the companion
 * narrative report (`AAASM-217-design-fidelity.md`) can embed them.
 *
 * Runs at 1280x800 (the hi-fi reference viewport).
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), '..', 'verification-reports', 'AAASM-217-design-fidelity')

// Hi-fi RGB tokens from `design/v1/hi-fi/styles.css` (also lives in
// `dashboard/src/styles.css`). Drift between the two would fail these.
const TOKENS = {
  paper: 'rgb(245, 244, 240)', // --paper
  paper2: 'rgb(255, 255, 255)', // --paper-2
  paper3: 'rgb(235, 233, 226)', // --paper-3
  ink: 'rgb(14, 14, 14)', // --ink
  ink3: 'rgb(90, 90, 90)', // --ink-3
  ink4: 'rgb(138, 138, 138)', // --ink-4
  line: 'rgb(216, 212, 199)', // --line
  ok: 'rgb(34, 89, 42)', // --ok (active status)
  danger: 'rgb(184, 41, 30)', // --danger (suspended status / suspend btn)
  warn: 'rgb(138, 90, 0)', // --warn
}

const ACTIVE_AGENT = {
  id: 'agent-design-01',
  name: 'alpha-bot',
  framework: 'langgraph',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 12,
  policy_violations_count: 2,
  last_event: '2026-05-14T08:00:00Z',
  tool_names: ['search', 'shell'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { owner: 'alice', mode: 'enforce' },
  pid: null,
}

const FLAGGED_AGENT = {
  id: 'agent-design-02',
  name: 'gamma-bot',
  framework: 'langgraph',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 80,
  policy_violations_count: 75, // > 50 → flagged
  last_event: '2026-05-14T07:00:00Z',
  tool_names: ['gmail.send'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { owner: 'bob', mode: 'shadow', note: 'pending policy review' },
  pid: null,
}

const SUSPENDED_AGENT = {
  id: 'agent-design-03',
  name: 'beta-bot',
  framework: 'crewai',
  version: '0.1.0',
  status: 'suspended',
  layer: 'sdk',
  session_count: 4,
  policy_violations_count: 0,
  last_event: '2026-05-13T22:00:00Z',
  tool_names: ['notion.read'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { owner: 'carol' },
  pid: null,
}

const AGENTS = [ACTIVE_AGENT, FLAGGED_AGENT, SUSPENDED_AGENT]

async function injectToken(page: Page) {
  await page.addInitScript(() =>
    localStorage.setItem('aa_token', 'design-fidelity-token'),
  )
}

async function mockApi(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/approvals**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/agents**', (route) => {
    const url = route.request().url()
    const idMatch = url.match(/\/api\/v1\/agents\/([^/?]+)(?:\?|$)/)
    if (idMatch && !url.includes('/suspend') && !url.includes('/resume')) {
      const a = AGENTS.find((x) => x.id === idMatch[1]) ?? ACTIVE_AGENT
      return route.fulfill({ json: a })
    }
    return route.fulfill({ json: AGENTS })
  })
}

async function gotoFleet(page: Page) {
  await page.goto('/agents')
  await page.getByTestId('fleet-page').waitFor()
  await page.getByTestId('agent-row').first().waitFor()
}

test.describe('AAASM-1382 — Fleet + Agent Detail design fidelity @ 1280x800', () => {
  test.use({ viewport: { width: 1280, height: 800 } })

  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('Fleet page-head matches hi-fi tokens + layout', async ({ page }) => {
    await gotoFleet(page)
    const head = page.getByTestId('fleet-page-head')
    await expect(head).toBeVisible()

    // Hi-fi `.page-head`: padding 22 24 18, white paper-2 background.
    const bg = await head.evaluate((el) => getComputedStyle(el).backgroundColor)
    expect(bg).toBe(TOKENS.paper2)

    // Counter reads "N of M agents".
    const counter = page.getByTestId('fleet-page-count')
    await expect(counter).toContainText('of')
    await expect(counter).toContainText('agents')

    // Title font-size: 22px per hi-fi.
    const titleSize = await head.locator('.fleet-page__title').evaluate(
      (el) => getComputedStyle(el as Element).fontSize,
    )
    expect(titleSize).toBe('22px')

    await head.screenshot({ path: `${EVIDENCE_DIR}/01-fleet-page-head.png` })
  })

  test('Fleet view tabs render with active-tab underline accent', async ({ page }) => {
    await gotoFleet(page)
    const tabs = page.getByTestId('fleet-tabs')
    await expect(tabs).toBeVisible()

    // Both tabs render.
    await expect(page.getByTestId('fleet-tab-agents')).toBeVisible()
    await expect(page.getByTestId('fleet-tab-sessions')).toBeVisible()

    // Active tab has ink bottom-border; inactive is transparent.
    const activeBorder = await page.getByTestId('fleet-tab-agents').evaluate(
      (el) => getComputedStyle(el as Element).borderBottomColor,
    )
    expect(activeBorder).toBe(TOKENS.ink)
    const inactiveBorder = await page.getByTestId('fleet-tab-sessions').evaluate(
      (el) => getComputedStyle(el as Element).borderBottomColor,
    )
    expect(inactiveBorder).not.toBe(TOKENS.ink)

    await tabs.screenshot({ path: `${EVIDENCE_DIR}/02-fleet-view-tabs.png` })
  })

  test('Fleet filter bar renders search + framework + status + flagged controls', async ({ page }) => {
    await gotoFleet(page)
    const filters = page.getByTestId('fleet-filters')
    await expect(filters).toBeVisible()

    // Sentinel controls per hi-fi.
    await expect(page.getByTestId('fleet-filter-search')).toBeVisible()
    await expect(page.getByTestId('fleet-filter-framework-all')).toBeVisible()
    await expect(page.getByTestId('fleet-filter-status-all')).toBeVisible()
    await expect(page.getByTestId('fleet-filter-flagged')).toBeVisible()

    await filters.screenshot({ path: `${EVIDENCE_DIR}/03-fleet-filter-bar.png` })
  })

  test('Fleet table sticky header carries the hi-fi tokens', async ({ page }) => {
    await gotoFleet(page)
    const table = page.getByTestId('agents-table')
    await expect(table).toBeVisible()

    // 11 columns: select + 9 data + actions.
    const headerCells = page.locator('.fleet-table__th')
    expect(await headerCells.count()).toBe(11)

    // Sort indicators present for sortable columns.
    await expect(page.getByTestId('fleet-sort-name')).toBeVisible()
    await expect(page.getByTestId('fleet-sort-framework')).toBeVisible()
    await expect(page.getByTestId('fleet-sort-status')).toBeVisible()

    // Header background: paper-2 (sticky thead chrome).
    const headBg = await headerCells.first().evaluate(
      (el) => getComputedStyle(el).backgroundColor,
    )
    expect(headBg).toBe(TOKENS.paper2)

    await table.screenshot({ path: `${EVIDENCE_DIR}/04-fleet-table-chrome.png` })
  })

  test('Fleet flagged row picks up the danger-tinted background', async ({ page }) => {
    await gotoFleet(page)
    // gamma-bot is flagged; its row should carry the flagged modifier.
    const flaggedRow = page.locator('.fleet-table__row--flagged').first()
    await expect(flaggedRow).toBeVisible()
    const bg = await flaggedRow.evaluate(
      (el) => getComputedStyle(el as Element).backgroundColor,
    )
    // Hi-fi: rgba(184, 41, 30, 0.04) — soft red wash.
    expect(bg).toMatch(/rgba?\(184,\s*41,\s*30/)

    await flaggedRow.screenshot({ path: `${EVIDENCE_DIR}/05-fleet-flagged-row.png` })
  })

  test('Fleet bulk action bar appears with all four hi-fi buttons', async ({ page }) => {
    await gotoFleet(page)
    await page.getByTestId('fleet-select-all').click()
    const bar = page.getByTestId('fleet-bulkbar')
    await expect(bar).toBeVisible()
    await expect(page.getByTestId('fleet-bulkbar-count')).toContainText('selected')
    await expect(page.getByTestId('fleet-bulkbar-shadow')).toBeVisible()
    await expect(page.getByTestId('fleet-bulkbar-suspend')).toBeVisible()
    await expect(page.getByTestId('fleet-bulkbar-resume')).toBeVisible()
    await expect(page.getByTestId('fleet-bulkbar-clear')).toBeVisible()

    // Suspend button is the only danger-styled one.
    const suspendBg = await page.getByTestId('fleet-bulkbar-suspend').evaluate(
      (el) => getComputedStyle(el).backgroundColor,
    )
    expect(suspendBg).toBe(TOKENS.danger)

    await bar.screenshot({ path: `${EVIDENCE_DIR}/06-fleet-bulkbar.png` })
  })

  test('Agent Detail drawer renders head + identity strip + tabs', async ({ page }) => {
    await gotoFleet(page)
    await page.getByTestId('agent-row').first().click()
    await page.getByTestId('drawer-panel').waitFor()

    // Drawer panel is 580 px wide per hi-fi (581 px once the 1 px left
    // border is included in `getBoundingClientRect`).
    const panelWidth = await page.getByTestId('drawer-panel').evaluate(
      (el) => (el as HTMLElement).getBoundingClientRect().width,
    )
    expect(panelWidth).toBeGreaterThanOrEqual(580)
    expect(panelWidth).toBeLessThanOrEqual(581)

    // Head section.
    await page.locator('.ad-head').screenshot({ path: `${EVIDENCE_DIR}/07-detail-head.png` })

    // Identity strip — 5-column grid (1.2fr 1fr 1fr 1fr 1fr).
    const strip = page.getByTestId('agent-detail-identity')
    await expect(strip).toBeVisible()
    const tracks = await strip.evaluate(
      (el) => getComputedStyle(el as Element).gridTemplateColumns.split(/\s+/).filter(Boolean),
    )
    expect(tracks.length).toBe(5)
    await strip.screenshot({ path: `${EVIDENCE_DIR}/08-detail-identity-strip.png` })

    // Tab navigation — 6 tabs.
    const tabs = page.getByTestId('agent-detail-tabs')
    await expect(tabs).toBeVisible()
    expect(await tabs.locator('.ad-tabs__tab').count()).toBe(6)
    await tabs.screenshot({ path: `${EVIDENCE_DIR}/09-detail-tabs.png` })
  })

  test('Agent Detail Overview tab posture + traffic + events cards', async ({ page }) => {
    await gotoFleet(page)
    await page.getByTestId('agent-row').first().click()
    await page.getByTestId('agent-detail-body').waitFor()

    const body = page.getByTestId('agent-detail-body')
    await expect(page.getByTestId('agent-detail-posture')).toBeVisible()
    await expect(page.getByTestId('agent-detail-traffic-mix')).toBeVisible()
    await expect(page.getByTestId('agent-events')).toBeVisible()
    // Mini-bars: Allow / Narrow / Deny / Approval.
    expect(await body.locator('.ad-minibar').count()).toBe(4)

    await body.screenshot({ path: `${EVIDENCE_DIR}/10-detail-overview.png` })
  })

  test('Agent Detail follow-up tabs render the empty-state callout', async ({ page }) => {
    await gotoFleet(page)
    await page.getByTestId('agent-row').first().click()
    await page.getByTestId('agent-detail-tab-capability').click()
    const callout = page.getByTestId('ad-tab-empty-capability')
    await expect(callout).toBeVisible()
    await callout.screenshot({ path: `${EVIDENCE_DIR}/11-detail-tab-empty.png` })
  })

  test('Suspend reason dialog renders with required-field validation', async ({ page }) => {
    await gotoFleet(page)
    await page.getByTestId('agent-row').first().click()
    // AAASM-1405 portalled the Drawer to `document.body`, so the drawer
    // head now paints above the AppShell topbar and a real pointer click
    // reaches the suspend button.
    await page.getByTestId('agent-detail-suspend').click()
    const dialog = page.getByTestId('suspend-dialog')
    await expect(dialog).toBeVisible()

    // Confirm disabled until reason is non-empty.
    await expect(page.getByTestId('suspend-dialog-confirm')).toBeDisabled()
    await page.getByTestId('suspend-dialog-input').fill('budget exceeded')
    await expect(page.getByTestId('suspend-dialog-confirm')).toBeEnabled()

    await dialog.screenshot({ path: `${EVIDENCE_DIR}/12-suspend-dialog.png` })
  })

  test('Full-page screenshots for Fleet + Agent Detail context', async ({ page }) => {
    await gotoFleet(page)
    await page.screenshot({ path: `${EVIDENCE_DIR}/00-fleet-fullpage.png`, fullPage: true })

    await page.getByTestId('agent-row').first().click()
    await page.getByTestId('drawer-panel').waitFor()
    await page.screenshot({ path: `${EVIDENCE_DIR}/00-detail-fullpage.png`, fullPage: true })
  })
})
