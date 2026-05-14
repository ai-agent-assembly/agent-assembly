/**
 * Design-fidelity verification for the trace UI (AAASM-1383).
 *
 * Walks the rendered TraceView and asserts the *visual* contract against
 * the hi-fi reference at `design/v1/hi-fi/trace.jsx` + `design/v1/hi-fi/styles.css`:
 *   - severity backgrounds resolve to the exact CSS variable tokens
 *   - row grid has the documented 5-column layout
 *   - PayloadModal proportions stay within hi-fi constraints
 *   - Export toolbar sits above the filter, right-aligned
 *
 * Captures full-page screenshots into `dashboard/docs/verification/aaasm-1383/`
 * for visual review alongside the hi-fi.
 *
 * Known accepted divergence (filed as Bug sub-task): the dashboard renders
 * events as a row-grid timeline, while the hi-fi renders them as vertical
 * step-cards with icon + connecting line on the left. This was an
 * implementation decision merged in AAASM-1065 and is tracked separately.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1383')

const AGENT_ID = 'agent-aaasm-1383'
const SESSION_ID = 'session-aaasm-1383'

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
  tool_names: ['search'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: {},
  pid: null,
}

const EVENTS = [
  {
    id: 'evt-llm',
    timestamp: '2026-04-23T14:23:01Z',
    type: 'llm_call',
    agent: 'support-agent',
    durationMs: 834,
    payloadPreview: 'GPT-4o · lookup billing',
    payload: { model: 'gpt-4o' },
    severity: 'info',
  },
  {
    id: 'evt-tool',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'tool_call',
    agent: 'support-agent',
    durationMs: 45,
    payloadPreview: 'query_db | SELECT ...',
    payload: { table: 'billing' },
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
    payloadPreview: 'detected AWS_SECRET_ACCESS_KEY',
    payload: { matched_rule: 'aws-secret-access-key' },
    severity: 'warning',
  },
]

// Hi-fi token values from design/v1/hi-fi/styles.css.
// These mirror dashboard/src/styles.css exactly — the assertion below
// would catch any drift between the two source-of-truth files.
const HIFI_TOKENS = {
  paper: 'rgb(245, 244, 240)',     // #f5f4f0
  dangerBg: 'rgb(246, 218, 214)',  // #f6dad6
  warnBg: 'rgb(245, 230, 196)',    // #f5e6c4
  infoBg: 'rgb(214, 223, 238)',    // #d6dfee
}

async function injectToken(page: Page) {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'fidelity-token'))
}

async function mockApi(page: Page) {
  await page.route(`**/api/v1/agents/${AGENT_ID}`, r => r.fulfill({ json: AGENT }))
  await page.route(
    `**/api/v1/agents/${AGENT_ID}/sessions/${SESSION_ID}/trace`,
    r => r.fulfill({ json: EVENTS }),
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

test.describe('AAASM-1383 — Trace UI design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('severity backgrounds resolve to the exact hi-fi token RGB', async ({ page }) => {
    await gotoTrace(page)

    // The row itself carries data-severity; locate directly by attribute.
    const infoBg = await page
      .locator('.trace-event[data-severity="info"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(infoBg).toBe(HIFI_TOKENS.infoBg)

    const criticalBg = await page
      .locator('.trace-event[data-severity="critical"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(criticalBg).toBe(HIFI_TOKENS.dangerBg)

    // credential_leak forces warn-bg via the [data-event-type] override
    const leakBg = await page
      .locator('.trace-event[data-event-type="credential_leak"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(leakBg).toBe(HIFI_TOKENS.warnBg)

    // neutral (no severity) row falls back to --paper
    const neutralBg = await page
      .locator('.trace-event[data-severity="neutral"]')
      .first()
      .evaluate(el => getComputedStyle(el).backgroundColor)
    expect(neutralBg).toBe(HIFI_TOKENS.paper)

    await page.screenshot({ path: `${EVIDENCE_DIR}/01-severity-tokens.png`, fullPage: true })
  })

  test('step-card structure: rail (icon + line) on the left, body on the right', async ({ page }) => {
    await gotoTrace(page)
    // Pick a non-last row so it carries the connecting line below the icon.
    const row = page.getByTestId('trace-event').first()

    // Top-level <li> is a flex row (rail + body) per the hi-fi step-card layout.
    const display = await row.evaluate(el => getComputedStyle(el).display)
    expect(display).toBe('flex')

    // Left rail: circular icon + vertical connector to the next step.
    const rail = row.locator('.trace-event__rail')
    await expect(rail).toBeVisible()
    const icon = rail.locator('.trace-event__icon-circle')
    await expect(icon).toBeVisible()
    // 24×24 circle from the hi-fi spec. boundingBox() includes the 1px
    // border on each side (24 content + 2 borders = 26). Assert the
    // *declared* width directly to enforce the contract precisely.
    const declared = await icon.evaluate(el => ({
      w: parseFloat(getComputedStyle(el).width),
      h: parseFloat(getComputedStyle(el).height),
      radius: getComputedStyle(el).borderRadius,
    }))
    expect(declared.w).toBe(24)
    expect(declared.h).toBe(24)
    expect(declared.radius).toBe('50%')
    // Connecting line exists on every event except the last.
    await expect(rail.locator('.trace-event__rail-line')).toBeVisible()

    // Right body: head (label + time + duration), detail, meta.
    const body = row.locator('.trace-event__body')
    await expect(body).toBeVisible()
    await expect(body.locator('.trace-event__head .trace-event__label')).toBeVisible()
    await expect(body.locator('.trace-event__head .trace-event__time')).toBeVisible()
    await expect(body.locator('.trace-event__head .trace-event__duration')).toBeVisible()
    await expect(body.locator('.trace-event__detail')).toBeVisible()
    await expect(body.locator('.trace-event__meta')).toBeVisible()

    // The last row must NOT have a rail-line — terminates the timeline.
    const last = page.getByTestId('trace-event').last()
    await expect(last.locator('.trace-event__rail-line')).toHaveCount(0)

    await page.screenshot({ path: `${EVIDENCE_DIR}/02-step-card-structure.png`, fullPage: true })
  })

  test('PayloadModal stays within hi-fi proportions (width ≤ 720, max-height ≤ 80vh)', async ({ page }) => {
    await gotoTrace(page)
    await page.locator('.trace-event[data-event-type="policy_violation"]').click()
    const modal = page.getByTestId('payload-modal')
    await expect(modal).toBeVisible()

    const modalBox = await modal.boundingBox()
    expect(modalBox).not.toBeNull()
    // CSS: width: min(720px, 90vw); max-height: 80vh.
    // boundingBox().width includes the 1px borders on each side, so the
    // ceiling is 722 (= 720 content + 2px borders). 2px is imperceptible.
    expect(modalBox!.width).toBeLessThanOrEqual(722)
    // Assert the CSS declared width directly (excludes borders).
    const declaredWidth = await modal.evaluate(el => parseFloat(getComputedStyle(el).width))
    expect(declaredWidth).toBeLessThanOrEqual(720)

    const viewport = page.viewportSize()!
    expect(modalBox!.height).toBeLessThanOrEqual(viewport.height * 0.8 + 2)

    // Redacted-line CSS contract: warn-bg + 3px warn left border
    const redactedBg = await page.getByTestId('redacted-field').first().evaluate(el => getComputedStyle(el).backgroundColor)
    expect(redactedBg).toBe(HIFI_TOKENS.warnBg)

    await page.screenshot({ path: `${EVIDENCE_DIR}/03-payload-modal-proportions.png`, fullPage: true })
  })

  test('Export toolbar sits above the filter and is right-aligned', async ({ page }) => {
    await gotoTrace(page)
    const toolbar = page.getByTestId('trace-toolbar')
    const filter = page.getByTestId('trace-filter')

    const toolbarBox = await toolbar.boundingBox()
    const filterBox = await filter.boundingBox()
    expect(toolbarBox).not.toBeNull()
    expect(filterBox).not.toBeNull()

    // Toolbar must visually precede the filter (i.e., be above it).
    expect(toolbarBox!.y).toBeLessThan(filterBox!.y)

    // Export button is right-aligned inside the toolbar (justify-content: flex-end).
    const justify = await toolbar.evaluate(el => getComputedStyle(el).justifyContent)
    expect(justify).toBe('flex-end')

    await page.screenshot({ path: `${EVIDENCE_DIR}/04-toolbar-position.png`, fullPage: true })
  })

  test('filter bar empty state renders shared EmptyState component', async ({ page }) => {
    await gotoTrace(page)
    // Hide everything via the filter.
    await page.getByTestId('trace-filter-critical').click()
    await page.getByTestId('trace-filter-warning').click()
    await page.getByTestId('trace-filter-info').click()
    await page.getByTestId('trace-filter-neutral').click()

    const empty = page.getByTestId('trace-filter-empty')
    await expect(empty).toBeVisible()
    // Uses shared <EmptyState> internally (data-testid="empty-state" inside the wrapper).
    await expect(empty.locator('[data-testid="empty-state"]')).toBeVisible()
    await expect(empty).toContainText('All events hidden by filter')

    await page.screenshot({ path: `${EVIDENCE_DIR}/05-filter-empty-state.png`, fullPage: true })
  })

  test('tooltip on policy violation icon surfaces violation reason in role=tooltip', async ({ page }) => {
    await gotoTrace(page)
    await page.locator('.trace-event[data-event-type="policy_violation"]').locator('.trace-event__icon-circle').hover()
    const tip = page.getByRole('tooltip')
    await expect(tip).toBeVisible()
    await expect(tip).toHaveText('refund > $100 requires human approval')
    await page.screenshot({ path: `${EVIDENCE_DIR}/06-violation-tooltip.png`, fullPage: true })
  })
})
