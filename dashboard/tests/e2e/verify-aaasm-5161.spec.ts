/**
 * Verification capture for AAASM-5161 — Fleet "Blocked / 24h" / "Scrubbed /
 * 24h" columns lose their right-alignment and severity colouring.
 *
 * Stands the real dashboard up against a mocked `/api/v1/agents` list plus
 * `/api/v1/analytics/agent-enforcement`, seeded with agents that cross both
 * thresholds (`blocked24h > 50`, `scrubbed24h > 0`) plus a neutral agent and
 * an agent absent from the enforcement fixture, so one screenshot shows all
 * the states the fix touches:
 *   - the two numeric columns forming a right-aligned, scannable edge
 *   - `blocked24h > 50` rendered in the danger tone at weight 600
 *   - `scrubbed24h > 0` rendered in the scrub tone
 *   - the neutral / absent cases staying untoned
 *
 * Screenshots land in dashboard/verify/5161/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5161')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// Stable agent ids (32-char lower-hex, matching the real AgentResponse.id form).
const ID_DANGER = 'd1'.repeat(16)
const ID_SCRUB = 's2'.repeat(16)
const ID_NEUTRAL = 'n3'.repeat(16)
const ID_ABSENT = 'a4'.repeat(16)

function agent(id: string, name: string, framework: string, overrides: Record<string, unknown> = {}) {
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
    ...overrides,
  }
}

const AGENTS = [
  agent(ID_DANGER, 'checkout-agent', 'langgraph'), // blocked24h > 50 -> danger tone
  agent(ID_SCRUB, 'refund-agent', 'crewai'), // scrubbed24h > 0 -> scrub tone
  agent(ID_NEUTRAL, 'audit-agent', 'autogen'), // both counts present but below threshold -> untoned
  agent(ID_ABSENT, 'quiet-agent', 'langgraph'), // absent from enforcement fixture -> renders —
]

// `GET /api/v1/analytics/agent-enforcement` returns a bare array of
// { agent_id, blocked, scrubbed }. ID_ABSENT is intentionally omitted.
const ENFORCEMENT = [
  { agent_id: ID_DANGER, blocked: 63, scrubbed: 0 },
  { agent_id: ID_SCRUB, blocked: 4, scrubbed: 9 },
  { agent_id: ID_NEUTRAL, blocked: 12, scrubbed: 0 },
]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5161')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific) so unmatched reads never 500 the
  // page; specific fixtures registered afterwards win (Playwright matches
  // most-recently-added first).
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => r.fulfill({ json: ENFORCEMENT }))
  await page.route('**/api/v1/agents**', (r) => {
    const url = new URL(r.request().url())
    const m = /\/api\/v1\/agents\/([0-9a-f]+)/.exec(url.pathname)
    if (m) {
      const found = AGENTS.find((a) => a.id === m[1]) ?? AGENTS[0]
      return r.fulfill({ json: found })
    }
    return r.fulfill({ json: { items: AGENTS, total: AGENTS.length } })
  })
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
}

test.describe('AAASM-5161 — Fleet enforcement column alignment + tone', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`Blocked/Scrubbed columns are right-aligned and correctly toned in ${theme}`, async ({ page }) => {
      await bootstrap(page, theme)

      await page.goto('/agents')
      await page.getByTestId('agents-table').waitFor()

      const dangerCell = page
        .locator('[data-testid="agent-row"]', { hasText: 'checkout-agent' })
        .getByText('63', { exact: true })
      await expect(dangerCell).toHaveClass(/fleet-table__numeric--danger/)

      const scrubCell = page
        .locator('[data-testid="agent-row"]', { hasText: 'refund-agent' })
        .getByText('9', { exact: true })
      await expect(scrubCell).toHaveClass(/fleet-table__numeric--scrub/)

      const neutralRow = page.locator('[data-testid="agent-row"]', { hasText: 'audit-agent' })
      const neutralBlocked = neutralRow.getByText('12', { exact: true })
      await expect(neutralBlocked).not.toHaveClass(/fleet-table__numeric--danger/)

      const absentRow = page.locator('[data-testid="agent-row"]', { hasText: 'quiet-agent' })
      await expect(absentRow).toContainText('—')

      // Right-alignment: the numeric `<td>` right edge should line up with the
      // header cell's right edge for both columns (AAASM-5161's core defect was
      // the span shrink-wrapping instead of the cell right-aligning).
      const blockedHeader = page.getByTestId('fleet-sort-blocked24h').locator('..')
      const blockedCell = dangerCell.locator('xpath=ancestor::td[1]')
      const headerBox = await blockedHeader.boundingBox()
      const cellBox = await blockedCell.boundingBox()
      expect(headerBox).not.toBeNull()
      expect(cellBox).not.toBeNull()
      if (headerBox && cellBox) {
        expect(Math.abs(headerBox.x + headerBox.width - (cellBox.x + cellBox.width))).toBeLessThan(2)
      }

      await page.screenshot({ path: `${EVIDENCE_DIR}/fleet-${theme}.png`, fullPage: true })
    })
  }
})
