/**
 * Verification capture for AAASM-5317 — wire the trust score into the dashboard.
 *
 * Stands the real dashboard up against a mocked `/api/v1/agents` list plus the
 * `GET /api/v1/analytics/trust` fixture (AAASM-5083), and captures the two
 * surfaces the ticket wires from the rollup:
 *   - the Fleet "Trust" column (a filled TrustBar for a scored agent, `—` for a
 *     cold-start agent whose score the endpoint reports as `null`), and
 *   - the Agent-Detail trust gauge (real score + the "under your configured
 *     weights" framing, or `—` for cold start).
 *
 * Agent A has a real score (~78), agent B is cold-start (`trust: null`), and a
 * third agent is omitted from the fixture entirely — all three must render
 * honestly (78 / — / —), never a coerced 0 or 50.
 *
 * Screenshots land in dashboard/verify/5317/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5317')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// Stable agent ids (32-char lower-hex, matching the real AgentResponse.id form).
const ID_A = 'a1'.repeat(16)
const ID_B = 'b2'.repeat(16)
const ID_C = 'c3'.repeat(16)

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
    is_flagged: false,
    tool_names: [],
    metadata: { owner: 'platform-team', mode: 'enforce' },
    pid: null,
    ...overrides,
  }
}

const AGENTS = [
  agent(ID_A, 'checkout-agent', 'langgraph'),
  agent(ID_B, 'refund-agent', 'crewai'),
  agent(ID_C, 'quiet-agent', 'autogen'), // absent from trust fixture -> renders —
]

// `GET /api/v1/analytics/trust` returns a TrustResponse (AAASM-5083). Agent A
// has a real score; agent B is cold-start (`trust: null`); agent C is omitted.
const TRUST = {
  agents: [
    { agent_id: ID_A, trust: 78 },
    { agent_id: ID_B, trust: null },
  ],
  minActions: 20,
  truncated: false,
  weights: {
    approval_rejection: { enabled: true, weight: 0.5 },
    credential_redaction: { enabled: true, weight: 1.5 },
    policy_violation: { enabled: true, weight: 1.0 },
  },
  window: '7d',
}

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5317')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures added after
  // win (Playwright matches most-recently-added first).
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/analytics/trust**', (r) => r.fulfill({ json: TRUST }))
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

test.describe('AAASM-5317 — trust score wired into the dashboard', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`Fleet TrustBar + Agent-Detail gauge render the real score in ${theme}`, async ({ page }) => {
      await bootstrap(page, theme)

      // --- Fleet: the Trust column now carries the real rollup score. ---
      await page.goto('/agents')
      await page.getByTestId('agents-table').waitFor()

      const rowA = page.locator('[data-testid="agent-row"]', { hasText: 'checkout-agent' })
      // A filled bar renders its numeric value; the cold-start / absent agents
      // keep the em-dash — never a coerced 0.
      await expect(rowA.getByTestId('fleet-trust')).toHaveText('78')

      const rowB = page.locator('[data-testid="agent-row"]', { hasText: 'refund-agent' })
      await expect(rowB.getByTestId('fleet-trust')).toHaveText('—') // cold start (null)

      const rowC = page.locator('[data-testid="agent-row"]', { hasText: 'quiet-agent' })
      await expect(rowC.getByTestId('fleet-trust')).toHaveText('—') // absent from fixture

      await page.screenshot({ path: `${EVIDENCE_DIR}/fleet-${theme}.png`, fullPage: true })

      // --- Agent-Detail: the trust gauge now shows the real score + the ADR
      // 0019 "under your configured weights" framing. Navigate client-side by
      // clicking the row (a hard load of the nested route 404s under base './'). ---
      await rowA.getByTestId('fleet-row-name').click()
      await page.getByTestId('agent-detail-identity').waitFor()
      const gauge = page.getByTestId('agent-detail-identity')
      await expect(gauge).toContainText('78')
      await expect(page.getByTestId('agent-detail-trust-weights')).toHaveText('under your configured weights')
      await page.screenshot({ path: `${EVIDENCE_DIR}/agent-detail-scored-${theme}.png`, fullPage: true })

      // --- Agent-Detail for the cold-start agent: the gauge renders `—`. ---
      await page.goto('/agents')
      await page.getByTestId('agents-table').waitFor()
      await page
        .locator('[data-testid="agent-row"]', { hasText: 'refund-agent' })
        .getByTestId('fleet-row-name')
        .click()
      await page.getByTestId('agent-detail-identity').waitFor()
      await page.screenshot({ path: `${EVIDENCE_DIR}/agent-detail-coldstart-${theme}.png`, fullPage: true })
    })
  }
})
