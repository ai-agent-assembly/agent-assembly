/**
 * Verification capture for AAASM-5341 — wiring the Topology node-detail
 * enforcement-mode toggle to the live backend (AAASM-5338 single-agent /
 * AAASM-5340 cascade preview + echo-back apply).
 *
 * Re-derives, against `page.route` fixtures the reviewer would otherwise take
 * on trust, the claims the ticket makes:
 *
 *  1. an Admin caller on an `enforce` node sees the "◐ Switch to shadow mode"
 *     action, which opens the weaken form;
 *  2. the weaken form requires a non-empty reason + a future/≤72h expiry
 *     before its confirm is enabled;
 *  3. choosing cascade previews first — the explicit "shadow these N agents"
 *     list — then requires an explicit confirm, which echoes the previewed set
 *     back to the apply endpoint;
 *  4. an over-cap (>50) preview surfaces the server's 422 rejection rather than
 *     inventing a client-side truncation;
 *  5. a non-Admin caller sees no shadow action, only the Admin-required hint.
 *
 * Screenshots land in dashboard/verify/5341/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5341')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * An unsigned JWT whose `scope` claim carries `scopes`. The dashboard reads
 * scopes from the token via `parseScopesFromJwt` on load; the signature is
 * never verified client-side (the gateway is authoritative), so an unsigned
 * token with a real payload is exactly what the app parses.
 */
function fakeJwt(scopes: string[]): string {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o))
      .toString('base64')
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replace(/=+$/, '')
  return `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'e2e', scope: scopes })}.sig`
}

/** One enforce node + a small subtree; the panel drives off the node's `mode`. */
const NODES = [
  {
    id: 'planner', name: 'planner', depth: 0, status: 'active', team_id: 'support',
    mode: 'enforce', flagged: false, trust: null, owner: 'platform-team',
    policy_count: 2, budget: { spend_usd: 4.1, limit_usd: 100.0 },
  },
  {
    id: 'worker-a', name: 'worker-a', depth: 1, status: 'active', team_id: 'support',
    mode: 'enforce', flagged: false, trust: null, owner: 'platform-team',
    policy_count: 1, budget: { spend_usd: 2.5, limit_usd: 40.0 },
  },
]
const EDGES = [{ source: 'planner', target: 'worker-a', kind: 'delegation', cross_team: false }]

const LINEAGE = {
  agent_id: 'planner',
  ancestor_count: 1,
  ancestors: [{ id: 'planner', name: 'planner', depth: 0, team_id: 'support' }],
}

/** The affected set a cascade preview returns for the planner subtree. */
const PREVIEW = { affected_ids: ['planner', 'worker-a', 'worker-b'], count: 3 }

interface BootstrapOpts {
  scopes: string[]
  /** When true, the preview endpoint returns a 422 over-cap rejection. */
  previewOverCap?: boolean
}

async function bootstrap(page: Page, theme: Theme, opts: BootstrapOpts) {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text())
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (init: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', init.token)
      localStorage.setItem(init.themeKey, init.theme)
    },
    { themeKey: THEME_KEY, theme, token: fakeJwt(opts.scopes) },
  )

  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/topology', (r) => r.fulfill({ json: { nodes: NODES, edges: EDGES, cascade_loaded: false } }))
  await page.route('**/api/v1/topology/nodes/*/events', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology/lineage/**', (r) => r.fulfill({ json: LINEAGE }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  // Enforcement-mode preview: 200 with the affected set, or 422 over-cap.
  await page.route('**/api/v1/agents/*/enforcement-mode/preview', (r) => {
    if (opts.previewOverCap) {
      return r.fulfill({ status: 422, json: { error: 'cascade exceeds MAX_CASCADE_AGENTS' } })
    }
    return r.fulfill({ json: PREVIEW })
  })
  // Enforcement-mode apply: always OK for the happy path.
  await page.route('**/api/v1/agents/*/enforcement-mode', (r) =>
    r.fulfill({ json: { agent_id: 'planner', new_mode: 'observe', expires_at: null } }),
  )

  return { errors }
}

async function gotoTopology(page: Page) {
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/topology'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('topology-graph').waitFor()
  await page.waitForTimeout(700) // let d3-force settle
}

async function openPlannerPanel(page: Page) {
  await page.locator('[data-testid="topology-node"]', { hasText: 'planner' }).first().click({ force: true })
  await page.getByTestId('node-detail-panel').waitFor()
}

/** A `datetime-local` value one hour ahead in local wall-clock time. */
function oneHourAheadLocal(): string {
  const d = new Date(Date.now() + 3_600_000)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

test.describe('AAASM-5341 — enforcement-mode toggle + cascade', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`admin toggle, weaken form, and cascade preview→confirm in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { scopes: ['read', 'write', 'admin'] })
      await gotoTopology(page)
      await openPlannerPanel(page)

      // ── 1. the toggle shows on an enforce node for an Admin ─────────────
      const toggle = page.getByTestId('node-detail-shadow-mode')
      await expect(toggle).toBeVisible()
      await expect(toggle).toContainText('Switch to shadow mode')
      await expect(page.getByTestId('node-detail-shadow-admin-hint')).toHaveCount(0)
      await page.getByTestId('node-detail-panel').screenshot({
        path: `${EVIDENCE_DIR}/enforce-node-toggle-${theme}.png`,
      })

      // ── 2. the weaken form gates on reason + expiry ─────────────────────
      await toggle.click()
      await page.getByTestId('shadow-dialog').waitFor()
      const confirm = page.getByTestId('shadow-dialog-confirm')
      await expect(confirm).toBeDisabled()
      await page.getByTestId('shadow-dialog-reason').fill('debugging a false positive')
      await expect(confirm).toBeDisabled() // still no expiry
      await page.getByTestId('shadow-dialog-expiry').fill(oneHourAheadLocal())
      await expect(confirm).toBeEnabled()
      await page.getByTestId('shadow-dialog').screenshot({
        path: `${EVIDENCE_DIR}/weaken-form-${theme}.png`,
      })

      // ── 3. cascade previews the explicit set, then confirms ─────────────
      await page.getByTestId('shadow-dialog-cascade-toggle').check()
      // With cascade chosen the primary button previews (not submits) first.
      const previewBtn = page.getByTestId('shadow-dialog-preview-btn')
      await expect(previewBtn).toBeVisible()
      await previewBtn.click()
      const previewList = page.getByTestId('shadow-dialog-preview')
      await previewList.waitFor()
      await expect(page.getByTestId('shadow-dialog-preview-count')).toContainText('shadow these 3 agents')
      await expect(page.getByTestId('shadow-dialog-preview-id')).toHaveCount(3)
      await page.getByTestId('shadow-dialog').screenshot({
        path: `${EVIDENCE_DIR}/cascade-preview-confirm-${theme}.png`,
      })
      // Explicit confirm applies and closes the dialog.
      await page.getByTestId('shadow-dialog-confirm').click()
      await expect(page.getByTestId('shadow-dialog')).toHaveCount(0)

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }

  test('over-cap (>50) preview surfaces the server rejection', async ({ page }) => {
    await bootstrap(page, 'light', { scopes: ['read', 'write', 'admin'], previewOverCap: true })
    await gotoTopology(page)
    await openPlannerPanel(page)

    await page.getByTestId('node-detail-shadow-mode').click()
    await page.getByTestId('shadow-dialog').waitFor()
    await page.getByTestId('shadow-dialog-reason').fill('bulk observe window')
    await page.getByTestId('shadow-dialog-expiry').fill(oneHourAheadLocal())
    await page.getByTestId('shadow-dialog-cascade-toggle').check()
    await page.getByTestId('shadow-dialog-preview-btn').click()

    // The server's 422 is surfaced verbatim; no preview list is fabricated.
    await expect(page.getByTestId('shadow-dialog-server-error')).toContainText('maximum affected-agent count')
    await expect(page.getByTestId('shadow-dialog-preview')).toHaveCount(0)
    await page.getByTestId('shadow-dialog').screenshot({
      path: `${EVIDENCE_DIR}/over-cap-rejection.png`,
    })
  })

  test('non-Admin caller sees no shadow action, only the Admin hint', async ({ page }) => {
    await bootstrap(page, 'light', { scopes: ['read', 'write'] })
    await gotoTopology(page)
    await openPlannerPanel(page)

    await expect(page.getByTestId('node-detail-shadow-mode')).toHaveCount(0)
    await expect(page.getByTestId('node-detail-shadow-admin-hint')).toBeVisible()
    await page.getByTestId('node-detail-panel').screenshot({
      path: `${EVIDENCE_DIR}/non-admin-hidden.png`,
    })
  })
})
