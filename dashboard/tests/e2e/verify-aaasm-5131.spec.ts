/**
 * Verification pass for the agent-detail posture summary — AAASM-5131.
 *
 * The unit tests mock `capabilityClient`, so they prove the *panel* reacts to an
 * absence. They cannot prove the wiring: that a real HTTP 503 travelling through
 * `openapi-fetch` and TanStack Query still reaches the operator as "unavailable"
 * rather than as a posture. That is what this run drives, over the network
 * layer, in a real browser.
 *
 * Two scenarios, each in light and dark:
 *
 *  1. **healthy** — the capability matrix loads with a resolved policy document.
 *     Allow and Deny render as counts of real cells; Narrow and Approval still
 *     render `—`, because the projection emits only `allow` / `deny` / `na` and
 *     no amount of healthy data changes that.
 *  2. **degraded** — `/capability/matrix` returns 503. Nothing on the panel may
 *     read as a posture: no `0`, no filled bar, no clean bill of health.
 *
 * `page.route` is used rather than a `fetch` shim because the generated client
 * captures `globalThis.fetch` at module load; a shim installed later would never
 * be consulted. The auth token is seeded via `addInitScript` for the same reason
 * — it has to exist before any module body runs.
 *
 * Screenshots land in dashboard/verify/5131/.
 */
import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5131')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const AGENT_ID = 'research-bot-04'

/**
 * `session_count` and `policy_violations_count` are deliberately large and
 * unequal: the panel used to render `Allow = 1421 − 63` and `Deny = 63`, so if
 * either number appears anywhere in the posture card the old derivation is back.
 */
const AGENT = {
  id: AGENT_ID,
  name: 'research-bot-04',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 1421,
  policy_violations_count: 63,
  tool_names: ['gmail.send'],
  metadata: { owner: 'alice', mode: 'enforce' },
  pid: null,
}

const RESOURCES = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: ['gmail/*'] },
  { id: 'pg', name: 'Postgres', group: 'data', paths: ['pg.public.*'] },
]

/** Two allow cells and three deny cells; every other verb is `na`. */
const MATRIX = {
  resources: RESOURCES,
  sampleCalls: [],
  policies: [
    {
      id: 'P-001',
      name: 'global default-deny',
      version: '1',
      scope: 'global',
      status: 'active',
      affects: [AGENT_ID],
      rules: [],
    },
  ],
  agents: [
    {
      id: AGENT_ID,
      name: 'research-bot-04',
      framework: 'langgraph',
      owner: 'alice',
      trust: null,
      mode: 'enforce',
      status: 'active',
      lastSeen: '2m ago',
      caps: {
        gmail: { read: 'allow', write: 'deny', delete: 'na', exec: 'na' },
        pg: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
      },
    },
  ],
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme, degraded: boolean): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberate 503 below makes the browser log a resource failure; that is
    // the fixture doing its job, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5131')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Broadest → narrowest (Playwright matches most-recently-registered first).
  await page.route('**/api/v1/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) => r.fulfill({ json: { ticket: 'e2e-ticket' } }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: [AGENT], total: 1 } }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/subtree-burn**`, (r) =>
    r.fulfill({ json: { total: 0, daily: [], children: [] } }),
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}`, (r) => r.fulfill({ json: AGENT }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())

  await page.route('**/api/v1/capability/matrix**', (r) =>
    degraded
      ? r.fulfill({
          status: 503,
          contentType: 'application/json',
          body: '{"error":"service_unavailable"}',
        })
      : r.fulfill({ json: MATRIX }),
  )

  return { errors }
}

/**
 * Open the drawer through the Fleet route.
 *
 * The production build emits relative asset paths that 404 on a deep link like
 * `/agents/:id`, so the single-segment route is loaded first and the drawer
 * opened with a row click.
 */
async function openAgentDetail(page: Page) {
  await page.goto('/agents')
  await page.getByTestId('fleet-row-name').first().click()
  await expect(page.getByTestId('agent-detail')).toBeVisible()
  await expect(page.getByTestId('agent-detail-posture')).toBeVisible()
}

/** Visible text with the screen-reader sentence removed. */
async function visibleText(page: Page, testId: string): Promise<string> {
  return page.getByTestId(testId).evaluate((el) => {
    const clone = el.cloneNode(true) as HTMLElement
    clone.querySelectorAll('.truth-sr-only').forEach((n) => n.remove())
    return clone.textContent?.trim() ?? ''
  })
}

test.describe('AAASM-5131 — agent-detail posture asserts only what it measured', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`healthy matrix — allow and deny are counted, narrow and approval stay absent (${theme})`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, false)
      await openAgentDetail(page)

      const posture = page.getByTestId('agent-detail-posture')

      // ── Allow and Deny are counts of real capability cells ───────────────
      await expect(page.getByTestId('agent-posture-allow')).toHaveAttribute(
        'data-truth-state',
        'known',
        { timeout: 20_000 },
      )
      expect(await visibleText(page, 'agent-posture-allow')).toBe('2')
      expect(await visibleText(page, 'agent-posture-deny')).toBe('3')

      // ── The old derivation must be gone from the surface entirely ────────
      // 1421 sessions − 63 violations was the previous "Allow"; 63 was "Deny".
      await expect(posture).not.toContainText('1358')
      await expect(posture).not.toContainText('1421')
      await expect(posture).not.toContainText('63')

      // ── The two the projection can never emit ────────────────────────────
      for (const row of ['agent-posture-narrow', 'agent-posture-approval']) {
        await expect(page.getByTestId(row)).toHaveAttribute('data-truth-state', 'not-supported')
        expect(await visibleText(page, row)).toBe('—')
      }
      // No bar is drawn for them either — a zero-width fill is what a measured
      // zero looks like.
      await expect(
        page.getByTestId('agent-posture-narrow-row').locator('.ad-minibar__fill'),
      ).toHaveCount(0)
      await expect(posture).toContainText('decided per action by other policy stages')

      await expect(posture).not.toContainText('undefined')
      await expect(posture).not.toContainText('NaN')

      await posture.screenshot({ path: `${EVIDENCE_DIR}/posture-healthy-${theme}.png` })
      await page.screenshot({
        path: `${EVIDENCE_DIR}/agent-detail-healthy-${theme}.png`,
        fullPage: true,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`a failed matrix request renders unavailable, not a posture (${theme})`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, true)
      await openAgentDetail(page)

      const posture = page.getByTestId('agent-detail-posture')

      // The app's QueryClient takes TanStack's defaults, so the 503 is retried
      // three times with exponential backoff (~7s) before the query settles as
      // an error. Both halves of that window matter: *while retrying* the panel
      // must already refuse to claim a posture, and *once settled* the absence
      // must sharpen from "unknown" (in flight) to "unavailable" (it failed).
      await expect(page.getByTestId('agent-posture-allow')).not.toHaveAttribute(
        'data-truth-state',
        'known',
      )
      expect(await visibleText(page, 'agent-posture-allow')).toBe('—')

      await expect(page.getByTestId('agent-posture-allow')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
        { timeout: 30_000 },
      )
      await expect(page.getByTestId('agent-posture-deny')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      )

      // Every figure is a dash, no bar is drawn, and the failure is announced.
      for (const row of ['allow', 'narrow', 'deny', 'approval']) {
        expect(await visibleText(page, `agent-posture-${row}`)).toBe('—')
      }
      await expect(posture.locator('.ad-minibar__fill')).toHaveCount(0)
      await expect(posture).toContainText('the request for this value failed')
      await expect(posture).not.toContainText('0')

      await posture.screenshot({ path: `${EVIDENCE_DIR}/posture-unavailable-${theme}.png` })
      await page.screenshot({
        path: `${EVIDENCE_DIR}/agent-detail-unavailable-${theme}.png`,
        fullPage: true,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
