/**
 * Verification pass for the Overview truthfulness lane — AAASM-5113 / 5114 /
 * 5115 / 5116 / 5168.
 *
 * The unit tests mock the query hooks, so they prove the *component* reacts to
 * an absence. They cannot prove the wiring: that a real HTTP 503 travelling
 * through `openapi-fetch` and TanStack Query still reaches the operator as
 * "unavailable" rather than as a clean `0`. That is what this run drives, over
 * the network layer, in a real browser.
 *
 * Two scenarios, each in light and dark:
 *
 *  1. **healthy** — every query succeeds and every agent reports enforcement
 *     counts. The live figures render as numbers, but the two figures nothing
 *     computes (the L3 scrub posture score and "leaked") still render `—`, and
 *     the overall ring describes the mean it actually takes.
 *  2. **degraded** — `/approvals`, `/policies` and `/alerts` return 503 and the
 *     enforcement lookup omits an agent. Nothing on the page may read as a
 *     clean bill of health: no `0`, no "queue clear", no "No critical issues".
 *
 * `page.route` is used rather than a `fetch` shim because the generated client
 * captures `globalThis.fetch` at module load; a shim installed later would
 * never be consulted. The auth token is seeded via `addInitScript` for the same
 * reason — it has to exist before any module body runs.
 *
 * Screenshots land in dashboard/verify/5113/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5113')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

function makeAgent(id: string, name: string, violations = 0) {
  return {
    id,
    name,
    framework: 'langgraph',
    status: 'active',
    version: '0.1.0',
    layer: null,
    last_event: null,
    recent_events: [],
    recent_traces: [],
    active_sessions: [],
    session_count: 0,
    policy_violations_count: violations,
    tool_names: [],
    metadata: { mode: 'enforce' },
    registered_at: '2026-01-01T00:00:00Z',
    policy_id: null,
  }
}

const AGENTS = {
  items: [makeAgent('a1', 'research-bot'), makeAgent('a2', 'sales-outreach', 80)],
  page: 1,
  per_page: 100,
  total: 2,
}

/** Counts for both agents — the only case in which a fleet total is a measurement. */
const ENFORCEMENT_FULL = [
  { agent_id: 'a1', blocked: 4, scrubbed: 12 },
  { agent_id: 'a2', blocked: 1, scrubbed: 9 },
]

/** `a2` is missing, which is exactly what Fleet renders as `—`. */
const ENFORCEMENT_PARTIAL = [{ agent_id: 'a1', blocked: 4, scrubbed: 12 }]

const APPROVALS = { items: [{ id: 'ap-1' }, { id: 'ap-2' }], page: 1, per_page: 100, total: 2 }
const POLICIES = {
  items: [{ name: 'baseline', version: '1.0.0', active: true, rule_count: 3, policy_yaml: '' }],
  page: 1,
  per_page: 50,
  total: 1,
}
const ALERTS = {
  items: [
    {
      id: 'al-1',
      ruleId: 'r-1',
      ruleName: 'shell.exec blocked',
      severity: 'CRITICAL',
      status: 'FIRING',
      agentId: 'research-bot',
      firstFiredAt: '2026-07-26T14:02:08Z',
      resolvedAt: null,
      destinationIds: [],
    },
    {
      id: 'al-2',
      ruleId: 'r-2',
      ruleName: 'budget breach',
      severity: 'WARNING',
      status: 'FIRING',
      agentId: null,
      firstFiredAt: '2026-07-26T14:01:41Z',
      resolvedAt: null,
      destinationIds: [],
    },
  ],
  total: 2,
}

const TIMELINE = {
  window: '24h',
  bucketSecs: 3600,
  buckets: Array.from({ length: 24 }, () => ({ allow: 10, narrow: 2, deny: 1, scrub: 3, ts: 0 })),
}

interface Harness {
  errors: string[]
}

/** A 503 the app sees as a genuine transport failure. */
async function fulfil503(page: Page, pattern: string) {
  await page.route(pattern, (r) =>
    r.fulfill({ status: 503, contentType: 'application/json', body: '{"error":"service_unavailable"}' }),
  )
}

async function bootstrap(page: Page, theme: Theme, degraded: boolean): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberate 503s below make the browser log a resource failure; that is
    // the fixture doing its job, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5113')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/overview/enforcement-timeline**', (r) => r.fulfill({ json: TIMELINE }))
  await page.route('**/api/v1/analytics/agent-enforcement**', (r) =>
    r.fulfill({ json: degraded ? ENFORCEMENT_PARTIAL : ENFORCEMENT_FULL }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  if (degraded) {
    await fulfil503(page, '**/api/v1/approvals**')
    await fulfil503(page, '**/api/v1/policies**')
    await fulfil503(page, '**/api/v1/alerts**')
  } else {
    await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: APPROVALS }))
    await page.route('**/api/v1/policies**', (r) => r.fulfill({ json: POLICIES }))
    await page.route('**/api/v1/alerts**', (r) => r.fulfill({ json: ALERTS }))
  }

  return { errors }
}

async function openOverview(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/overview')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('overview-page')).toBeVisible()
}

/** Visible text with the screen-reader sentence removed. */
async function visibleText(page: Page, testId: string): Promise<string> {
  return page.getByTestId(testId).evaluate((el) => {
    const clone = el.cloneNode(true) as HTMLElement
    clone.querySelectorAll('.truth-sr-only').forEach((n) => n.remove())
    return clone.textContent?.trim() ?? ''
  })
}

test.describe('AAASM-5113 — Overview asserts only what it measured', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`healthy backend — live figures render, uncomputed ones stay absent (${theme})`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, false)
      await openOverview(page)

      // ── 5113: the L3 posture ring has no derivation, so it has no number ──
      const scrubRing = page.getByTestId('overview-ring-L3 · scrub')
      await expect(scrubRing).toHaveAttribute('data-truth-state', 'not-evaluated')
      await expect(scrubRing).not.toContainText('91')
      await expect(page.getByTestId('overview-ring-state-L3 · scrub')).toContainText('Not evaluated')

      // ── 5113: "leaked" was a hardcoded green zero ────────────────────────
      await expect(page.getByTestId('overview-leaked')).toHaveAttribute(
        'data-truth-state',
        'not-evaluated',
      )
      expect(await visibleText(page, 'overview-leaked')).toBe('—')

      // ── 5113: the overall ring describes the mean it actually takes ──────
      const overall = page.getByTestId('overview-ring-overall')
      await expect(overall).toHaveAttribute('data-truth-state', 'known')
      await expect(overall).toContainText('unweighted mean · L1 and L2')
      await expect(page.getByTestId('overview-page')).not.toContainText('weighted across all layers')

      // ── 5114: with every agent reporting, the totals are real numbers ────
      expect(await visibleText(page, 'overview-blocked')).toBe('5')
      expect(await visibleText(page, 'overview-stripped')).toBe('21')

      // ── 5115: a real queue length still renders, and a real empty is clear ─
      expect(await visibleText(page, 'overview-approval-count')).toBe('2')
      await expect(page.getByTestId('overview-approvals')).toContainText(
        'awaiting operator decision',
      )

      // ── 5116: the panel reports alerts as alerts ─────────────────────────
      const recent = page.getByTestId('overview-recent')
      await expect(recent).toContainText('recent alerts')
      await expect(recent).toContainText('critical')
      await expect(recent).toContainText('warning')
      for (const verdict of ['deny', 'narrow', 'scrub']) {
        await expect(recent).not.toContainText(verdict)
      }

      await expect(page.getByTestId('overview-page')).not.toContainText('undefined')
      await expect(page.getByTestId('overview-page')).not.toContainText('NaN')

      await page.getByTestId('overview-hero').screenshot({
        path: `${EVIDENCE_DIR}/hero-rings-healthy-${theme}.png`,
      })
      await page.screenshot({ path: `${EVIDENCE_DIR}/overview-healthy-${theme}.png`, fullPage: true })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`failed queries never become a clean bill of health (${theme})`, async ({ page }) => {
      const harness = await bootstrap(page, theme, true)
      await openOverview(page)

      // ── 5115 headline: a 503 on /approvals must not read as an empty queue ─
      //
      // The app's QueryClient takes TanStack's defaults, so a 503 is retried
      // three times with exponential backoff (~7s) before the query settles as
      // an error. Both halves of that window matter and are asserted here:
      // *while retrying* the page must already refuse to claim a clear queue,
      // and *once settled* the absence must sharpen from "unknown" (in flight)
      // to "unavailable" (the request failed). An earlier revision of this spec
      // only checked the settled state and would have passed a page that
      // rendered `0` for the first seven seconds.
      const approvals = page.getByTestId('overview-approvals')
      const count = page.getByTestId('overview-approval-count')
      await expect(count).not.toHaveAttribute('data-truth-state', 'known')
      await expect(approvals).not.toContainText('queue clear')
      expect(await visibleText(page, 'overview-approval-count')).toBe('—')

      // Retries exhaust well inside this budget; the tone escalates to fault.
      await expect(count).toHaveAttribute('data-truth-state', 'unavailable', { timeout: 20_000 })
      await expect(approvals).toContainText('queue unavailable')
      await expect(approvals).not.toContainText('queue clear')
      expect(await visibleText(page, 'overview-approval-count')).toBe('—')

      // ── 5115: policies likewise ──────────────────────────────────────────
      await expect(page.getByTestId('overview-policy-count')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
        { timeout: 20_000 },
      )
      expect(await visibleText(page, 'overview-policy-count')).toBe('—')

      // ── 5115: a failed alerts query is not "nothing is firing" ───────────
      expect(await visibleText(page, 'overview-firing-count')).toBe('—')
      const issue = page.getByTestId('overview-top-issue')
      await expect(issue).not.toContainText('No critical issues')
      await expect(page.getByTestId('overview-top-issue-absent')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
        { timeout: 20_000 },
      )
      await expect(page.getByTestId('overview-recent-absent')).toBeVisible()

      // ── 5114: one agent missing from the lookup disqualifies the totals ──
      for (const id of ['overview-blocked', 'overview-stripped', 'overview-scrubbed']) {
        await expect(page.getByTestId(id)).toHaveAttribute('data-truth-state', 'unknown')
        expect(await visibleText(page, id)).toBe('—')
      }

      // The failure is announced, not merely blank.
      await expect(approvals).toContainText('the request for this value failed')

      await page.getByTestId('overview-hero').screenshot({
        path: `${EVIDENCE_DIR}/hero-rings-degraded-${theme}.png`,
      })
      await page.getByTestId('overview-approvals').screenshot({
        path: `${EVIDENCE_DIR}/approvals-unavailable-${theme}.png`,
      })
      await page.screenshot({
        path: `${EVIDENCE_DIR}/overview-degraded-${theme}.png`,
        fullPage: true,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
