/**
 * Review pass for the Live-Ops truthfulness lane
 * (AAASM-5129 / 5167 / 5148 / 5128).
 *
 * Each regression is driven explicitly rather than assumed — the wire is made
 * to withhold what production actually withholds, and the approvals request is
 * failed at the network layer while the page is asked what is waiting.
 *
 * What each run re-derives:
 *
 *  1. a stream whose frames carry no `latency_ms` — the production shape today
 *     — renders the shared absence on every row, never `<1ms`, while a frame
 *     that *does* carry one still prints it (AAASM-5129);
 *  2. an `ops_change` frame renders `not-supported` for the three columns that
 *     payload has no field for (AAASM-5129);
 *  3. a failed approvals request renders `unavailable` in both the pane-head
 *     chip and the pane body, and is visibly different from a queue that
 *     loaded and came back empty (AAASM-5167);
 *  4. approve POSTs to the UUID the gateway parses, not to a governance-event
 *     id or a `trace:span` composite (AAASM-5128);
 *  5. a read-scope caller gets every mutating affordance disabled — halt-all,
 *     the row action menu, and approve/reject — and issues no write
 *     (AAASM-5148), and `page on-call`, which has no production path at all,
 *     is disabled for everyone;
 *  6. deciding an approval leaves the pane body, the pane-head chip and the
 *     header bell agreeing, rather than two of them asserting a stale count;
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the approvals
 * failure is injected with `page.route` and the token is seeded with
 * `addInitScript` before any module runs — a fetch shim installed later would
 * never be seen. The event stream is driven with `page.routeWebSocket`.
 *
 * Screenshots land in dashboard/verify/5129/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5129')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query
 * three times with exponential backoff before settling into `isError`. That is
 * real product behaviour — a slow request is not a broken one — so the run
 * waits it out rather than reconfiguring the app to fail faster than it does.
 */
const OUTAGE_SETTLE_MS = 30_000

/** A real approval id: the UUID shape `Uuid::parse_str` accepts server-side. */
const APPROVAL_ID = '3f1c9a52-0c4e-4a1b-9f2d-6a7b8c9d0e1f'
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const AGENTS = [
  {
    id: 'support-agent',
    name: 'support-agent',
    framework: '',
    metadata: {},
    active_sessions: [],
  },
]

const APPROVAL = {
  id: APPROVAL_ID,
  agent_id: 'support-agent',
  action: 'write pg.users',
  reason: 'Policy requires human approval',
  status: 'pending',
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 900_000).toISOString(),
  routing_status: null,
  team_id: null,
}

/**
 * A violation frame. `latency_ms` is omitted unless asked for, because that is
 * what the gateway emits today — `ViolationPayload.latency_ms` is documented
 * as "Optional today — populated once the audit pipeline tracks per-action
 * duration end-to-end".
 */
function violationFrame(i: number, latencyMs?: number) {
  return {
    event_type: 'violation',
    id: `evt-${i}`,
    agent_id: 'support-agent',
    timestamp: new Date().toISOString(),
    payload: {
      kind: 'audit',
      source: 'sdk',
      received_at_ms: 0,
      sequence_number: i,
      op_type: 'tool_call',
      resource: 'gmail.send',
      status: 'running',
      team: 'support',
      ...(latencyMs === undefined ? {} : { latency_ms: latencyMs }),
    },
  }
}

/** An ops_change frame: op_id, state and updated_at, and nothing else. */
function opsChangeFrame() {
  return {
    event_type: 'ops_change',
    id: 900,
    agent_id: 'support-agent',
    timestamp: new Date().toISOString(),
    payload: {
      op_id: 'trace-abc:span-1',
      state: 'running',
      updated_at: new Date().toISOString(),
    },
  }
}

interface Harness {
  errors: string[]
  writes: Array<{ url: string; method: string }>
}

interface Fixture {
  /** Scopes baked into the seeded JWT. Defaults to full access. */
  scopes?: string[]
  /** Fail `GET /api/v1/approvals` at the network layer. */
  failApprovals?: boolean
  /** Return a pending approval rather than an empty queue. */
  withApproval?: boolean
  /** Frames to push down the event socket. */
  frames?: unknown[]
}

/**
 * Minimal unsigned JWT.
 *
 * The claim is `scope` (an array), which is what `parseScopesFromJwt` reads;
 * the signature is irrelevant because the dashboard never verifies it — the
 * gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5129', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [], writes: [] }

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted sockets and the deliberately-failed fixture are the run's own
    // doing, not the app misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', (e) => harness.errors.push(`pageerror: ${e.message}`))

  const scopes = fixture.scopes ?? ['read', 'write', 'admin']
  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(scopes) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/topology/teams**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/auth/ws-ticket', (r) =>
    r.fulfill({ json: { ticket: 'e2e-5129-ticket' } }),
  )

  await page.route('**/api/v1/ops/**', (r: Route) => {
    harness.writes.push({ url: r.request().url(), method: r.request().method() })
    return r.fulfill({ status: 204, body: '' })
  })

  // The list glob also matches `/approvals/{id}/approve`, and Playwright
  // matches the most recently added route first — so the list handler is
  // registered before the two decide handlers, not after.
  await page.route('**/api/v1/approvals**', (r: Route) =>
    fixture.failApprovals
      ? r.fulfill({ status: 503, json: { detail: 'approvals backend unavailable' } })
      : r.fulfill({ json: { items: fixture.withApproval ? [APPROVAL] : [] } }),
  )

  await page.route('**/api/v1/approvals/*/approve', (r: Route) => {
    harness.writes.push({ url: r.request().url(), method: r.request().method() })
    return r.fulfill({ json: { ...APPROVAL, status: 'approved' } })
  })
  await page.route('**/api/v1/approvals/*/reject', (r: Route) => {
    harness.writes.push({ url: r.request().url(), method: r.request().method() })
    return r.fulfill({ json: { ...APPROVAL, status: 'rejected' } })
  })

  const frames = fixture.frames ?? []
  await page.routeWebSocket('**/api/v1/ws/events**', (ws) => {
    for (const f of frames) ws.send(JSON.stringify(f))
  })

  return harness
}

async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

/**
 * Capture the stream rows legibly.
 *
 * `.op-row__main` is a fixed-column grid about 730px wide, and in the shipped
 * three-pane layout the stream pane is far narrower than that, so the latency
 * and resource cells sit outside the pane's `overflow: hidden`. Below 1280 the
 * page's own media query stacks the panes full-width — a real shipped layout,
 * not a test-only style override — which is where those two columns are
 * actually readable. The evidence is captured there as well.
 */
async function shotStacked(page: Page, name: string) {
  await page.setViewportSize({ width: 1200, height: 1400 })
  await page.getByTestId('live-ops-stream-zone').scrollIntoViewIfNeeded()
  await shot(page, name)
  await page.setViewportSize({ width: 1280, height: 720 })
}

test.describe('AAASM-5129 review — Live-Ops claims only what it measured', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`an unmeasured latency never reads as "<1ms" — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        // Three frames with no latency at all (production today) and one that
        // carries a real measurement, so the run proves the row still prints a
        // value it actually has.
        frames: [
          violationFrame(1),
          violationFrame(2),
          violationFrame(3),
          violationFrame(4, 834),
        ],
      })
      await navigate(page, '/live')

      const rows = page.getByTestId('op-row')
      await expect(rows).toHaveCount(4)

      // ── the fabricated claim is gone from every row ────────────────────
      await expect(page.getByText('<1ms')).toHaveCount(0)
      const unmeasured = page.locator(
        '[data-testid="op-row-latency"][data-truth-state="unknown"]',
      )
      await expect(unmeasured).toHaveCount(3)
      for (const cell of await unmeasured.all()) {
        await expect(cell).toContainText('—')
      }

      // ── a real measurement is still asserted ──────────────────────────
      await expect(page.getByText('834ms')).toHaveCount(1)

      await shot(page, `unmeasured-latency-${theme}`)
      await shotStacked(page, `unmeasured-latency-rows-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an ops_change row says the columns are not supported — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { frames: [opsChangeFrame()] })
      await navigate(page, '/live')

      await expect(page.getByTestId('op-row')).toHaveCount(1)
      for (const id of ['op-row-latency', 'op-row-op-type', 'op-row-resource']) {
        const cell = page.getByTestId(id)
        await expect(cell).toHaveAttribute('data-truth-state', 'not-supported')
        await expect(cell).toContainText('—')
      }
      // No row may report a duration it has no field for.
      await expect(page.getByText('<1ms')).toHaveCount(0)
      await expect(page.getByText('0ms')).toHaveCount(0)

      await shot(page, `ops-change-row-${theme}`)
      await shotStacked(page, `ops-change-row-rows-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a failed approvals request never reads as an empty queue — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        failApprovals: true,
        frames: [violationFrame(1)],
      })
      await navigate(page, '/live')

      // The in-flight body carries the same test id (it is the pane's one
      // status slot), so the wait is on the state settling — waiting on
      // visibility would pass while the request was still retrying.
      const body = page.getByTestId('approval-pool-unavailable')
      await expect(body).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      await expect(body).toContainText('Approval queue unavailable')
      await expect(page.getByTestId('approval-pool-retry')).toBeVisible()

      // The empty state must not be reachable while the queue is broken.
      await expect(page.getByTestId('approval-pool-empty')).toHaveCount(0)
      await expect(page.getByText('No pending approvals')).toHaveCount(0)

      // …and neither the pane-head chip nor the header bell may claim a clear
      // queue. The bell is on every route, so it is the widest reach of the
      // same defect: `data?.length ?? 0` hid its badge on a failed request,
      // making an outage look exactly like an empty queue.
      const count = page.getByTestId('live-ops-approvals-count')
      await expect(count).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      await expect(count).toContainText('—')
      await expect(page.getByTestId('approvals-bell-absent')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      )
      await expect(page.getByTestId('approvals-bell-badge')).toHaveCount(0)

      await shot(page, `approvals-outage-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an empty queue says so, and says something else — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { frames: [violationFrame(1)] })
      await navigate(page, '/live')

      const empty = page.getByTestId('approval-pool-empty')
      await expect(empty).toBeVisible()
      await expect(empty).toContainText('No pending approvals')
      await expect(empty).toHaveAttribute('data-truth-state', 'empty')
      await expect(page.getByTestId('approval-pool-unavailable')).toHaveCount(0)
      // A zero from a request that succeeded is a real answer.
      await expect(page.getByTestId('live-ops-approvals-chip')).toContainText('0 waiting')
      await expect(page.getByTestId('approval-pool-retry')).toHaveCount(0)
      // A clear queue leaves the header bell bare — which is only correct
      // because a failed one no longer looks like this.
      await expect(page.getByTestId('approvals-bell-badge')).toHaveCount(0)
      await expect(page.getByTestId('approvals-bell-absent')).toHaveCount(0)

      await shot(page, `approvals-empty-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`approve acts on the UUID the gateway parses — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        withApproval: true,
        frames: [violationFrame(1)],
      })
      await navigate(page, '/live')

      const card = page.getByTestId('approval-pool-item')
      await expect(card).toHaveCount(1)
      await expect(card).toHaveAttribute('data-approval-id', APPROVAL_ID)
      // expires_at came with the real approval, so the TTL countdown is live.
      await expect(page.getByTestId('approval-countdown')).toBeVisible()
      await expect(page.getByTestId('live-ops-approvals-chip')).toContainText('1 waiting')
      await expect(page.getByTestId('approvals-bell-badge')).toHaveText('1')

      await shot(page, `approvals-queue-${theme}`)

      await page.getByTestId('approval-approve-btn').click()

      await expect
        .poll(() => harness.writes.filter((w) => w.url.includes('/approve')).length)
        .toBe(1)
      const write = harness.writes.find((w) => w.url.includes('/approve'))!
      const id = new URL(write.url).pathname.split('/').at(-2)!
      // The regression: the old code sent a governance-event id or a
      // "{trace_id}:{span_id}" composite here and the request 400'd on
      // `Uuid::parse_str` before the queue was ever consulted.
      expect(id).toMatch(UUID_RE)
      expect(id).toBe(APPROVAL_ID)

      // Every surface reading the queue must agree afterwards. The body used
      // to shrink from component-local state while the pane-head chip and the
      // always-visible header bell went on reporting the old count, because
      // those two read the shared cache and nothing wrote it.
      await expect(page.getByTestId('approval-pool-empty')).toBeVisible()
      await expect(page.getByTestId('live-ops-approvals-chip')).toContainText('0 waiting')
      await expect(page.getByTestId('approvals-bell-badge')).toHaveCount(0)

      await shot(page, `approvals-decided-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a read-scope caller gets every mutating control disabled — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        scopes: ['read'],
        withApproval: true,
        frames: [violationFrame(1)],
      })
      await navigate(page, '/live')

      // ── the fleet-wide kill switch ────────────────────────────────────
      const halt = page.getByTestId('live-ops-halt-all')
      await expect(halt).toBeDisabled()

      // ── the affordance with no production path at all ─────────────────
      await expect(page.getByTestId('live-ops-page-oncall')).toBeDisabled()

      // ── the per-op controls ───────────────────────────────────────────
      await expect(page.getByTestId('op-row')).toHaveCount(1)
      await page.getByTestId('row-action-trigger').click()
      for (const id of [
        'row-action-pause',
        'row-action-resume',
        'row-action-terminate',
        'row-action-halt-agent',
      ]) {
        await expect(page.getByTestId(id)).toBeDisabled()
      }
      await page.keyboard.press('Escape')

      // ── approve / reject ──────────────────────────────────────────────
      await expect(page.getByTestId('approval-approve-btn')).toBeDisabled()
      await expect(page.getByTestId('approval-reject-btn')).toBeDisabled()

      await shot(page, `read-only-${theme}`)

      // Nothing the read-only caller could reach issued a write.
      expect(harness.writes).toEqual([])
      expect(harness.errors).toEqual([])
    })

    test(`a write-scope caller keeps the same controls live — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        scopes: ['read', 'write'],
        withApproval: true,
        frames: [violationFrame(1)],
      })
      await navigate(page, '/live')

      await expect(page.getByTestId('live-ops-halt-all')).toBeEnabled()
      await page.getByTestId('row-action-trigger').click()
      await expect(page.getByTestId('row-action-pause')).toBeEnabled()
      await page.keyboard.press('Escape')
      await expect(page.getByTestId('approval-approve-btn')).toBeEnabled()

      await shot(page, `write-scope-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
