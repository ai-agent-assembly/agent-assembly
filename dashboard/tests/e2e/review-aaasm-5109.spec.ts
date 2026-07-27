/**
 * Review pass for the Trace route + placeholder lane (AAASM-5109 / AAASM-5165).
 *
 * Each regression is driven explicitly rather than assumed: the wire is made to
 * withhold exactly what production withholds, and the trace request is failed
 * at the network layer while the page is asked what the agent did.
 *
 * What each run re-derives:
 *
 *  1. the page requests `/api/v1/traces/{session_id}` — the only trace path
 *     `openapi/v1.yaml` declares — and never the
 *     `/agents/{id}/sessions/{sid}/trace` route that does not exist
 *     (AAASM-5109);
 *  2. a production-shaped response (every span carrying `end_time: null`, the
 *     shape `aa-api/src/routes/traces.rs` reconstructs from the audit log)
 *     renders the shared absence for every duration, never `null ms` and never
 *     `NaN ms` (AAASM-5165);
 *  3. the payload preview renders "no payload recorded" rather than the literal
 *     string `null` — the whole preview body's production state, since
 *     `TraceSpan` has no payload field at all (AAASM-5165);
 *  4. a span whose operation carries no governance outcome shows an absence
 *     marker, not a green ✓ ALLOWED chip fabricated from a fall-through
 *     default (AAASM-5109);
 *  5. a failed trace request renders `unavailable` with a retry, and is
 *     visibly different from a session that loaded and had no spans;
 *  6. the severity filter — three of whose four checkboxes can never match a
 *     row, because the span schema has no severity field — is not offered;
 *  7. a span that *was* measured still prints its duration, so the guards did
 *     not simply blank the column;
 *  8. a child span is drawn indented under its parent, and an orphaned or
 *     cyclic parent chain still renders flat instead of hanging (AAASM-5109);
 *  9. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the trace
 * response is injected with `page.route` and the token seeded with
 * `addInitScript` before any module runs — a fetch shim installed later would
 * never be seen.
 *
 * Screenshots land in dashboard/verify/5109/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5109')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const AGENT_ID = 'agent-001'
const SESSION_ID = 'session-abc'
const TRACE_PATH = `/agents/${AGENT_ID}/trace/${SESSION_ID}`

/**
 * How long an outage may take to become visible.
 *
 * `main.tsx` mounts a default `QueryClient`, which retries a failed query three
 * times with exponential backoff before settling into `isError`. That is real
 * product behaviour — a slow request is not a broken one — so the run waits it
 * out rather than reconfiguring the app to fail faster than it does.
 */
const OUTAGE_SETTLE_MS = 30_000

const AGENTS = [
  {
    id: AGENT_ID,
    name: 'support-agent',
    framework: '',
    metadata: {},
    active_sessions: [],
  },
]

interface WireSpan {
  span_id: string
  parent_span_id: string | null
  operation: string
  decision: string | null
  start_time: string
  end_time: string | null
}

/**
 * A span in the shape the gateway actually returns.
 *
 * `build_trace_from_audit` sets `end_time` and `parent_span_id` to `None` for
 * every span it reconstructs, and `decision` to a stringified integer when the
 * audit payload carried one — so the defaults here are the production case, not
 * a contrived worst case.
 */
function span(overrides: Partial<WireSpan> = {}): WireSpan {
  return {
    span_id: 'span-1',
    parent_span_id: null,
    operation: 'ToolCallIntercepted',
    decision: null,
    start_time: '2026-04-23T14:23:01.000Z',
    end_time: null,
    ...overrides,
  }
}

interface Harness {
  errors: string[]
  /** Every API path the page requested, for the route assertions. */
  requested: string[]
}

interface Fixture {
  /** Spans to return. Ignored when `failTrace` is set. */
  spans?: WireSpan[]
  /** Fail `GET /api/v1/traces/{id}` at the network layer. */
  failTrace?: boolean
}

/** Minimal unsigned JWT — the dashboard never verifies it; the gateway is the authority. */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5109', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [], requested: [] }

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // The deliberately-failed fixture is the run's own doing, not the app
    // misbehaving.
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', (e) => harness.errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(['read', 'write', 'admin']) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', (r: Route) => {
    harness.requested.push(new URL(r.request().url()).pathname)
    return r.fulfill({ json: {} })
  })
  await page.route('**/api/v1/agents**', (r: Route) => {
    harness.requested.push(new URL(r.request().url()).pathname)
    return r.fulfill({ json: AGENTS })
  })

  await page.route('**/api/v1/traces/**', (r: Route) => {
    harness.requested.push(new URL(r.request().url()).pathname)
    if (fixture.failTrace) {
      return r.fulfill({ status: 404, json: { detail: `Session not found: ${SESSION_ID}` } })
    }
    return r.fulfill({
      json: {
        session_id: SESSION_ID,
        agent_id: AGENT_ID,
        spans: fixture.spans ?? [],
      },
    })
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

test.describe('AAASM-5109 / 5165 review — Trace calls a real route and admits what it lacks', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`the page calls the route the schema declares — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { spans: [span()] })
      await navigate(page, TRACE_PATH)
      await expect(page.getByTestId('trace-timeline')).toBeVisible()

      // The route that exists was called…
      expect(harness.requested).toContain(`/api/v1/traces/${SESSION_ID}`)
      // …and the one that does not exist was never attempted. This is the
      // whole of AAASM-5109: the old path 404'd on every single request.
      expect(harness.requested.some((p) => p.includes('/sessions/'))).toBe(false)
      expect(harness.requested.some((p) => p.endsWith('/trace'))).toBe(false)

      await shot(page, `route-called-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an unmeasured duration never reads as "null ms" or "NaN ms" — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        // Three production-shaped spans (no end_time) plus one that really was
        // measured, so the run proves the row still prints what it has.
        spans: [
          span({ span_id: 's1' }),
          span({ span_id: 's2', operation: 'PolicyViolation' }),
          span({ span_id: 's3', operation: 'ApprovalRequested' }),
          span({
            span_id: 's4',
            operation: 'ToolDispatched',
            end_time: '2026-04-23T14:23:01.834Z',
          }),
        ],
      })
      await navigate(page, TRACE_PATH)

      const rows = page.getByTestId('trace-event')
      await expect(rows).toHaveCount(4)

      // ── the fabricated claims are gone ────────────────────────────────
      await expect(page.getByText('null ms')).toHaveCount(0)
      await expect(page.getByText('NaN ms')).toHaveCount(0)
      const unmeasured = page.locator(
        '[data-testid="trace-event-duration"][data-truth-state="unknown"]',
      )
      await expect(unmeasured).toHaveCount(3)
      for (const cell of await unmeasured.all()) {
        await expect(cell).toContainText('—')
      }

      // ── a real measurement is still asserted ──────────────────────────
      await expect(page.getByText('834 ms')).toHaveCount(1)

      await shot(page, `unmeasured-duration-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a span with no recorded verdict shows no ALLOWED chip — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        spans: [span({ span_id: 's1' }), span({ span_id: 's2', operation: 'PolicyViolation' })],
      })
      await navigate(page, TRACE_PATH)

      await expect(page.getByTestId('trace-event')).toHaveCount(2)

      // `ToolCallIntercepted` records only that governance saw the call, never
      // how it ruled — the old deriver's `return 'allowed'` default stamped it
      // ✓ ALLOWED anyway.
      const absentVerdict = page.getByTestId('trace-event-verdict-absent')
      await expect(absentVerdict).toHaveCount(1)
      await expect(absentVerdict).toHaveAttribute('data-truth-state', 'not-evaluated')

      // The violation, whose operation *is* the outcome, still gets its chip.
      await expect(page.locator('[data-testid="verdict-chip"][data-verdict="denied"]')).toHaveCount(1)

      await shot(page, `verdict-absent-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the payload preview says "no payload recorded", not "null" — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { spans: [span()] })
      await navigate(page, TRACE_PATH)

      await page.getByTestId('trace-event').click()
      await expect(page.getByTestId('payload-modal')).toBeVisible()

      const body = page.getByTestId('redaction-preview-body')
      await expect(body).toBeVisible()
      await expect(body).toContainText('no payload recorded')
      // The AAASM-5165 regression: `JSON.stringify(payload, null, 2) ?? 'null'`
      // put the four-character word into the console block, and after 5109
      // that would have been the *only* thing the block ever showed.
      await expect(body).not.toContainText('null')

      const marker = page.getByTestId('redaction-preview-absent')
      await expect(marker).toHaveAttribute('data-truth-state', 'not-supported')

      // The modal subtitle carries the same unmeasured duration.
      const duration = page.getByTestId('payload-modal-duration')
      await expect(duration).not.toHaveAttribute('data-truth-state', 'known')
      await expect(duration).toContainText('—')

      await shot(page, `payload-absent-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`a failed trace request never reads as an empty session — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { failTrace: true })
      await navigate(page, TRACE_PATH)

      const body = page.getByTestId('trace-unavailable')
      await expect(body).toHaveAttribute('data-truth-state', 'unavailable', {
        timeout: OUTAGE_SETTLE_MS,
      })
      await expect(body).toContainText('Trace unavailable')

      // The empty state must not be reachable while the request is failing —
      // "this agent did nothing" and "we could not find out" are different
      // facts and only one of them exonerates the agent.
      await expect(page.getByTestId('empty-state')).toHaveCount(0)
      await expect(page.getByText('No events recorded for this session')).toHaveCount(0)
      await expect(page.getByTestId('trace-timeline')).toHaveCount(0)

      // The failure stays actionable.
      await expect(page.getByRole('button', { name: 'Retry' })).toBeVisible()

      await shot(page, `trace-unavailable-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an empty session says so, and says something else — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { spans: [] })
      await navigate(page, TRACE_PATH)

      const empty = page.getByTestId('empty-state')
      await expect(empty).toBeVisible()
      await expect(empty).toContainText('No events recorded for this session')
      // A session that loaded and had no spans is a real, known answer, so it
      // carries no absence badge and no fault tone.
      await expect(empty).toHaveAttribute('data-truth-state', 'empty')
      await expect(page.getByTestId('trace-unavailable')).toHaveCount(0)

      await shot(page, `trace-empty-${theme}`)
      expect(harness.errors).toEqual([])
    })


    test(`child spans are indented under their parent — ${theme}`, async ({ page }) => {
      // AAASM-5109 lists `parent_span_id` -> nesting as target behaviour. The
      // run asserts the *drawn* offset, not merely that a prop was threaded
      // through: a `data-depth` attribute with no visual consequence would
      // satisfy the ticket on paper and change nothing an operator sees.
      const harness = await bootstrap(page, theme, {
        spans: [
          span({ span_id: 'root', operation: 'ToolCallIntercepted' }),
          span({ span_id: 'child', parent_span_id: 'root', operation: 'ToolDispatched' }),
          span({ span_id: 'grandchild', parent_span_id: 'child', operation: 'PolicyViolation' }),
        ],
      })
      await navigate(page, TRACE_PATH)

      const rows = page.getByTestId('trace-event')
      await expect(rows).toHaveCount(3)
      await expect(rows.nth(0)).toHaveAttribute('data-depth', '0')
      await expect(rows.nth(1)).toHaveAttribute('data-depth', '1')
      await expect(rows.nth(2)).toHaveAttribute('data-depth', '2')

      // Real, computed indentation — strictly increasing left offset.
      const offsets = await rows.evaluateAll((els) =>
        els.map((el) => el.getBoundingClientRect().left),
      )
      expect(offsets[1]).toBeGreaterThan(offsets[0])
      expect(offsets[2]).toBeGreaterThan(offsets[1])

      await shot(page, `nesting-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`an orphaned or cyclic parent chain still renders — ${theme}`, async ({ page }) => {
      // Neither case should be emitted, and nothing on the wire forbids either:
      // `build_trace_from_audit` scans a bounded window so a parent can fall
      // outside it, and no producer validates against a loop. Both must render
      // flat rather than hang the page or throw.
      const harness = await bootstrap(page, theme, {
        spans: [
          span({ span_id: 'orphan', parent_span_id: 'not-in-this-response' }),
          span({ span_id: 'loop-a', parent_span_id: 'loop-b' }),
          span({ span_id: 'loop-b', parent_span_id: 'loop-a' }),
        ],
      })
      await navigate(page, TRACE_PATH)

      const rows = page.getByTestId('trace-event')
      await expect(rows).toHaveCount(3)
      for (let i = 0; i < 3; i += 1) {
        await expect(rows.nth(i)).toHaveAttribute('data-depth', '0')
      }

      const offsets = await rows.evaluateAll((els) =>
        els.map((el) => el.getBoundingClientRect().left),
      )
      expect(new Set(offsets).size).toBe(1)

      expect(harness.errors).toEqual([])
    })

    test(`the severity filter is not offered when nothing carries a severity — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, {
        spans: [span({ span_id: 's1' }), span({ span_id: 's2', operation: 'PolicyViolation' })],
      })
      await navigate(page, TRACE_PATH)

      await expect(page.getByTestId('trace-timeline')).toBeVisible()
      await expect(page.getByTestId('trace-event')).toHaveCount(2)

      // `TraceSpan` has no severity field, so every row is neutral and three of
      // the filter's four checkboxes could never match anything. Offering them
      // would let an operator uncheck "Critical", see nothing change, and
      // conclude there are no critical events.
      await expect(page.getByTestId('trace-filter')).toHaveCount(0)
      await expect(page.getByTestId('trace-filter-critical')).toHaveCount(0)

      // The export affordance, which does have a production path, is still there.
      await expect(page.getByTestId('export-trace')).toBeVisible()

      await shot(page, `no-severity-filter-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
