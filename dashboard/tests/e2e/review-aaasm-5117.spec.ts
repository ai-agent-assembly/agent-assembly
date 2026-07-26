/**
 * Review pass for the Audit Log contract lane — AAASM-5117 / 5118 / 5119 /
 * 5120 / 5151 — against a payload in the shape the gateway really emits.
 *
 * The unit suite can only prove the readers are right about a payload the test
 * author wrote. This run drives the shipped bundle against the **integer**
 * `decision` the gateway serialises (`"decision": response.decision`, a prost
 * `i32`) and re-derives, in a browser, the claims a reviewer would otherwise
 * take on trust:
 *
 *  1. the decision column populates from the integer form — the defect was that
 *     `typeof decision === 'string'` never matched, so the column, the CSV and
 *     the compliance report were empty in every enforce-mode deployment
 *     (AAASM-5117);
 *  2. the truncation notice states the window is partial and offers to read
 *     more, rather than presenting 50 rows as the complete immutable trail
 *     (AAASM-5120);
 *  3. the type filters name real `AuditEventType` families and none of the five
 *     invented ones (AAASM-5118);
 *  4. summaries come from the real payload shape and never render `undefined`
 *     or a raw JSON dump (AAASM-5119);
 *  5. the agent column presents the hex as the unresolvable audit-id digest it
 *     is, and offers no link to an agent page it cannot reach (AAASM-5151);
 *  6. an observe-mode row — decision rewritten to ALLOW, event type rewritten to
 *     ToolCallIntercepted — never renders as a bare allow: the suppressed DENY
 *     is on screen and the row still scans as a violation (AAASM-5117 review);
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5117/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5117')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const RESEARCH_AGENT = '9f2c1a7b4d8e0f3a6b5c4d3e2f1a0b9c'
const SUPPORT_AGENT = '00112233445566778899aabbccddeeff'

/**
 * Rows exactly as the two producers serialise them.
 *
 * `decision` is an integer on every row — that is the whole point of the run.
 * seq 1048 is the gateway's `record_audit` shape (`reason` / `policy_rule`, no
 * `blocked_action`); 1047 and 1044 are the runtime's `build_payload` shape
 * (`detail` object); 1042 carries no decision at all, which must read as an
 * explicit absence rather than as an allow.
 */
const ROWS = [
  {
    seq: 1048,
    timestamp: '2026-07-26T14:02:11Z',
    agent_id: RESEARCH_AGENT,
    session_id: 'a41f9c22',
    event_type: 'PolicyViolation',
    payload: JSON.stringify({
      action_type: 2,
      decision: 2, // DENY
      reason: 'External recipient requires explicit approval',
      policy_rule: 'deny-external-mail',
      latency_us: 412,
      trace_id: 'trace-abc123',
      org_id: 'acme',
      team_id: 'research',
    }),
  },
  {
    seq: 1047,
    timestamp: '2026-07-26T14:01:58Z',
    agent_id: RESEARCH_AGENT,
    session_id: 'a41f9c22',
    event_type: 'ToolCallIntercepted',
    payload: JSON.stringify({
      event_id: '550e8400-e29b-41d4-a716-446655440000',
      action_type: 'TOOL_CALL',
      source: 'sdk',
      decision: 1, // ALLOW
      detail: { kind: 'tool_call', tool_name: 'pg_users', tool_source: 'mcp', succeeded: true },
    }),
  },
  {
    seq: 1046,
    timestamp: '2026-07-26T14:01:40Z',
    agent_id: SUPPORT_AGENT,
    session_id: '6d44be01',
    event_type: 'ApprovalRequested',
    payload: JSON.stringify({
      action_type: 1,
      decision: 3, // PENDING
      reason: 'Spend above the per-call ceiling',
      policy_rule: 'approve-high-cost-llm',
    }),
  },
  {
    seq: 1045,
    timestamp: '2026-07-26T14:01:20Z',
    agent_id: SUPPORT_AGENT,
    session_id: '6d44be01',
    event_type: 'CredentialLeakBlocked',
    payload: JSON.stringify({
      action_type: 2,
      decision: 4, // REDACT
      reason: 'AWS access key present in tool arguments',
      policy_rule: 'scrub-credentials',
    }),
  },
  {
    seq: 1044,
    timestamp: '2026-07-26T14:01:09Z',
    agent_id: SUPPORT_AGENT,
    session_id: '6d44be01',
    event_type: 'ApprovalGranted',
    payload: JSON.stringify({
      decision: 1,
      detail: { kind: 'approval', approval_id: 'zendesk-escalation', approved: true },
    }),
  },
  {
    // Observe mode: `transform_for_observe_mode` rewrote a Deny to Allow, and
    // `record_audit` rewrote the event type to the benign ToolCallIntercepted.
    // Only `shadow_decision` / `shadow_reason` record that anything was blocked
    // — `reason` and `policy_rule` are emptied by the rewrite.
    seq: 1043,
    timestamp: '2026-07-26T14:01:02Z',
    agent_id: RESEARCH_AGENT,
    session_id: 'a41f9c22',
    event_type: 'ToolCallIntercepted',
    payload: JSON.stringify({
      action_type: 2,
      decision: 1, // ALLOW — rewritten
      reason: '',
      policy_rule: '',
      latency_us: 288,
      dry_run: true,
      shadow_decision: 'deny',
      shadow_reason: 'gmail/send blocked for external recipients',
    }),
  },
  {
    // No decision field at all — a sandbox lifecycle event.
    seq: 1042,
    timestamp: '2026-07-26T14:00:55Z',
    agent_id: RESEARCH_AGENT,
    session_id: 'a41f9c22',
    event_type: 'SandboxStarted',
    payload: JSON.stringify({ event_id: 'sbx-9', source: 'proxy' }),
  },
]

/** 7 loaded rows out of 4820 matching the filter — a deliberately short window. */
const LOGS = { items: ROWS, page: 1, per_page: 100, total: 4820 }

const COST_SUMMARY = {
  date: '2026-07-26',
  daily_spend_usd: '48.00',
  daily_limit_usd: '200.00',
  per_team: [],
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted WS upgrades are the fixture's doing, not the app's.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5117')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/costs**', (r) => r.fulfill({ json: COST_SUMMARY }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: LOGS }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

test.describe('AAASM-5117 review — audit-log contract and truncation', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`decision column populates from the integer wire form in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/audit')
      await expect(page.getByTestId('audit-table')).toBeVisible()

      // ── 1. every proto discriminant reaches the column ────────────────────
      await expect(page.getByTestId('audit-decision-1048')).toHaveText('deny')
      await expect(page.getByTestId('audit-decision-1047')).toHaveText('allow')
      await expect(page.getByTestId('audit-decision-1046')).toHaveText('pending')
      await expect(page.getByTestId('audit-decision-1045')).toHaveText('redact')

      // A row with no decision is an explicit absence, never a default allow.
      const noVerdict = page.getByTestId('audit-decision-1042')
      await expect(noVerdict).toHaveAttribute('data-truth-state', 'not-evaluated')
      await expect(noVerdict).not.toHaveText('allow')

      // ── 6. observe mode never reads as a clean allow ──────────────────────
      // The enforced allow is true — the action proceeded — but the suppressed
      // denial is beside it, and the row still scans red despite the gateway
      // having rewritten the event type to a benign ToolCallIntercepted.
      await expect(page.getByTestId('audit-decision-1043')).toHaveText('allow')
      const suppressedChip = page.getByTestId('audit-suppressed-1043')
      await expect(suppressedChip).toHaveText('⊙ observe: deny')
      await expect(suppressedChip).toHaveAttribute(
        'title',
        /gmail\/send blocked for external recipients/,
      )
      await expect(page.getByTestId('audit-row-1043')).toHaveClass(/audit-row--violation/)
      // The rewrite empties `reason`; the real explanation survives only in
      // `shadow_reason` and must reach the summary column.
      await expect(page.getByTestId('audit-summary-1043')).toHaveText(
        'gmail/send blocked for external recipients',
      )

      // ── 4. summaries come from the real payload, with no undefined ────────
      await expect(page.getByTestId('audit-summary-1048')).toHaveText(
        'External recipient requires explicit approval — deny-external-mail',
      )
      await expect(page.getByTestId('audit-summary-1047')).toHaveText('pg_users (mcp) · ✓ ok')
      const table = page.getByTestId('audit-table')
      await expect(table).not.toContainText('undefined')
      await expect(table).not.toContainText('NaN')
      await expect(table).not.toContainText('[object Object]')

      // ── 5. the agent cell is a labelled digest, not a link ────────────────
      const agentCell = page.getByTestId('audit-agent-id-1048')
      await expect(agentCell).toHaveAttribute('title', new RegExp(RESEARCH_AGENT))
      await expect(agentCell).toHaveAttribute('title', /not resolvable/)
      await expect(page.getByTestId('audit-agent-link-1048')).toHaveCount(0)

      await page.getByTestId('audit-table').screenshot({
        path: `${EVIDENCE_DIR}/audit-decision-column-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`the window states its own truncation in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/audit')
      await expect(page.getByTestId('audit-table')).toBeVisible()

      // ── 2. truncation is never presented as completeness ─────────────────
      const banner = page.getByTestId('audit-coverage')
      await expect(banner).toBeVisible()
      await expect(banner).toContainText('Partial — 7 of 4820')
      await expect(banner).toContainText('This is not the complete trail')
      await expect(banner).not.toContainText('Complete —')
      await expect(page.getByTestId('audit-load-more')).toBeVisible()
      await expect(page.getByTestId('audit-count')).toContainText('7 / 4820')

      await banner.screenshot({ path: `${EVIDENCE_DIR}/audit-coverage-partial-${theme}.png` })

      // ── 3. only real event families are offered ──────────────────────────
      for (const invented of ['LLMCall', 'ToolCall', 'FileOp', 'NetworkCall', 'ApprovalEvent']) {
        await expect(page.getByTestId(`audit-type-btn-${invented}`)).toHaveCount(0)
        await expect(page.getByTestId(`audit-stat-${invented}`)).toHaveCount(0)
      }
      await expect(page.getByTestId('audit-stat-policy')).toContainText('2')
      await expect(page.getByTestId('audit-stat-approval')).toContainText('2')
      await expect(page.getByTestId('audit-stat-tool')).toContainText('2')
      await expect(page.getByTestId('audit-stat-sandbox')).toContainText('1')

      // The filter actually selects rows, rather than emptying the table.
      await page.getByTestId('audit-type-btn-approval').click()
      await expect(page.getByTestId('audit-row-1046')).toBeVisible()
      await expect(page.getByTestId('audit-row-1048')).toHaveCount(0)

      await page.getByTestId('audit-stats').screenshot({
        path: `${EVIDENCE_DIR}/audit-event-families-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
