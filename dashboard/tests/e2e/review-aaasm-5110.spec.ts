/**
 * Review pass for AAASM-5110 + AAASM-5111 — the Identity surface must not
 * present invented identity, permission or network data as production fact.
 *
 * Re-derives, against a realistic payload, the claims a reviewer would
 * otherwise take on trust:
 *
 *  1. the Roles tab renders exactly the agents the registry returned — none of
 *     the four seeded ones (`support-agent`, `code-review`, `data-analyst`,
 *     `deploy-agent`) and none of their teams;
 *  2. owner team folds to `—` under `not-supported` rather than naming a team,
 *     and a missing `last_event` folds to `—` under `unknown` rather than
 *     dating the sighting;
 *  3. the permissions panel renders the real cascade scopes, and attributes no
 *     grant to `support-agent-policy-v2`, `deploy-agent-policy-v1`,
 *     `agent.operator` or `agent.readonly` — none of which exist;
 *  4. an empty cascade renders `unconfigured`, never "no effective
 *     permissions": under AAASM-5106 an empty allow/deny over an empty cascade
 *     means nothing was evaluated, not that the agent holds nothing;
 *  5. the Access Log renders `not-supported` with no row, no verdict and no
 *     address-shaped text anywhere — and its filter is inert, so an empty
 *     surface can never be read as "no events matched";
 *  6. neither tab produces console errors or uncaught exceptions, in light and
 *     dark.
 *
 * Screenshots land in dashboard/verify/5110/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5110')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** Anything IPv4-shaped, so a freshly invented address fails these too. */
const IPV4 = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/

/** The four agents and their teams that existed only in the deleted seed. */
const SEED_AGENT_NAMES = ['support-agent', 'code-review', 'data-analyst', 'deploy-agent']
const SEED_TEAMS = ['cx', 'platform', 'analytics', 'devops']

/** Grant sources the seed attributed capabilities to. None exist. */
const SEED_GRANT_SOURCES = [
  'support-agent-policy-v2',
  'deploy-agent-policy-v1',
  'agent.operator',
  'agent.readonly',
]

/** Identities and addresses the access-log seed invented. */
const SEED_IDENTITIES = [
  'alice@agent-assembly.dev',
  'bob@agent-assembly.dev',
  'carol@agent-assembly.dev',
  'gateway-ci',
  'observability-exporter',
  'retired-runner',
]

function rawAgent(over: Record<string, unknown>) {
  return {
    framework: 'langgraph',
    version: '1.0.0',
    tool_names: [],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
    ...over,
  }
}

/**
 * Two registered agents. `etl-worker` carries `last_event: null` — a freshly
 * registered agent that has not reported yet — so the `unknown` branch is
 * exercised alongside the known one. Neither carries a team: `AgentResponse`
 * has no field for one.
 */
const AGENTS = {
  items: [
    rawAgent({ id: 'a1', name: 'orchestrator', status: 'active', last_event: '2026-07-26T09:00:00Z' }),
    rawAgent({ id: 'a2', name: 'etl-worker', status: 'idle', last_event: null }),
  ],
  page: 1,
  per_page: 100,
  total: 2,
}

/** A real cascade: two scopes, each contributing a rule. */
const POPULATED_CASCADE = {
  allow: ['tools.invoke'],
  deny: ['secrets.read'],
  sources: [
    { scope: 'global', allow: ['tools.invoke'], deny: [] },
    { scope: 'team:platform', allow: [], deny: ['secrets.read'] },
  ],
}

/**
 * The AAASM-5106 condition: the gateway resolved no policy document, so the
 * empty allow/deny alongside it is the absence of an evaluation rather than a
 * finding. This is what every shipped deployment currently returns.
 */
const EMPTY_CASCADE = { allow: [], deny: [], sources: [] }

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
      sessionStorage.setItem('aa_token', 'e2e-review-5110')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/iam/members**', (r) =>
    r.fulfill({ json: { items: [], page: 1, page_size: 20, total: 0 } }),
  )
  await page.route('**/api/v1/iam/roles**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/agents?**', (r) => r.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/agents', (r) => r.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  return { errors }
}

/** Register the capability fixture for whichever cascade this case needs. */
async function routeCascade(page: Page, cascade: unknown) {
  await page.route('**/api/v1/agents/*/capabilities', (r) => r.fulfill({ json: cascade }))
}

async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate((target) => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

test.describe('AAASM-5110 / AAASM-5111 review — Identity truthfulness', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`Roles tab renders only registered agents in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await routeCascade(page, POPULATED_CASCADE)
      await navigate(page, '/identity?tab=roles')

      const list = page.getByTestId('agent-registry-list')
      await expect(list).toBeVisible()

      // ── 1. exactly the registry's agents, none of the seeded four ───────
      await expect(page.getByTestId('agent-row-a1')).toContainText('orchestrator')
      await expect(page.getByTestId('agent-row-a2')).toContainText('etl-worker')
      const listText = await list.innerText()
      for (const name of SEED_AGENT_NAMES) {
        expect(listText, `seed agent "${name}" must not render`).not.toContain(name)
      }
      for (const team of SEED_TEAMS) {
        expect(listText, `seed team "${team}" must not render`).not.toContain(team)
      }

      // ── 2. absent fields fold to `—` with their state, not to a value ───
      const ownerTeam = page.getByTestId('agent-owner-team-a1')
      await expect(ownerTeam).toHaveAttribute('data-truth-state', 'not-supported')
      await expect(ownerTeam).toContainText('—')

      const lastSeenUnknown = page.getByTestId('agent-last-seen-a2')
      await expect(lastSeenUnknown).toHaveAttribute('data-truth-state', 'unknown')
      await expect(lastSeenUnknown).toContainText('—')

      // A real timestamp still renders as one — the fix is not "blank everything".
      const lastSeenKnown = page.getByTestId('agent-last-seen-a1')
      await expect(lastSeenKnown).toHaveAttribute('data-truth-state', 'known')
      await expect(lastSeenKnown).toContainText('2026-07-26 09:00')

      expect(listText).not.toContain('undefined')
      expect(listText).not.toContain('NaN')

      await list.screenshot({ path: `${EVIDENCE_DIR}/roles-registry-${theme}.png` })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`permissions panel renders the real cascade in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await routeCascade(page, POPULATED_CASCADE)
      await navigate(page, '/identity?tab=roles')
      await page.getByTestId('agent-row-a1').click()

      const panel = page.getByTestId('agent-permissions-panel')
      await expect(panel).toBeVisible()

      // ── 3. the gateway's own scope labels, and no invented grant source ──
      const scopes = page.getByTestId('permission-scope-label')
      await expect(scopes).toHaveCount(2)
      await expect(scopes.nth(0)).toHaveText('global')
      await expect(scopes.nth(1)).toHaveText('team:platform')
      await expect(page.getByTestId('permission-allow-list').first()).toContainText('tools.invoke')

      const panelText = await panel.innerText()
      for (const source of SEED_GRANT_SOURCES) {
        expect(panelText, `invented grant source "${source}" must not render`).not.toContain(source)
      }

      // The grant date the seed used to supply is an explicit absence now.
      const granted = page.getByTestId('permission-granted-at').first()
      await expect(granted).toContainText('Not supported')

      await panel.screenshot({ path: `${EVIDENCE_DIR}/roles-cascade-${theme}.png` })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`an empty cascade reads as unconfigured, not as "no permissions" in ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await routeCascade(page, EMPTY_CASCADE)
      await navigate(page, '/identity?tab=roles')
      await page.getByTestId('agent-row-a1').click()

      // ── 4. the AAASM-5106 case ──────────────────────────────────────────
      const state = page.getByTestId('agent-permissions-unconfigured')
      await expect(state).toBeVisible()
      await expect(state).toHaveAttribute('data-truth-state', 'unconfigured')
      await expect(state).toContainText('no evaluation has taken place')
      await expect(page.getByTestId('permission-scope')).toHaveCount(0)

      // The reassuring phrasing the panel used to reach for must be gone.
      const panelText = await page.getByTestId('agent-permissions-panel').innerText()
      expect(panelText).not.toContain('no effective permissions')

      await page.getByTestId('agent-permissions-panel').screenshot({
        path: `${EVIDENCE_DIR}/roles-empty-cascade-${theme}.png`,
      })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`Access Log shows no fabricated event in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/identity?tab=access-log')

      const panel = page.getByTestId('iam-panel-access-log')
      await expect(panel).toBeVisible()

      // ── 5. not-supported, and nothing that looks like evidence ──────────
      const state = page.getByTestId('access-log-unsupported')
      await expect(state).toHaveAttribute('data-truth-state', 'not-supported')
      await expect(state).toContainText('AAASM-5176')
      await expect(state).toContainText('AAASM-5177')

      await expect(page.getByTestId('access-log-table')).toHaveCount(0)
      await expect(page.locator('[data-testid^="access-log-row-"]')).toHaveCount(0)

      const panelText = await panel.innerText()
      for (const identity of SEED_IDENTITIES) {
        expect(panelText, `seed identity "${identity}" must not render`).not.toContain(identity)
      }
      expect(panelText, 'no address-shaped text may render').not.toMatch(IPV4)
      expect(panelText).not.toContain('undefined')

      // The filter is visible but cannot be operated into implying a result.
      await expect(page.getByTestId('access-log-filter-bar')).toHaveAttribute(
        'data-disabled',
        'true',
      )
      await expect(page.getByTestId('access-log-filter-identity')).toBeDisabled()

      await panel.screenshot({ path: `${EVIDENCE_DIR}/access-log-${theme}.png` })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
