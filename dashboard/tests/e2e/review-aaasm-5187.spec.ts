/**
 * Review pass for the Capability parity lane (AAASM-5187 / 5125 / 5154).
 *
 * The wire is made to serve a matrix shaped the way `project_matrix` actually
 * shapes one — read/write/delete on the Filesystem family only, `exec` on
 * Terminal, Network-outbound and every MCP-tool column — because all three
 * defects are only visible against that shape. A fixture with eight uniformly
 * populated resources (the design mock's) hides the verb defect entirely.
 *
 * What each run re-derives:
 *
 *  1. **AAASM-5187** — the summary strip carries no narrowed metric at all. The
 *     tile reported a real `0` for a state `decide()` cannot emit; it is removed
 *     rather than relabelled, because unlike the `flagged agents` tile beside it
 *     the absence is structural, not contingent (ADR 0026 Decision 2).
 *  2. **AAASM-5125** — the page lands on `exec`, the verb this matrix actually
 *     populates, not on `write`, which it models on one column out of four.
 *  3. **AAASM-5154** — the row header opens the agent, and the destination
 *     genuinely resolves: the run asserts the agent drawer renders, not merely
 *     that a URL was pushed. Trace shipped a row link to a route that 404'd
 *     (AAASM-5109) and a URL-only assertion would have passed on it.
 *  4. Neither theme produces console errors or uncaught exceptions.
 *
 * It also regenerates `verify/5124/bulk-options-*.png`, which were orphaned when
 * that run's shot was renamed and still show a bulk bar the UI no longer has.
 * Regenerated rather than deleted so the name keeps meaning what it says.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so every response
 * is injected with `page.route` and the token is seeded with `addInitScript`
 * before any module runs — a fetch shim installed later would never be seen.
 *
 * Screenshots land in dashboard/verify/5187/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5187')
const HOUSEKEEPING_DIR = resolve(process.cwd(), 'verify/5124')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** The three system families `project_matrix` always emits, plus one MCP tool. */
const RESOURCES = [
  { id: 'filesystem', name: 'Filesystem', group: 'files', paths: ['/srv/**'] },
  { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
  { id: 'network-outbound', name: 'Network', group: 'infra', paths: [] },
  { id: 'search_web', name: 'search_web', paths: [] },
]

const na = { read: 'na', write: 'na', delete: 'na', exec: 'na' } as const

/**
 * Agents in the vocabulary the projection can emit, with `trust` null and the
 * optional columns omitted — what the live endpoint actually sends today.
 *
 * The ids are the registry's hex-encoded 16-byte agent ids, which is the same
 * value `GET /api/v1/agents/{id}` parses; the row-header link is only honest if
 * the id it carries is the one the detail route accepts.
 */
const AGENTS = [
  {
    id: '0102030405060708090a0b0c0d0e0f10',
    name: 'research-bot-04',
    framework: 'LangChain',
    owner: 'data-platform',
    trust: null,
    status: 'active',
    lastSeen: new Date().toISOString(),
    caps: {
      filesystem: { ...na, read: 'allow', write: 'allow', delete: 'deny' },
      terminal: { ...na, exec: 'allow' },
      'network-outbound': { ...na, exec: 'deny' },
      search_web: { ...na, exec: 'allow' },
    },
  },
  {
    id: '1112131415161718191a1b1c1d1e1f20',
    name: 'support-triage',
    framework: 'CrewAI',
    owner: 'cx-tools',
    trust: null,
    status: 'active',
    lastSeen: new Date().toISOString(),
    caps: {
      filesystem: { ...na, read: 'allow', write: 'deny', delete: 'deny' },
      terminal: { ...na, exec: 'deny' },
      'network-outbound': { ...na, exec: 'allow' },
      search_web: { ...na, exec: 'allow' },
    },
  },
]

/**
 * One resolved policy document, so the cascade is non-empty.
 *
 * With an empty cascade every count folds to Unconfigured (AAASM-5106) and the
 * summary shows no numbers at all — which would let the narrowed tile's removal
 * pass for the wrong reason. A loaded cascade is the state in which a fabricated
 * `0` would actually have been rendered.
 */
const MATRIX = {
  resources: RESOURCES,
  agents: AGENTS,
  policies: [
    {
      id: 'P-021',
      name: 'egress-scope',
      scope: 'team:data-platform',
      status: 'active',
      affects: [AGENTS[0].id],
      rules: [{ resource: 'network-outbound', verb: ['exec'], action: 'deny', condition: '' }],
    },
  ],
  sampleCalls: [],
  // AAASM-5106: a real cascade is loaded, so the summary reports real counts.
  cascadeLoaded: true,
}

/** The agent record `GET /api/v1/agents/{id}` returns for a matrix row. */
function agentRecord(index: number) {
  const a = AGENTS[index]
  return {
    id: a.id,
    name: a.name,
    framework: a.framework,
    version: '1.0.0',
    status: 'Active',
    tool_names: ['search_web'],
    metadata: {},
    session_count: 0,
    policy_violations_count: 0,
    active_sessions: [],
    recent_events: [],
    recent_traces: [],
  }
}

/**
 * Minimal unsigned JWT. The claim is `scope` (an array), which is what
 * `parseScopesFromJwt` reads; the signature is irrelevant because the dashboard
 * never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5187', scope: scopes })}.`
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const harness: Harness = { errors: [] }

  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // Aborted sockets are the run's own doing, not the app misbehaving.
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
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) =>
    r.fulfill({ json: { ticket: 'e2e-5187-ticket' } }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/analytics/**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/capability/matrix**', (r) => r.fulfill({ json: MATRIX }))
  await page.route('**/api/v1/agents?**', (r) =>
    r.fulfill({
      json: { items: AGENTS.map((_, i) => agentRecord(i)), page: 1, per_page: 50, total: 2 },
    }),
  )
  for (const [i, a] of AGENTS.entries()) {
    await page.route(`**/api/v1/agents/${a.id}`, (r) => r.fulfill({ json: agentRecord(i) }))
  }

  return harness
}

async function shot(page: Page, dir: string, name: string) {
  await page.screenshot({ path: resolve(dir, `${name}.png`), fullPage: true })
}

async function openCapability(page: Page) {
  await page.goto('/capability')
  await expect(page.getByRole('heading', { name: /Capability/ })).toBeVisible()
  await expect(page.getByRole('grid', { name: 'capability matrix' })).toBeVisible()
}

test.describe('AAASM-5187/5125/5154 review — the Capability surface claims only what it can', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
    await mkdir(HOUSEKEEPING_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`the summary reports no narrowed metric, and lands on a populated verb — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await openCapability(page)

      // AAASM-5125: the landing verb is the one this matrix populates.
      await expect(page.getByRole('radio', { name: 'exec' })).toHaveAttribute(
        'aria-checked',
        'true',
      )
      await expect(page.getByRole('radio', { name: 'write' })).toHaveAttribute(
        'aria-checked',
        'false',
      )

      // AAASM-5187: no narrowed tile, and no fabricated zero anywhere on the
      // strip. The remaining counts are real, which is what makes the absence of
      // this one a deliberate statement rather than a side effect of an
      // unloaded matrix.
      const summary = page.getByLabel('matrix summary')
      await expect(summary).toBeVisible()
      await expect(summary).not.toContainText(/narrow/i)
      await expect(page.getByTestId('cap-summary-narrow')).toHaveCount(0)
      await expect(page.getByTestId('cap-summary-allow')).toContainText(/\d/)
      await expect(page.getByTestId('cap-summary-flagged')).toContainText('Not evaluated')

      await shot(page, EVIDENCE_DIR, `summary-and-landing-verb-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`switching the verb is still the operator's to make — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await openCapability(page)

      await page.getByRole('radio', { name: 'write' }).click()
      await expect(page.getByRole('radio', { name: 'write' })).toHaveAttribute(
        'aria-checked',
        'true',
      )
      // The write matrix is the sparse one the page no longer opens on — proof
      // the default was the fix and not a removal of the verb.
      await expect(page.getByLabel('matrix summary')).toContainText('total "allow" cells (write)')

      await shot(page, EVIDENCE_DIR, `verb-write-chosen-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`the row header opens the agent and the route resolves — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await openCapability(page)

      await page.getByRole('button', { name: `open agent ${AGENTS[0].name}` }).click()

      // Not just the URL: the destination has to render. A pushed path that
      // matches no route leaves the operator on a blank shell (AAASM-5109).
      await expect(page).toHaveURL(new RegExp(`/agents/${AGENTS[0].id}$`))
      await expect(page.getByTestId('drawer-panel')).toBeVisible()
      await expect(page.getByTestId('drawer-panel')).toContainText(AGENTS[0].name)

      await shot(page, EVIDENCE_DIR, `row-header-to-agent-${theme}`)
      expect(harness.errors).toEqual([])
    })

    /**
     * Housekeeping, not a claim about this lane.
     *
     * `verify/5124/bulk-options-*.png` were orphaned when that run's shot was
     * renamed to `bulk-no-selection-*`, and still show a bulk bar with a
     * pre-selected decision — a UI AAASM-5124 removed. Stale evidence of a
     * superseded control is worse than none, so the name is re-shot against the
     * current build rather than deleted: the bulk bar as it exists today, with
     * its decision list open and nothing pre-selected.
     */
    test(`regenerate the orphaned 5124 bulk-options evidence — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await openCapability(page)

      await page.getByRole('checkbox', { name: `select ${AGENTS[0].name}` }).check()
      // Exact: the legend's `decision legend` label matches a loose lookup too.
      const decision = page.getByLabel('decision', { exact: true })
      await expect(decision).toBeVisible()
      // What the control offers today: nothing pre-selected, and no option the
      // gateway answers with a 400.
      await expect(decision).toHaveValue('')
      for (const rejected of ['narrow', 'approval']) {
        await expect(decision.locator(`option[value="${rejected}"]`)).toHaveCount(0)
      }

      await shot(page, HOUSEKEEPING_DIR, `bulk-options-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
