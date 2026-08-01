/**
 * Verification for AAASM-5369 — the capability surface degrades instead of
 * unmounting or fabricating a zero.
 *
 * ## What only a browser can show here
 *
 * The unit tests prove each fold returns an absence. They cannot prove the two
 * things this ticket is actually about:
 *
 *  - that the **application** survives. The shell's `ErrorBoundary` wraps
 *    `<Outlet />`, so a throw in the shell's own body escaped every boundary in
 *    the tree and emptied `<div id="root">`. There is no "error-boundary"
 *    fallback to assert against for that one — the evidence is that the rail,
 *    the topbar and the routed page are all still there.
 *  - that the capability summary states *unknown* rather than *unconfigured*.
 *    Both suppress the counts, so a screenshot alone cannot tell them apart;
 *    `data-truth-state` and the reason text can.
 *
 * ## The bodies used, and why they are the realistic ones
 *
 * `{}` everywhere is not the interesting case for either lane — the policies
 * hook already rejects it (`!data?.items` throws), and the Capability page
 * reads `matrix.agents` before the summary is reached. The bodies below are the
 * ones a version-skewed API or a rewriting proxy actually produces and which
 * previously reached the folds intact:
 *
 *  - `{"items": {}}` — a policies envelope whose `items` is not an array. Passes
 *    the hook's truthiness check, then `.filter` threw.
 *  - `{"items": [{}]}` — rows the dashboard cannot read. `!undefined` is `true`,
 *    so each unreadable row counted itself as an inactive policy.
 *  - a matrix with every field the grid renders but **no `cascadeLoaded`** — an
 *    API predating AAASM-5106. `!undefined` is `true`, so the fold reported a
 *    measured `documentCount: 0` and the summary announced "no policy document
 *    is loaded" about a deployment it had not read.
 *
 * ## A defect visible in this evidence that this ticket does not fix
 *
 * `shell-survives-non-array-policies.png` is taken on Overview, and the L2 card
 * in it reads **"undefined ACTIVE POLICIES"**. That is not a regression from
 * this change and not an artefact of the harness: `OverviewPage.tsx` folds the
 * *same* policies query with its own undecoded
 * `mapCertain(certainFromQuery(policiesQuery), p => p.length)`, so `{"items":
 * {}}` gives it `undefined` where the shell now reports an absence. It is
 * recorded as `hazardous` in `lib/truthfulness/__tests__/foldAudit.test.ts`
 * and carried as a follow-up rather than fixed here — OverviewPage folds four
 * queries and migrating one of them would leave that file half-decoded with no
 * test able to say which half.
 *
 * The screenshot is kept as-is rather than retaken somewhere flattering: it is
 * the honest picture of what a schema-invalid policies response does to the app
 * after this fix, and the shell surviving is exactly what it is evidence of.
 *
 * Screenshots land in dashboard/verify/5369/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5369')

/**
 * A real 3-part JWT with an admin `scope` claim.
 *
 * The Policy rail badge does not exist for a non-admin caller: since AAASM-5186
 * the shell short-circuits `badgeFor('policy')` to `null` unless
 * `useCan('admin')`. A scope-less token would make every assertion below pass
 * against a badge that was never rendered — the vacuous pass this file must not
 * have.
 */
const b64url = (o: object) =>
  Buffer.from(JSON.stringify(o))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
const JWT = `${b64url({ alg: 'none' })}.${b64url({ sub: 'kelly@security', scope: ['read', 'write', 'admin'] })}.sig`

/** A readable policies envelope: one active version, two superseded. */
const GOOD_POLICIES = {
  items: [
    { name: 'default', version: '1.0.0', rule_count: 5, active: true, policy_yaml: '' },
    { name: 'experimental', version: '0.9.0', rule_count: 2, active: false, policy_yaml: '' },
    { name: 'staging', version: '0.1.0', rule_count: 1, active: false, policy_yaml: '' },
  ],
}

const AGENTS = {
  items: [
    {
      id: 'agent-0',
      name: 'agent-0',
      framework: 'langchain',
      version: '0.1.0',
      status: 'active',
      layer: 'sdk',
      session_count: 1,
      policy_violations_count: 0,
      last_event: '2026-06-01T10:00:00Z',
      tool_names: ['search'],
      recent_events: [],
    },
  ],
}

/** One agent × one resource, enough for the Capability grid to render. */
const MATRIX_BODY = {
  agents: [
    {
      id: 'agent-0',
      name: 'agent-0',
      framework: 'langchain',
      trust: null,
      status: 'active',
      lastSeen: '2026-06-01T10:00:00Z',
      caps: { 'res-1': { read: 'allow', write: 'deny', delete: 'na', exec: 'na' } },
    },
  ],
  resources: [{ id: 'res-1', name: 'files', group: 'files', paths: ['/tmp'] }],
  policies: [{ id: 'p1', name: 'baseline', scope: 'global', status: 'active', affects: [], rules: [] }],
  sampleCalls: [],
}

/** The AAASM-5106 flag an older API does not send. */
const MATRIX_WITHOUT_CASCADE_FLAG = MATRIX_BODY
const MATRIX_WITH_CASCADE_LOADED = { ...MATRIX_BODY, cascadeLoaded: true }

interface Harness {
  /** Console errors the app itself emitted. Fixture 404s are excluded. */
  readonly errors: string[]
}

interface Fixtures {
  readonly policies?: unknown
  readonly matrix?: unknown
}

async function bootstrap(page: Page, fixtures: Fixtures): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // sessionStorage only — the token never goes to localStorage (AAASM-4322).
  await page.addInitScript((token: string) => {
    sessionStorage.setItem('aa_token', token)
  }, JWT)

  // Permissive fallback first (least specific); Playwright matches the most
  // recently added route, so the specific fixtures below win.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/alerts**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) => r.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route(/\/api\/v1\/policies(\?.*)?$/, (r) =>
    r.request().method() === 'GET'
      ? r.fulfill({ json: fixtures.policies ?? GOOD_POLICIES })
      : r.fallback(),
  )
  await page.route('**/api/v1/capability/matrix**', (r) =>
    r.fulfill({ json: fixtures.matrix ?? MATRIX_WITH_CASCADE_LOADED }),
  )
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  // Enter at `/` and navigate in-app rather than deep-linking: the bundle is
  // built with a relative `base`, so a direct load resolves its assets against
  // the sub-path and the app never boots.
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  return { errors }
}

async function navigateTo(page: Page, path: string): Promise<void> {
  await page.evaluate((to) => {
    window.history.pushState({}, '', to)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

/**
 * The application is still the application.
 *
 * For the shell lane there is no error fallback to look for — the defect
 * *removed* the tree rather than replacing it — so the evidence has to be the
 * presence of real content. Each of these was absent from the empty root the
 * unfixed shell produced.
 */
async function expectShellIntact(page: Page, harness: Harness): Promise<void> {
  await expect(page.getByTestId('appshell')).toBeVisible()
  await expect(page.getByTestId('appshell-nav')).toBeVisible()
  await expect(page.getByTestId('appshell-topbar')).toBeVisible()
  await expect(page.getByTestId('nav-link-policy')).toBeVisible()
  await expect(page.getByTestId('nav-link-capability')).toBeVisible()
  await expect(page.getByTestId('error-boundary')).toHaveCount(0)
  expect(harness.errors).toEqual([])
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

test.describe('AAASM-5369 — a policies 200 the shell cannot read', () => {
  test('a non-array items keeps the whole application mounted', async ({ page }) => {
    // The body that threw `list.filter is not a function` out of AppShell's own
    // render, past the ErrorBoundary that wraps only the page.
    const harness = await bootstrap(page, { policies: { items: {} } })

    await expectShellIntact(page, harness)

    const marker = page.getByTestId('nav-badge-absent-policy')
    await expect(marker).toBeVisible()
    await expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    // The reason reaches the DOM, where an operator and a screen reader can
    // both get at it — a bare `—` is an absence nobody can act on.
    await expect(marker).toContainText('policy list came back in a shape')

    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'shell-survives-non-array-policies.png'),
      fullPage: true,
    })
  })

  test('rows it cannot read are not counted as inactive policies', async ({ page }) => {
    // Two unreadable rows used to render as the confident badge "2".
    const harness = await bootstrap(page, { policies: { items: [{}, {}] } })

    await expectShellIntact(page, harness)

    const badge = page.getByTestId('nav-badge-policy')
    await expect(badge).toBeVisible()
    await expect(badge).not.toHaveText('2')
    await expect(page.getByTestId('nav-badge-absent-policy')).toHaveAttribute(
      'data-truth-state',
      'unknown',
    )

    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'shell-refuses-to-count-unreadable-rows.png'),
      fullPage: true,
    })
  })

  test('a readable list still shows its measured count', async ({ page }) => {
    // Without this the whole describe would pass against a shell that reported
    // every policies response as unreadable.
    const harness = await bootstrap(page, {})

    await expect(page.getByTestId('nav-badge-policy')).toHaveText('2')
    await expect(page.getByTestId('nav-badge-absent-policy')).toHaveCount(0)
    await expectShellIntact(page, harness)
  })
})

test.describe('AAASM-5369 — a capability matrix that never states its cascade', () => {
  test('reports unknown, never "no policy document is loaded"', async ({ page }) => {
    const harness = await bootstrap(page, { matrix: MATRIX_WITHOUT_CASCADE_FLAG })
    await navigateTo(page, '/capability')
    await expect(page.getByTestId('capability-page')).toBeVisible()

    // The summary rendered — the assertions below are about what it says, and
    // would pass vacuously against a page that had unmounted.
    const allow = page.getByTestId('cap-summary-allow')
    await expect(allow).toBeVisible()

    // `unconfigured` is what the fabricated `documentCount: 0` produced: a
    // measured claim about the operator's deployment, derived from a body the
    // dashboard never read. `unknown` is the truth.
    await expect(allow).toHaveAttribute('data-truth-state', 'unknown')
    await expect(allow).not.toHaveAttribute('data-truth-state', 'unconfigured')
    for (const testId of ['cap-summary-deny', 'cap-summary-flagged']) {
      await expect(page.getByTestId(testId)).toHaveAttribute('data-truth-state', 'unknown')
    }

    // No fabricated figure anywhere in the summary row, and no affirmative
    // posture language — the AAASM-5112 rule.
    const summary = page.getByLabel('matrix summary')
    await expect(summary).not.toContainText('No policy document is loaded')
    const announced = (await summary.textContent()) ?? ''
    expect(announced).not.toMatch(/\b(safe|healthy|verified|clean|secure|all clear)\b/i)

    await expectShellIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'capability-unknown-not-unconfigured.png'),
      fullPage: true,
    })
  })

  test('still reports a genuinely unloaded cascade as unconfigured', async ({ page }) => {
    // The guard must not swallow the real AAASM-5106 signal. A body that parses
    // and says `cascadeLoaded: false` is a measurement, and stays one — without
    // this, the test above would pass against a fold that reported every matrix
    // as unreadable.
    const harness = await bootstrap(page, {
      matrix: { ...MATRIX_BODY, cascadeLoaded: false },
    })
    await navigateTo(page, '/capability')
    await expect(page.getByTestId('capability-page')).toBeVisible()

    await expect(page.getByTestId('cap-summary-allow')).toHaveAttribute(
      'data-truth-state',
      'unconfigured',
    )

    await expectShellIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'capability-real-unloaded-cascade.png'),
      fullPage: true,
    })
  })

  test('reports a loaded cascade as the measurement it is', async ({ page }) => {
    const harness = await bootstrap(page, { matrix: MATRIX_WITH_CASCADE_LOADED })
    await navigateTo(page, '/capability')
    await expect(page.getByTestId('capability-page')).toBeVisible()

    // One allow cell for the `read` verb, one deny — real counts off a real body.
    await expect(page.getByTestId('cap-summary-allow')).not.toHaveAttribute(
      'data-truth-state',
      'unknown',
    )

    await expectShellIntact(page, harness)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, 'capability-loaded-cascade.png'),
      fullPage: true,
    })
  })
})
