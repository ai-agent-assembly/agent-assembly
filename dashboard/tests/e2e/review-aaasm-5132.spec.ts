/**
 * Review pass for the onboarding truthfulness lane — AAASM-5132, 5133, 5179,
 * 5145.
 *
 * The four defects all had the same shape: the wizard reported an outcome it
 * never observed. This run drives the *failure* paths specifically, because
 * those are the ones that previously could not be reached at all — step 2 had
 * no `failed` phase and no `err` line kind, so "gateway down" and "gateway
 * healthy" rendered identically.
 *
 * Asserted here:
 *
 *  1. step 2 with the gateway unreachable renders an error and the shared
 *     `unavailable` marker — never "verified", and Continue stays disabled;
 *  2. step 2 against a live gateway prints that gateway's own version and
 *     checks map, and none of the fabricated transcript it used to print;
 *  3. step 2's copy button reports a failed clipboard write instead of turning
 *     green (AAASM-5145);
 *  4. step 3 renders `not-supported` with no action at all, and never mentions
 *     `~/.aa/keys/` or a private key (AAASM-5179);
 *  5. step 5 with a failing registry renders `unavailable`, not `0`;
 *  6. step 5 with an answered-but-empty registry renders a measured `0` and
 *     does *not* claim an enrollment — the two are different claims;
 *  7. step 5 with a registered agent reports the registry's own count;
 *  8. no console errors or uncaught exceptions on any of it.
 *
 * Run in both themes. Screenshots land in dashboard/verify/5132/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5132')
const THEME_KEY = 'aa-dashboard-theme'
const ONBOARDING_COMPLETED_KEY = 'aa.onboarding.completed'
const ONBOARDING_SESSION_KEY = 'aa.onboarding.session'

type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/** A gateway that answers, with a real version and a real per-subsystem map. */
const HEALTHY = {
  status: 'ok',
  version: '0.0.1',
  api_version: 'v1',
  uptime_secs: 3600,
  active_connections: 1,
  pipeline_lag_ms: 0,
  checks: { storage: 'ok', policy_engine: 'ok' },
}

/**
 * What a gateway with a broken storage backend actually puts on the wire.
 *
 * `aa-api/src/routes/health.rs` derives the 503 and the `"degraded"` status
 * string from the same `all_ok` boolean, so this pairing — 503 *with* a
 * complete body naming the subsystem — is the only degraded answer the gateway
 * can produce. An `abort()` fixture never exercises it.
 */
const DEGRADED = {
  ...HEALTHY,
  status: 'degraded',
  checks: { storage: 'degraded', policy_engine: 'ok' },
}

const AGENT = {
  id: 'agent-1',
  name: 'research-bot',
  framework: 'langgraph',
  version: '0.0.1',
  status: 'active',
  tool_names: [],
  metadata: {},
  session_count: 0,
  policy_violations_count: 0,
  active_sessions: [],
  recent_events: [],
  recent_traces: [],
  last_event: '2026-07-26T09:00:00Z',
}

/** Strings the pre-fix wizard printed without having observed any of them. */
const FABRICATIONS = [
  '1.4.2',
  'api.agent-assembly.com',
  'ready to enroll',
  '~/.aa/keys/',
  'do not commit',
  'generate keypair',
  '14:02:11',
  'allowed-by-baseline',
]

interface Harness {
  errors: string[]
}

interface Fixtures {
  /**
   * 'up' answers 200; 'degraded' answers a real 503 *with* a HealthResponse;
   * 'down' aborts the request the way an offline gateway does.
   */
  health?: 'up' | 'degraded' | 'down'
  /** 'agent' → one registered; 'empty' → answered with none; 'fail' → 503. */
  registry?: 'agent' | 'empty' | 'fail'
  /** Remove `navigator.clipboard`, i.e. the non-secure-context case. */
  breakClipboard?: boolean
}

async function bootstrap(page: Page, theme: Theme, fixtures: Fixtures = {}): Promise<Harness> {
  const { health = 'up', registry = 'empty', breakClipboard = false } = fixtures
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() !== 'error') return
    const text = m.text()
    // An aborted request is the fixture's doing, not the app's — the app's own
    // handling of it is what the assertions below check.
    if (!text.startsWith('Failed to load resource')) errors.push(text)
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // Seeded before any module executes: `openapi-fetch` captures
  // `globalThis.fetch` at module load, so an in-page shim installed afterwards
  // is never consulted — which is also why the fixtures below are `page.route`
  // at the network layer rather than a stubbed fetch.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string; completed: string; session: string; breakClipboard: boolean }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5132')
      localStorage.setItem(opts.themeKey, opts.theme)
      localStorage.removeItem(opts.completed)
      localStorage.removeItem(opts.session)
      if (opts.breakClipboard) {
        Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true })
      }
    },
    {
      themeKey: THEME_KEY,
      theme,
      completed: ONBOARDING_COMPLETED_KEY,
      session: ONBOARDING_SESSION_KEY,
      breakClipboard,
    },
  )

  // Permissive fallback first (least specific); the specific fixtures below win,
  // since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  if (health === 'up') {
    await page.route('**/api/v1/health**', (r) => r.fulfill({ json: HEALTHY }))
  } else if (health === 'degraded') {
    await page.route('**/api/v1/health**', (r) => r.fulfill({ status: 503, json: DEGRADED }))
  } else {
    await page.route('**/api/v1/health**', (r) => r.abort('connectionrefused'))
  }

  await page.route('**/api/v1/agents**', (r) => {
    if (registry === 'fail') {
      return r.fulfill({ status: 503, json: { detail: 'registry unavailable' } })
    }
    const items = registry === 'agent' ? [AGENT] : []
    return r.fulfill({ json: { items, page: 1, per_page: 100, total: items.length } })
  })

  return { errors }
}

async function gotoStep(page: Page, step: 'install' | 'identity' | 'enroll') {
  await page.goto('/onboarding')
  await page.getByTestId('onboarding-wizard').waitFor()
  await page.getByTestId('onboarding-framework-langchain').click()
  await page.getByTestId('onboarding-continue').click() // → install
  if (step === 'install') return
  await page.getByTestId('onboarding-skip-step').click() // → identity
  if (step === 'identity') return
  await page.getByTestId('onboarding-skip-step').click() // → policy
  await page.getByTestId('onboarding-continue').click() // → enroll
}

/** No surface anywhere in the wizard may print a pre-fix fabrication. */
async function expectNoFabrications(page: Page) {
  const body = page.getByTestId('onboarding-wizard')
  for (const fabrication of FABRICATIONS) {
    await expect(body).not.toContainText(fabrication)
  }
}

test.describe('AAASM-5132 review — onboarding stops claiming what it never observed', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`step 2 renders an unreachable gateway as a failure in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { health: 'down' })
      await gotoStep(page, 'install')

      // Nothing is claimed before the operator asks.
      await expect(page.getByTestId('onboarding-install-ok')).toHaveCount(0)

      await page.getByTestId('onboarding-install-verify').click()

      // ── 1. the failure is visible, and is the shared `unavailable` state ──
      const absence = page.getByTestId('onboarding-install-absent')
      await expect(absence).toBeVisible()
      await expect(absence).toHaveAttribute('data-truth-state', 'unavailable')
      await expect(page.getByTestId('onboarding-install-err').first()).toBeVisible()
      await expect(page.getByTestId('onboarding-install-ok')).toHaveCount(0)
      const terminal = page.getByTestId('onboarding-install-terminal')
      await expect(terminal).not.toContainText('verified')
      await expect(terminal).not.toContainText('undefined')

      // The step did not advance on a failure.
      await expect(page.getByTestId('onboarding-continue')).toBeDisabled()
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-install').screenshot({
        path: `${EVIDENCE_DIR}/step2-gateway-down-${theme}.png`,
      })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`step 2 reports the live gateway's own health in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { health: 'up' })
      await gotoStep(page, 'install')

      await page.getByTestId('onboarding-install-verify').click()

      // ── 2. the transcript is the gateway's answer, not a constant ─────────
      const terminal = page.getByTestId('onboarding-install-terminal')
      await expect(page.getByTestId('onboarding-install-ok')).toBeVisible()
      await expect(terminal).toContainText('GET /api/v1/health')
      await expect(terminal).toContainText('0.0.1')
      await expect(terminal).toContainText('storage=ok')
      await expect(page.getByTestId('onboarding-install-absent')).toHaveCount(0)
      // Reachability is not SDK verification, and the step says so.
      await expect(page.getByTestId('onboarding-install-caveat')).toContainText(
        'not a verified SDK',
      )
      await expect(page.getByTestId('onboarding-continue')).toBeEnabled()
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-install').screenshot({
        path: `${EVIDENCE_DIR}/step2-gateway-up-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 2 renders a real 503 as a named degradation, not as silence, in ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { health: 'degraded' })
      await gotoStep(page, 'install')

      await page.getByTestId('onboarding-install-verify').click()

      // ── 2b. a 503 with a body is an ANSWER — the operator is told what broke ─
      const warn = page.getByTestId('onboarding-install-warn')
      await expect(warn).toBeVisible()
      await expect(warn).toContainText('storage')
      const terminal = page.getByTestId('onboarding-install-terminal')
      await expect(terminal).toContainText('storage=degraded')
      // Not "the gateway did not answer" — it answered, in detail.
      await expect(terminal).not.toContainText('did not answer')
      await expect(page.getByTestId('onboarding-install-err')).toHaveCount(0)
      await expect(page.getByTestId('onboarding-install-absent')).toHaveCount(0)
      // Reachable is not healthy: the step still does not pass.
      await expect(page.getByTestId('onboarding-install-ok')).toHaveCount(0)
      await expect(page.getByTestId('onboarding-continue')).toBeDisabled()
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-install').screenshot({
        path: `${EVIDENCE_DIR}/step2-gateway-degraded-${theme}.png`,
      })
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`step 2 withdraws a healthy verdict when a re-check fails in ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { health: 'up' })
      await gotoStep(page, 'install')

      await page.getByTestId('onboarding-install-verify').click()
      await expect(page.getByTestId('onboarding-install-ok')).toBeVisible()
      await expect(page.getByTestId('onboarding-continue')).toBeEnabled()

      // The gateway goes away between probes.
      await page.unroute('**/api/v1/health**')
      await page.route('**/api/v1/health**', (r) => r.abort('connectionrefused'))
      await page.getByTestId('onboarding-install-verify').click()

      // ── 2c. the verdict is withdrawn: no green footer over a red transcript ─
      await expect(page.getByTestId('onboarding-install-absent')).toHaveAttribute(
        'data-truth-state',
        'unavailable',
      )
      await expect(page.getByTestId('onboarding-install-ok')).toHaveCount(0)
      await expect(page.getByTestId('onboarding-continue')).toBeDisabled()
      await expect(page.locator('.onb-foot-meta')).not.toContainText('ready to continue')

      await page.getByTestId('onboarding-wizard').screenshot({
        path: `${EVIDENCE_DIR}/step2-verdict-withdrawn-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 2 copy button reports a failed clipboard write in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { breakClipboard: true })
      await gotoStep(page, 'install')

      // ── 3. AAASM-5145 — the non-secure-context case ──────────────────────
      const copy = page.getByTestId('onboarding-install-copy')
      await copy.click()
      await expect(copy).toHaveAttribute('data-copy-state', 'failed')
      await expect(copy).toContainText('copy failed')
      await expect(copy).not.toContainText('✓ copied')
      await expect(page.getByTestId('onboarding-install-copy-error')).toBeVisible()

      await page.getByTestId('onboarding-step-install').screenshot({
        path: `${EVIDENCE_DIR}/step2-clipboard-failed-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 3 offers no identity issuance and claims no key in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await gotoStep(page, 'identity')

      // ── 4. AAASM-5179 — not-supported, no action, no key claim ───────────
      const state = page.getByTestId('onboarding-identity-unsupported')
      await expect(state).toBeVisible()
      await expect(state).toHaveAttribute('data-truth-state', 'not-supported')
      await expect(state).toContainText('Not supported')
      await expect(page.getByTestId('onboarding-identity-generate')).toHaveCount(0)
      await expect(page.getByTestId('onboarding-step-identity').getByRole('button')).toHaveCount(0)
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-identity').screenshot({
        path: `${EVIDENCE_DIR}/step3-not-supported-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 5 renders a failed registry poll as unavailable, not zero, in ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { registry: 'fail' })
      await gotoStep(page, 'enroll')

      await page.getByTestId('onboarding-enroll-start').click()

      // ── 5. a failed request is never a count ─────────────────────────────
      const count = page.getByTestId('onboarding-enroll-count-value')
      await expect(count).toHaveAttribute('data-truth-state', 'unavailable')
      await expect(page.getByTestId('onboarding-enroll-count')).not.toContainText('0')
      const absence = page.getByTestId('onboarding-enroll-absent')
      await expect(absence).toHaveAttribute('data-truth-state', 'unavailable')
      await expect(absence).toHaveAttribute('role', 'alert')
      await expect(page.getByTestId('onboarding-enroll-connected')).toHaveCount(0)
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-enroll').screenshot({
        path: `${EVIDENCE_DIR}/step5-registry-unavailable-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 5 keeps an empty registry apart from an enrollment in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { registry: 'empty' })
      await gotoStep(page, 'enroll')

      await page.getByTestId('onboarding-enroll-start').click()

      // ── 6. an answered zero is a real answer, and is not an enrollment ────
      const count = page.getByTestId('onboarding-enroll-count-value')
      await expect(count).toHaveText('0')
      await expect(count).toHaveAttribute('data-truth-state', 'known')
      await expect(page.getByTestId('onboarding-enroll-empty')).toBeVisible()
      await expect(page.getByTestId('onboarding-enroll-connected')).toHaveCount(0)
      // Finish stays disabled: no agent has enrolled.
      await expect(page.getByTestId('onboarding-continue')).toBeDisabled()
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-enroll').screenshot({
        path: `${EVIDENCE_DIR}/step5-registry-empty-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })

    test(`step 5 reports a real registered agent in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme, { registry: 'agent' })
      await gotoStep(page, 'enroll')

      await page.getByTestId('onboarding-enroll-start').click()

      // ── 7. the count is the registry's, and the row is the agent it named ─
      await expect(page.getByTestId('onboarding-enroll-count-value')).toHaveText('1')
      await expect(page.getByTestId('onboarding-enroll-connected')).toBeVisible()
      const row = page.getByTestId(`onboarding-enroll-agent-${AGENT.id}`)
      await expect(row).toContainText('research-bot')
      await expect(row).toContainText('2026-07-26T09:00:00Z')
      await expect(page.getByTestId('onboarding-continue')).toBeEnabled()
      await expectNoFabrications(page)

      await page.getByTestId('onboarding-step-enroll').screenshot({
        path: `${EVIDENCE_DIR}/step5-registry-agent-${theme}.png`,
      })
      expect(harness.errors).toEqual([])
    })
  }
})
