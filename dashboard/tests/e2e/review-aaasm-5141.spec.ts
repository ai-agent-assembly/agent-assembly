/**
 * Review pass for the policy-editor lane (AAASM-5141 / AAASM-5142).
 *
 * Both regressions are driven through the real overlay against a real
 * four-rule policy, rather than asserted from a fixture the page never sees:
 *
 *  1. editing exactly one rule of four makes the pre-save footer say one rule
 *     was modified, not four — and the count agrees with the number of dirty
 *     dots the operator can see on the rule cards (AAASM-5141);
 *  2. adding a rule, removing a rule, and touching only policy metadata each
 *     report their own true blast radius rather than the policy's rule total
 *     (AAASM-5141);
 *  3. the footer "▸ Simulate impact" button opens the shipped single-request
 *     dry-run panel — the ratified v0 Simulate (ADR-0017 item 6) — and never
 *     says the feature is unbuilt (AAASM-5142);
 *  4. the simulator runs from inside the editor and returns a real verdict,
 *     with the editor and its unsaved draft still mounted behind it;
 *  5. an invalid draft still refuses to simulate, and opens no panel;
 *  6. Esc while the simulator is up dismisses the simulator alone — the editor
 *     behind it survives, and Esc dismisses it once the simulator is gone;
 *  7. neither theme produces console errors or uncaught exceptions.
 *
 * `openapi-fetch` captures `globalThis.fetch` at module load, so the policy
 * list and the simulate response are injected with `page.route` and the token
 * is seeded with `addInitScript` before any module runs — a fetch shim
 * installed later would never be seen.
 *
 * Screenshots land in dashboard/verify/5141/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5141')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * A real four-rule policy in the editor's own `spec.rules` schema — the shape
 * `serializeDraft` writes — so `draftFromPolicy` recovers four *editable*
 * rules. A policy whose body is unrecoverable loads as read-only `unknown`
 * rules, which cannot be edited and so cannot exercise the count at all.
 */
const POLICY_YAML = [
  'metadata:',
  '  name: research-bot-guardrails',
  '  scope: agent:research-bot-04',
  '  version: 2.1.0',
  'spec:',
  '  rules:',
  '    - id: R1',
  '      match:',
  '        actions: ["gmail:read"]',
  '      effect: allow',
  '    - id: R2',
  '      match:',
  '        actions: ["gdrive:read"]',
  '      effect: allow',
  '    - id: R3',
  '      match:',
  '        actions: ["s3:read"]',
  '      effect: block',
  '    - id: R4',
  '      match:',
  '        actions: ["shell:exec"]',
  '      effect: block',
  '',
].join('\n')

const POLICY = {
  name: 'research-bot-guardrails',
  version: '2.1.0',
  rule_count: 4,
  active: true,
  policy_yaml: POLICY_YAML,
}

const SIMULATE_VERDICT = {
  verdict: 'deny',
  matched_rule: 'R3',
  reason: 's3:read is blocked for this agent',
  redacted: false,
}

interface Harness {
  errors: string[]
  /** Every request that reached the simulate endpoint. */
  simulateCalls: unknown[]
}

/**
 * Minimal unsigned JWT. The claim is `scope` (an array), which is what
 * `parseScopesFromJwt` reads; the signature is irrelevant because the
 * dashboard never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5141', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const harness: Harness = { errors: [], simulateCalls: [] }

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
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/audit/sandbox-summary**', (r) =>
    r.fulfill({ status: 404, json: { detail: 'no sandbox summary' } }),
  )
  // AAASM-4892: `/policies` serves a paginated `{ items, total }` envelope.
  await page.route('**/api/v1/policies**', (r) =>
    r.fulfill({ json: { items: [POLICY], total: 1 } }),
  )
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies/simulate', (r) => {
    harness.simulateCalls.push(r.request().postDataJSON())
    return r.fulfill({ json: SIMULATE_VERDICT })
  })
  await page.route('**/api/v1/ws/events**', (r) => r.abort())

  return harness
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

/** Land on /policies and open the four-rule policy in the editor overlay. */
async function openEditor(page: Page) {
  await page.goto('/policies')
  await expect(page.getByTestId('policies-page')).toBeVisible()
  await page.getByTestId('policy-row').first().click()
  await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
  // All four rules must be genuinely editable, or the count proves nothing.
  await expect(page.getByTestId('editor-rule-3')).toBeVisible()
  await expect(page.getByTestId('editor-rule-0-unknown')).toHaveCount(0)
}

const footer = (page: Page) => page.getByTestId('editor-footer-status')

test.describe('AAASM-5141 / 5142 review — the policy editor states its real blast radius and opens the real simulator', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`one edited rule of four reads as one, not four — ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await openEditor(page)

      // Clean: the footer states the policy's size, which is a different claim.
      await expect(footer(page)).toHaveText(/Active · 4 rule\(s\)/)
      await shot(page, `blast-radius-clean-${theme}`)

      // Touch exactly one rule of the four.
      await page.getByTestId('editor-rule-1-verb-write').click()

      await expect(page.getByTestId('editor-dirty-chip')).toBeVisible()
      await expect(footer(page)).toHaveText(/^1 rule\(s\) modified/)
      await expect(footer(page)).not.toHaveText(/4 rule\(s\) modified/)
      // The number the footer prints and the dots the operator sees agree.
      await expect(page.locator('[data-testid$="-dirty-dot"]')).toHaveCount(1)
      await shot(page, `blast-radius-one-edit-${theme}`)

      // A second, separately-edited rule moves it to two — still not four.
      await page.getByTestId('editor-rule-3-verb-read').click()
      await expect(footer(page)).toHaveText(/^2 rule\(s\) modified/)
      await expect(page.locator('[data-testid$="-dirty-dot"]')).toHaveCount(2)
      await shot(page, `blast-radius-two-edits-${theme}`)

      expect(harness.errors).toEqual([])
    })

    test(`add, remove and metadata-only edits each report their own radius — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)

      // ── an added rule is one modification, not the new total of five ──
      await openEditor(page)
      await page.getByTestId('editor-add-rule').click()
      await expect(page.getByTestId('editor-rule-4')).toBeVisible()
      await expect(footer(page)).toHaveText(/^1 rule\(s\) modified/)
      await shot(page, `blast-radius-added-rule-${theme}`)

      // ── a removed rule is one modification, not the remaining three ──
      await page.reload()
      await openEditor(page)
      await page.getByTestId('editor-rule-1-remove').click()
      await expect(page.getByTestId('editor-rule-3')).toHaveCount(0)
      await expect(footer(page)).toHaveText(/^1 rule\(s\) modified/)
      await shot(page, `blast-radius-removed-rule-${theme}`)

      // ── metadata alone modifies no rule, and says so ─────────────────
      await page.reload()
      await openEditor(page)
      await page.getByTestId('editor-scope-input').fill('agent:research-bot-05')
      await expect(page.getByTestId('editor-dirty-chip')).toBeVisible()
      await expect(footer(page)).toHaveText(/^0 rule\(s\) modified/)
      await shot(page, `blast-radius-metadata-only-${theme}`)

      expect(harness.errors).toEqual([])
    })

    test(`the footer Simulate button opens the shipped dry-run and runs it — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await openEditor(page)

      // An unsaved edit, so the run also proves the draft survives.
      await page.getByTestId('editor-rule-1-verb-write').click()
      await expect(footer(page)).toHaveText(/^1 rule\(s\) modified/)

      await expect(page.getByTestId('policy-simulate')).toHaveCount(0)
      await page.getByTestId('editor-simulate-btn').click()

      // The real panel, not a toast asserting the feature does not exist.
      const panel = page.getByTestId('policy-simulate')
      await expect(panel).toBeVisible()
      await expect(page.getByText(/coming soon/i)).toHaveCount(0)
      await shot(page, `simulate-open-from-editor-${theme}`)

      // It is a working simulator, not a shell: it round-trips a verdict.
      await page.getByTestId('simulate-tool-input').fill('s3_get')
      await page.getByTestId('simulate-target-input').fill('customer-pii/export.csv')
      await page.getByTestId('simulate-run-btn').click()
      await expect(page.getByTestId('simulate-verdict')).toHaveAttribute(
        'data-verdict',
        'deny',
      )
      await expect(page.getByTestId('simulate-matched-rule')).toHaveText('R3')
      expect(harness.simulateCalls).toHaveLength(1)
      await shot(page, `simulate-verdict-from-editor-${theme}`)

      // The editor and its unsaved draft are still there underneath.
      await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
      await page.getByTestId('policy-simulate-close').click()
      await expect(panel).toHaveCount(0)
      await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
      await expect(footer(page)).toHaveText(/^1 rule\(s\) modified/)
      await shot(page, `simulate-closed-draft-intact-${theme}`)

      expect(harness.errors).toEqual([])
    })

    test(`an invalid draft refuses to simulate and opens no panel — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await openEditor(page)

      // Strip R1's only verb to force a validation error.
      await page.getByTestId('editor-rule-0-verb-read').click()
      await page.getByTestId('editor-simulate-btn').click()

      await expect(
        page.getByText(/Fix validation errors before simulating/),
      ).toBeVisible()
      await expect(page.getByTestId('policy-simulate')).toHaveCount(0)
      expect(harness.simulateCalls).toEqual([])
      await shot(page, `simulate-blocked-by-validation-${theme}`)

      expect(harness.errors).toEqual([])
    })

    test(`Esc dismisses the simulator alone, then the editor — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme)
      await openEditor(page)
      await page.getByTestId('editor-simulate-btn').click()
      await expect(page.getByTestId('policy-simulate')).toBeVisible()

      // The simulator is a top-layer <dialog>, but its Esc keydown still
      // reaches the document listener OverlayHost installs. That dismiss
      // belongs to the topmost surface only.
      await page.keyboard.press('Escape')
      await expect(page.getByTestId('policy-simulate')).toHaveCount(0)
      await expect(page.getByTestId('policy-editor-overlay')).toBeVisible()
      await shot(page, `esc-closes-simulator-only-${theme}`)

      // And Esc still dismisses the editor once the simulator is gone.
      await page.keyboard.press('Escape')
      await expect(page.getByTestId('policy-editor-overlay')).toHaveCount(0)

      expect(harness.errors).toEqual([])
    })
  }
})
