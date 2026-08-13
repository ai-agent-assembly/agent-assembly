/**
 * Verification capture for AAASM-5090 — the real capability-matrix endpoint.
 *
 * Serves the shape the live projection actually returns: real registry- and
 * policy-derived columns (id, name, framework, owner, status, lastSeen, caps)
 * with every unsourced field *absent* rather than zeroed — no trust score, no
 * over-permission flag, no per-policy hit count, no call samples, and no group
 * on a tool column. The capture proves the page folds each of those to the `—`
 * placeholder instead of rendering a fabricated 0.
 *
 * Screenshots land in dashboard/verify/5090/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5090')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const ID_A = 'a1'.repeat(16)
const ID_B = 'b2'.repeat(16)

// Exactly what `GET /api/v1/capability/matrix` now emits: the three system
// capability families plus a declared tool column, and agents whose trust /
// mode / flagged / note fields are omitted because the gateway has no source.
const MATRIX = {
  resources: [
    { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
    { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
    { id: 'network_outbound', name: 'Network (outbound)', group: 'infra', paths: [] },
    // A tool column: operator-supplied name, deliberately ungrouped.
    { id: 'search', name: 'search', paths: [] },
  ],
  agents: [
    {
      id: ID_A,
      name: 'checkout-agent',
      framework: 'langgraph',
      owner: 'team-alpha',
      status: 'active',
      mode: 'enforce',
      lastSeen: new Date(Date.now() - 120_000).toISOString(),
      caps: {
        filesystem: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
        search: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      },
    },
    {
      // Registered without a team and without an enforcement-mode override, so
      // owner and mode are absent too — both must render as `—`.
      id: ID_B,
      name: 'refund-agent',
      framework: 'crewai',
      status: 'active',
      lastSeen: new Date(Date.now() - 3_600_000).toISOString(),
      caps: {
        filesystem: { read: 'allow', write: 'allow', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
        network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        search: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
      },
    },
  ],
  policies: [
    {
      id: 'global',
      name: 'baseline',
      scope: 'global',
      status: 'active',
      affects: [ID_A, ID_B],
      rules: [{ resource: 'filesystem', verb: ['write'], action: 'deny', condition: '' }],
    },
  ],
  // Call samples need a proposed-vs-current policy diff nothing computes yet.
  sampleCalls: [],
  // AAASM-5106 / ADR 0024: a cascade is loaded (the baseline policy above), so
  // the matrix projects real cells rather than folding to "not evaluated".
  cascadeLoaded: true,
}

async function bootstrap(page: Page, theme: Theme) {
  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-5090')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/fleet/active-sessions**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/capability/matrix**', (r) => r.fulfill({ json: MATRIX }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
}

test.describe('AAASM-5090 — real capability matrix', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`matrix renders projected cells and folds absent fields in ${theme}`, async ({ page }) => {
      await bootstrap(page, theme)
      await page.goto('/capability')
      await page.getByTestId('capability-page').waitFor()
      await page.getByRole('heading', { name: /Capability/ }).waitFor()

      // Real projected columns are present, including the ungrouped tool column.
      await expect(page.getByRole('columnheader', { name: /Filesystem/ })).toBeVisible()
      await expect(page.getByRole('columnheader', { name: /Terminal/ })).toBeVisible()
      await expect(page.getByRole('columnheader', { name: /search/ })).toBeVisible()

      // Trust has no source, so every row shows the placeholder — never "trust 0".
      await expect(page.getByText('trust —').first()).toBeVisible()
      await expect(page.getByText('trust 0')).toHaveCount(0)

      await page.screenshot({ path: `${EVIDENCE_DIR}/capability-matrix-${theme}.png`, fullPage: true })

      // --- Per-agent tab: owner / mode / trust all fold on the team-less agent. ---
      await page.getByRole('button', { name: 'Per-agent' }).click()
      await page.getByRole('button', { name: /refund-agent/ }).click()
      await expect(page.getByText(/crewai\s*·\s*—\s*·\s*trust\s*—\s*·\s*—\s*mode/)).toBeVisible()
      await page.screenshot({ path: `${EVIDENCE_DIR}/capability-per-agent-${theme}.png`, fullPage: true })

      // --- Per-resource tab: lastSeen is formatted from the real ISO stamp. ---
      // Since AAASM-5125 the page lands on the verb the projection populates
      // most (EXEC here, not the old hard-coded WRITE), and the per-resource
      // tree defaults to the first resource (Filesystem). No agent declares
      // EXEC on Filesystem, so that pairing is empty; select Terminal, on which
      // checkout-agent (lastSeen 2m ago) declares EXEC, to show a formatted row.
      await page.getByRole('button', { name: 'Per-resource' }).click()
      await page.getByTestId('per-resource-node-terminal').click()
      await expect(page.getByText('2m ago').first()).toBeVisible()
      await page.screenshot({ path: `${EVIDENCE_DIR}/capability-per-resource-${theme}.png`, fullPage: true })
    })
  }
})
