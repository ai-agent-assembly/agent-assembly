/**
 * Review pass for AAASM-5090 — independent validation of the Capability page
 * against a realistic `GET /api/v1/capability/matrix` payload.
 *
 * The capture spec (`verify-aaasm-5090.spec.ts`) documents the feature; this one
 * re-derives the claims a reviewer has to trust, so a regression in either shows
 * up as a failure rather than as a screenshot nobody diffs:
 *
 *  1. the grid is genuinely agents × resources, with allow / deny / na cells
 *     addressable by decision;
 *  2. every field the endpoint legitimately omits (`trust`, `flagged`,
 *     `hits24h`, `sampleCalls`, and a tool column's `group`) folds to the shared
 *     `—` affordance or an explicit empty state — never to a fabricated `0`;
 *  3. the filter bar narrows the grid (search, framework, mode);
 *  4. the page produces no console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5090/review/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5090/review')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const ID_A = 'a1'.repeat(16)
const ID_B = 'b2'.repeat(16)

/**
 * The projection's real shape. Absent keys are absent on purpose — they are the
 * fields the gateway has no source for, and the point of the run is that the UI
 * treats "absent" and "zero" as different things.
 */
const MATRIX = {
  resources: [
    { id: 'filesystem', name: 'Filesystem', group: 'files', paths: [] },
    { id: 'terminal', name: 'Terminal', group: 'infra', paths: [] },
    { id: 'network_outbound', name: 'Network (outbound)', group: 'infra', paths: [] },
    // Tool columns are operator-named and carry no group — the projection has no
    // taxonomy to put them in.
    { id: 'send_email', name: 'send_email', paths: [] },
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
      // No trust, no flagged, no note.
      caps: {
        filesystem: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
        send_email: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
      },
    },
    {
      // Registered without a team and without an enforcement-mode override.
      id: ID_B,
      name: 'refund-agent',
      framework: 'crewai',
      status: 'active',
      lastSeen: new Date(Date.now() - 3_600_000).toISOString(),
      caps: {
        filesystem: { read: 'allow', write: 'allow', delete: 'deny', exec: 'na' },
        terminal: { read: 'na', write: 'na', delete: 'na', exec: 'deny' },
        network_outbound: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
        send_email: { read: 'na', write: 'na', delete: 'na', exec: 'allow' },
      },
    },
  ],
  policies: [
    {
      id: 'global/baseline',
      name: 'baseline',
      version: '3',
      scope: 'global',
      status: 'active',
      // hits24h omitted: no per-policy counter exists.
      affects: [ID_A, ID_B],
      rules: [
        { resource: 'filesystem', verb: ['write'], action: 'deny', condition: '' },
        { resource: 'send_email', verb: ['exec'], action: 'deny', condition: '' },
      ],
    },
  ],
  // Call samples need a proposed-vs-current policy diff nothing computes yet.
  sampleCalls: [],
  // AAASM-5106 / ADR 0024: `cascadeLoaded` is required-but-always-present on the
  // wire, so a realistic payload carries it — the fields this fixture omits are
  // the ones the gateway genuinely has no source for, and this is not one of
  // them. Omitting it made `decodeCascadeFields` reject the body and render the
  // cascade lane's "shape this dashboard cannot read" absence, which is a
  // different surface from the absent-vs-zero folds this spec exists to check.
  cascadeLoaded: true,
}

interface Harness {
  errors: string[]
}

async function bootstrap(page: Page, theme: Theme): Promise<Harness> {
  const errors: string[] = []
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(m.text())
  })
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))

  // The token must be seeded before any module executes: openapi-fetch captures
  // globalThis.fetch at module load, so an in-page fetch shim installed later
  // would never be consulted. Routing happens at the network layer for the same
  // reason.
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-review-5090')
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

  return { errors }
}

test.describe('AAASM-5090 review — capability matrix page', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`grid, absent-field folds and filters hold up in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await page.goto('/capability')
      await page.getByTestId('capability-page').waitFor()

      // ── 1. agents × resources ───────────────────────────────────────────
      const grid = page.getByRole('grid', { name: 'capability matrix' })
      await expect(grid).toBeVisible()
      // One header per resource, plus the corner cell.
      await expect(grid.getByRole('columnheader')).toHaveCount(MATRIX.resources.length + 1)
      await expect(grid.getByRole('rowheader')).toHaveCount(MATRIX.agents.length)
      // 2 agents × 4 resources of cells. Since AAASM-5125 the page lands on the
      // verb the loaded projection populates most, not a hard-coded WRITE: EXEC
      // has 6 non-na cells (Terminal/Network/send_email carry exec) against
      // WRITE's 2 (Filesystem alone), so this fixture opens on EXEC — allow on
      // A/terminal, B/network, B/send_email; deny on A/network, A/send_email,
      // B/terminal; na on both Filesystem exec cells.
      await expect(grid.getByRole('gridcell')).toHaveCount(
        MATRIX.agents.length * MATRIX.resources.length,
      )
      await expect(grid.locator('[data-decision="allow"]')).toHaveCount(3)
      await expect(grid.locator('[data-decision="deny"]')).toHaveCount(3)
      await expect(grid.locator('[data-decision="na"]')).toHaveCount(2)

      // WRITE is where the Filesystem column carries the only decisions: one
      // allow (refund-agent) and one deny (checkout-agent), the rest na.
      await page.getByRole('radio', { name: 'write' }).click()
      await expect(grid.locator('[data-decision="allow"]')).toHaveCount(1)
      await expect(grid.locator('[data-decision="deny"]')).toHaveCount(1)
      await expect(grid.locator('[data-decision="na"]')).toHaveCount(6)

      // ── 2. absent fields fold to `—`, never to 0 ────────────────────────
      // trust: absent on both agents.
      await expect(page.getByText('trust —')).toHaveCount(MATRIX.agents.length)
      await expect(page.getByText('trust 0')).toHaveCount(0)
      // No trust score means no bar — an empty bar reads as zero.
      await expect(grid.locator('.cap-trust-bar')).toHaveCount(0)
      // flagged: absent, so no flag dot anywhere.
      await expect(page.getByLabel('agent flagged')).toHaveCount(0)
      await expect(page.getByLabel('recent flag')).toHaveCount(0)
      // owner: absent on refund-agent only.
      await expect(grid.getByRole('rowheader').filter({ hasText: 'refund-agent' })).toContainText('—')
      // tool column group: absent, so the group strip is empty rather than
      // rendering "undefined" or "0".
      const toolHeader = grid.getByRole('columnheader').filter({ hasText: 'send_email' })
      await expect(toolHeader.locator('.cap-mx-col-h-group')).toHaveText('')
      await expect(toolHeader).not.toContainText('undefined')
      // Nothing on the page invented a zero for the omitted counters.
      await expect(page.getByText('undefined')).toHaveCount(0)
      await expect(page.getByText('NaN')).toHaveCount(0)

      await page.screenshot({ path: `${EVIDENCE_DIR}/matrix-${theme}.png`, fullPage: true })

      // sampleCalls / hits24h: the drawer must show its empty state, not a 0 row.
      await grid.locator('[data-decision="deny"]').first().click()
      const drawer = page.getByRole('dialog', { name: 'capability cell inspect' })
      await expect(drawer).toBeVisible()
      await expect(drawer.getByText('no recent calls')).toBeVisible()
      await expect(drawer.locator('table.cap-drawer-calls')).toHaveCount(0)
      await expect(drawer).toContainText('baseline')
      await page.screenshot({ path: `${EVIDENCE_DIR}/cell-inspect-${theme}.png`, fullPage: true })
      await drawer.getByLabel('close drawer').click()
      await expect(drawer).toBeHidden()

      // ── 3. filter bar ───────────────────────────────────────────────────
      const bar = page.getByRole('search')
      await expect(bar).toContainText('2 of 2 agents')

      await bar.getByLabel('search agents').fill('refund')
      await expect(bar).toContainText('1 of 2 agents')
      await expect(grid.getByRole('rowheader')).toHaveCount(1)
      await expect(grid.getByRole('rowheader')).toContainText('refund-agent')
      await page.screenshot({ path: `${EVIDENCE_DIR}/filtered-${theme}.png`, fullPage: true })
      await bar.getByLabel('search agents').fill('')
      await expect(grid.getByRole('rowheader')).toHaveCount(2)

      // framework select is built from the agents actually present.
      const framework = bar.locator('select').first()
      await expect(framework.locator('option')).toHaveText(['any', 'crewai', 'langgraph'])
      await framework.selectOption('langgraph')
      await expect(grid.getByRole('rowheader')).toHaveCount(1)
      await expect(grid.getByRole('rowheader')).toContainText('checkout-agent')
      await framework.selectOption('any')

      // mode: only the agent that declared one is an option, and filtering on it
      // excludes the agent whose mode is absent (not "" matching everything).
      const mode = bar.locator('select').nth(2)
      await expect(mode.locator('option')).toHaveText(['any', 'enforce'])
      await mode.selectOption('enforce')
      await expect(grid.getByRole('rowheader')).toHaveCount(1)
      await expect(grid.getByRole('rowheader')).toContainText('checkout-agent')
      await mode.selectOption('any')
      await expect(grid.getByRole('rowheader')).toHaveCount(2)

      // ── 4. clean console ────────────────────────────────────────────────
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
