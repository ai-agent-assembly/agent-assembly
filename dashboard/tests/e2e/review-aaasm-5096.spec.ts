/**
 * Review pass for AAASM-5096 — independent validation of the two surfaces the
 * enriched policy contract unblocks, against a realistic payload.
 *
 * Re-derives the claims a reviewer would otherwise take on trust, so a
 * regression shows up as a failure rather than as a screenshot nobody diffs:
 *
 *  1. the Policy list row renders one chip per agent in `affects`, collapsing
 *     the tail into `+N`;
 *  2. a row whose version is not in force carries no `affects` key at all and
 *     folds to the shared `—` — never to "0 agents";
 *  3. `hits24h` is absent on every row and folds to `—`, never to `0` (there is
 *     no audit source for it — AAASM-5100 / ADR 0018);
 *  4. the Teams Active-policies card lists the documents in force for the
 *     selected team with the cascade tier each comes from, and a team with no
 *     document in force says so explicitly rather than showing an empty list;
 *  5. neither page produces console errors or uncaught exceptions.
 *
 * Screenshots land in dashboard/verify/5096/.
 */
import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5096')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

/**
 * The enriched `GET /api/v1/policies` payload.
 *
 * `in-force` carries five affected agents so the `+N` collapse is exercised;
 * `retired` deliberately omits `affects` entirely — that is what the API emits
 * for a version the running engine does not carry, and the point of the run is
 * that the row treats "absent" and "empty" as different things. Neither carries
 * `hits24h`: nothing attributes an audit decision to a policy document.
 */
const AFFECTED = ['research-bot', 'support-triage', 'sales-outreach', 'docs-summarizer', 'etl-worker']
const POLICIES = {
  items: [
    {
      name: 'in-force',
      version: '2026-07-26T09:00:00Z',
      active: true,
      rule_count: 4,
      policy_yaml: 'metadata:\n  name: in-force\nscope: team:data-platform\nrules: []\n',
      affects: AFFECTED,
    },
    {
      // No `affects` key, no `hits24h` key.
      name: 'retired',
      version: '2026-07-20T09:00:00Z',
      active: false,
      rule_count: 2,
      policy_yaml: 'metadata:\n  name: retired\nscope: global\nrules: []\n',
    },
  ],
  page: 1,
  per_page: 50,
  total: 2,
}

/** Two documents in force for data-platform: one fleet-wide, one team-authored. */
const DATA_PLATFORM_POLICIES = {
  team_id: 'data-platform',
  policies: [
    { id: 'global/baseline', name: 'baseline', scope: 'global', version: '1.0.0' },
    { id: 'team:data-platform/pii-guard', name: 'pii-guard', scope: 'team:data-platform', version: '3.4.1' },
  ],
}

/** A team the engine carries no document for — an explicit statement, not a blank. */
const GROWTH_POLICIES = { team_id: 'growth', policies: [] as unknown[] }

const TOPOLOGY_OVERVIEW = {
  root_agent_count: 2,
  team_count: 2,
  total_agent_count: 4,
  teams: [
    { team_id: 'data-platform', agent_count: 3, root_agent_count: 1 },
    { team_id: 'growth', agent_count: 1, root_agent_count: 1 },
  ],
  standalone_root_agents: [] as unknown[],
}

const DATA_PLATFORM_TEAM = {
  team_id: 'data-platform',
  agent_count: 3,
  members: [
    { id: 'a1', name: 'orchestrator', status: 'active', depth: 0, flagged: false, mode: 'enforce' },
    { id: 'a2', name: 'etl-worker', status: 'active', depth: 1, flagged: false, mode: 'enforce' },
  ],
}

const COST_SUMMARY = {
  date: '2026-07-26',
  daily_spend_usd: '48.00',
  daily_limit_usd: '200.00',
  per_team: [{ team_id: 'data-platform', date: '2026-07-26', daily_spend_usd: '48.00', monthly_spend_usd: null }],
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
      sessionStorage.setItem('aa_token', 'e2e-review-5096')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Permissive fallback first (least specific); specific fixtures registered
  // afterwards win, since Playwright matches most-recently-added first.
  await page.route('**/api/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/costs**', (r) => r.fulfill({ json: COST_SUMMARY }))
  await page.route('**/api/v1/topology/overview**', (r) => r.fulfill({ json: TOPOLOGY_OVERVIEW }))
  await page.route('**/api/v1/topology/team/data-platform**', (r) => r.fulfill({ json: DATA_PLATFORM_TEAM }))
  await page.route('**/api/v1/policies', (r) => r.fulfill({ json: POLICIES }))
  await page.route('**/api/v1/policies/team/data-platform**', (r) => r.fulfill({ json: DATA_PLATFORM_POLICIES }))
  await page.route('**/api/v1/policies/team/growth**', (r) => r.fulfill({ json: GROWTH_POLICIES }))
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

test.describe('AAASM-5096 review — enriched policy contract', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`policy list row reach + hits hold up in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/policies')
      await expect(page.getByTestId('policies-list')).toBeVisible()

      const rows = page.getByTestId('policy-row')
      await expect(rows).toHaveCount(2)

      // ── 1. real reach renders as chips, with the tail collapsed ──────────
      const affects = page.getByTestId('policy-row-affects')
      await expect(affects).toHaveCount(1)
      for (const agent of AFFECTED.slice(0, 3)) {
        await expect(affects).toContainText(agent)
      }
      await expect(page.getByTestId('policy-row-affects-overflow')).toHaveText('+2')

      // ── 2. an absent reach folds to `—`, never to "0 agents" ─────────────
      const emptyReach = page.getByTestId('policy-row-affects-empty')
      await expect(emptyReach).toHaveCount(1)
      await expect(emptyReach).toHaveText('—')

      // ── 3. hits24h is absent on every row and folds to `—`, never 0 ──────
      const hits = page.getByTestId('policy-row-hits')
      await expect(hits).toHaveCount(2)
      for (let i = 0; i < 2; i += 1) {
        await expect(hits.nth(i)).toContainText('—')
        await expect(hits.nth(i)).not.toContainText('0 hits')
      }

      // Nothing invented a placeholder value anywhere on the list.
      await expect(page.getByTestId('policies-list')).not.toContainText('undefined')
      await expect(page.getByTestId('policies-list')).not.toContainText('NaN')

      await page.getByTestId('policies-list').screenshot({
        path: `${EVIDENCE_DIR}/policy-list-affects-hits-${theme}.png`,
      })

      // ── 5. clean console ────────────────────────────────────────────────
      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })

    test(`teams active-policies card renders the real cascade in ${theme}`, async ({ page }) => {
      const harness = await bootstrap(page, theme)
      await navigate(page, '/teams')
      await expect(page.getByTestId('teams-two-pane')).toBeVisible()

      // ── 4. the card lists the documents in force, with their tiers ───────
      const card = page.getByTestId('team-policies-card')
      await expect(card).toBeVisible()
      await expect(card).toContainText('Active policies (2)')
      await expect(page.getByTestId('team-policy-row')).toHaveCount(2)
      const scopes = page.getByTestId('team-policy-scope')
      await expect(scopes.nth(0)).toHaveText('global')
      await expect(scopes.nth(1)).toHaveText('team:data-platform')
      // Absent hit counts fold here too.
      const hits = page.getByTestId('team-policy-hits')
      await expect(hits.nth(0)).toHaveText('—')
      await expect(hits.nth(1)).toHaveText('—')
      await expect(card).not.toContainText('undefined')

      await card.screenshot({ path: `${EVIDENCE_DIR}/teams-active-policies-${theme}.png` })

      // A team the engine carries no document for says so, rather than
      // rendering a blank list that reads as a load failure.
      await page.getByTestId('team-list-row').filter({ hasText: 'growth' }).first().click()
      await expect(page.getByTestId('team-policies-empty')).toContainText('No policy is in force')
      await expect(page.getByTestId('team-policies-card')).toContainText('Active policies (0)')
      await page.getByTestId('team-policies-card').screenshot({
        path: `${EVIDENCE_DIR}/teams-active-policies-empty-${theme}.png`,
      })

      expect(harness.errors, 'no console errors or uncaught exceptions').toEqual([])
    })
  }
})
