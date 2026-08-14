/**
 * Review pass for the restored "Avg / agent today" KPI (AAASM-5159).
 *
 * Design-QA re-audit finding: the fourth spec KPI on
 * `design/v1/hi-fi/costs.jsx:299-305` — `daily_spend / per_agent.length`,
 * captioned with `costs.date` — had no shipped equivalent. ADR-0017 item 14
 * ratifies Utilisation and Blocked-by-budget as *additive* to the spec strip,
 * not a replacement for one of its four cards, so the missing card was a
 * genuine regression rather than an intentional simplification.
 *
 * Two cases, each in both themes:
 *
 *  1. a normal roster renders the computed average with the cost date as its
 *     sub-caption;
 *  2. a genuinely zero-agent roster renders the canonical absence glyph, never
 *     `NaN` or a fabricated `$0.00`.
 *
 * Screenshots land in dashboard/verify/5159/.
 */
import { test, expect, type Page, type Route } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5159')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const OVERVIEW = {
  root_agent_count: 2,
  standalone_root_agents: [],
  team_count: 2,
  total_agent_count: 5,
  teams: [
    { team_id: 'team-hot', agent_count: 3, root_agent_count: 1 },
    { team_id: 'team-cool', agent_count: 2, root_agent_count: 1 },
  ],
}

/** A fully-configured org, two tracked agents → avg/agent = 210/2 = $105.00. */
const COSTS_FULL = {
  date: '2026-05-13',
  daily_spend_usd: '210.00',
  daily_limit_usd: '200.00',
  monthly_spend_usd: '3200.00',
  monthly_limit_usd: '5000.00',
  per_agent: [
    { agent_id: 'agent-spendy', daily_spend_usd: '150.00', monthly_spend_usd: '2200.00', date: '2026-05-13' },
    { agent_id: 'agent-thrifty', daily_spend_usd: '40.00', monthly_spend_usd: '600.00', date: '2026-05-13' },
  ],
  per_team: [
    { team_id: 'team-hot', daily_spend_usd: '190.00', monthly_spend_usd: '2900.00', date: '2026-05-13' },
    { team_id: 'team-cool', daily_spend_usd: '20.00', monthly_spend_usd: '300.00', date: '2026-05-13' },
  ],
}

/** Same summary, but no agent has a per-agent cost row today — the divide-by-zero edge case. */
const COSTS_ZERO_AGENTS = {
  ...COSTS_FULL,
  per_agent: [],
}

interface Harness {
  errors: string[]
}

interface Fixture {
  /** Body for `GET /api/v1/costs`. Defaults to the fully-configured org. */
  costs?: unknown
}

/**
 * Minimal unsigned JWT. The claim is `scope` (an array), which is what
 * `parseScopesFromJwt` reads; the signature is irrelevant because the dashboard
 * never verifies it — the gateway is the authority.
 */
function makeToken(scopes: string[]): string {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url')
  return `${b64({ alg: 'none' })}.${b64({ sub: 'e2e-5159', scope: scopes })}.`
}

async function bootstrap(page: Page, theme: Theme, fixture: Fixture = {}): Promise<Harness> {
  const harness: Harness = { errors: [] }

  page.on('console', m => {
    if (m.type() !== 'error') return
    const text = m.text()
    if (!text.startsWith('Failed to load resource')) harness.errors.push(text)
  })
  page.on('pageerror', e => harness.errors.push(`pageerror: ${e.message}`))

  await page.addInitScript(
    (opts: { themeKey: string; theme: string; token: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme, token: makeToken(['read', 'write', 'admin']) },
  )

  // Permissive fallback first (least specific); later routes win because
  // Playwright matches most-recently-added first.
  await page.route('**/api/**', r => r.fulfill({ json: {} }))
  await page.route('**/api/v1/agents**', r => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology**', r => r.fulfill({ json: { nodes: [], edges: [] } }))
  await page.route('**/api/v1/topology/overview**', r => r.fulfill({ json: OVERVIEW }))
  await page.route('**/api/v1/approvals**', r => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/analytics/**', r => r.fulfill({ json: { buckets: [] } }))
  await page.route('**/api/v1/costs/history**', r => r.fulfill({ json: { points: [] } }))
  await page.route('**/api/v1/costs/budget-tree**', r => r.fulfill({ json: { root: null } }))

  // No trailing wildcard, so this matches the summary endpoint exactly and
  // never the `/costs/history` or `/costs/budget-tree` sub-resources above.
  await page.route('**/api/v1/costs', (r: Route) => r.fulfill({ json: fixture.costs ?? COSTS_FULL }))

  return harness
}

async function navigate(page: Page, path: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(target => {
    window.history.pushState({}, '', target)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, `${name}.png`), fullPage: true })
}

test.describe('AAASM-5159 review — Avg / agent today KPI', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of THEMES) {
    test(`renders the computed average with the cost date as its sub-caption — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_FULL })
      await navigate(page, '/costs')

      const card = page.getByTestId('costs-kpi-avg-per-agent')
      await expect(card).toBeVisible()
      await expect(card).toContainText('Avg / agent today')
      // 210.00 daily spend / 2 tracked agents = $105.00.
      await expect(card).toContainText('$105.00')
      await expect(card).toContainText('2026-05-13')

      await shot(page, `avg-per-agent-known-${theme}`)
      expect(harness.errors).toEqual([])
    })

    test(`renders an em-dash, never NaN or $0.00, when zero agents are tracked — ${theme}`, async ({
      page,
    }) => {
      const harness = await bootstrap(page, theme, { costs: COSTS_ZERO_AGENTS })
      await navigate(page, '/costs')

      const card = page.getByTestId('costs-kpi-avg-per-agent')
      await expect(card).toBeVisible()
      await expect(card.getByTestId('costs-kpi-avg-per-agent-value')).toHaveAttribute(
        'data-truth-state',
        'not-evaluated',
      )
      await expect(card).not.toContainText('NaN')
      await expect(card).not.toContainText('$0.00')
      // The summary itself resolved — only the ratio is undefined — so the
      // date sub-caption still renders.
      await expect(card).toContainText('2026-05-13')

      await shot(page, `avg-per-agent-zero-agents-${theme}`)
      expect(harness.errors).toEqual([])
    })
  }
})
