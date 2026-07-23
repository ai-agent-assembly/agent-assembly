/**
 * Verification for AAASM-5021 — AppShell chrome fidelity to
 * `design/v1/hi-fi/shell.jsx`.
 *
 * Renders the real dashboard shell against deterministic mocked backend data in
 * BOTH light and dark themes and captures screenshots into
 * `dashboard/verify/AAASM-5021/` for visual review against the hi-fi. The added
 * chrome under test:
 *   - brand sub-line (env · version) under "Agent Assembly"
 *   - rail-foot runtime status + agent count
 *   - ★ markers on Topology / Capability / Policy
 *   - Policy + Alerts rail count badges (real counts from the feature queries)
 *   - topbar breadcrumbs (env › page) + last-sync indicator
 *
 * Auth is seeded into sessionStorage per AAASM-4322 (aa_token).
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/AAASM-5021')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

// A real 3-part JWT carrying a `sub` claim so the topbar shows an identity.
const b64url = (o: object) =>
  Buffer.from(JSON.stringify(o)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
const JWT = `${b64url({ alg: 'none' })}.${b64url({ sub: 'kelly@security' })}.sig`

const AGENTS = Array.from({ length: 142 }, (_, i) => ({
  id: `agent-${i}`,
  name: `agent-${i}`,
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 0,
  last_event: '2026-06-01T10:00:00Z',
  tool_names: ['search'],
  recent_events: [],
}))

// Two inactive policies → the Policy rail badge shows "2".
const POLICIES = [
  { name: 'default-policy', version: '1.0.0', rule_count: 5, active: true, policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n' },
  { name: 'experimental', version: '0.9.0', rule_count: 2, active: false, policy_yaml: 'metadata:\n  name: experimental\nrules: []\n' },
  { name: 'staging-draft', version: '0.1.0', rule_count: 1, active: false, policy_yaml: 'metadata:\n  name: staging-draft\nrules: []\n' },
]

// One CRITICAL alert → the Alerts rail badge shows "1".
const ALERTS = {
  items: [
    { id: 'al-1', ruleId: 'r1', ruleName: 'budget breach', severity: 'CRITICAL', status: 'FIRING', agentId: 'agent-1', firstFiredAt: '2026-06-01T10:00:00Z', resolvedAt: null, destinationIds: [] },
    { id: 'al-2', ruleId: 'r2', ruleName: 'anomaly', severity: 'HIGH', status: 'FIRING', agentId: 'agent-2', firstFiredAt: '2026-06-01T10:00:00Z', resolvedAt: null, destinationIds: [] },
  ],
}

const APPROVALS = { items: [{ id: 'ap-1' }, { id: 'ap-2' }, { id: 'ap-3' }] }

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { token: string; key: string; theme: string }) => {
      sessionStorage.setItem('aa_token', opts.token)
      localStorage.setItem(opts.key, opts.theme)
    },
    { token: JWT, key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: APPROVALS }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [] } }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (r) =>
    r.request().method() === 'GET' ? r.fulfill({ json: { items: POLICIES } }) : r.fallback(),
  )
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) => r.fulfill({ json: { items: AGENTS } }))
  await page.route(/\/api\/v1\/alerts(\?.*)?$/, (r) => r.fulfill({ json: ALERTS }))
}

async function navToFleet(page: Page) {
  // Vite `base: './'` workaround — deep-link goto breaks asset resolution, so
  // boot at root and route client-side (same as the design-fidelity specs).
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/agents')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('appshell-nav')).toBeVisible()
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

for (const theme of ['light', 'dark'] as const) {
  test(`shell chrome renders in ${theme} theme`, async ({ page }) => {
    await seed(page, theme)
    await mockBackend(page)
    await navToFleet(page)

    expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(theme)

    // Chrome elements are present.
    await expect(page.getByTestId('appshell-brand-sub')).toBeVisible()
    await expect(page.getByTestId('appshell-nav-foot')).toContainText('runtime ok')
    await expect(page.getByTestId('appshell-nav-foot')).toContainText('142 agents')
    await expect(page.getByTestId('nav-star-topology')).toBeVisible()
    await expect(page.getByTestId('nav-star-capability')).toBeVisible()
    await expect(page.getByTestId('nav-star-policy')).toBeVisible()
    await expect(page.getByTestId('nav-badge-policy')).toHaveText('2')
    await expect(page.getByTestId('nav-badge-alerts')).toHaveText('1')
    await expect(page.getByTestId('appshell-breadcrumbs')).toContainText('Fleet')
    await expect(page.getByTestId('appshell-topbar-status')).toContainText('last sync')

    await page.screenshot({ path: `${EVIDENCE_DIR}/shell-${theme}.png`, fullPage: true })
    // Nav-rail close-up (brand sub-line, stars, badges, rail-foot).
    await page.getByTestId('appshell-nav').screenshot({ path: `${EVIDENCE_DIR}/rail-${theme}.png` })
    // Topbar close-up (breadcrumbs + last-sync + controls).
    await page.getByTestId('appshell-topbar').screenshot({ path: `${EVIDENCE_DIR}/topbar-${theme}.png` })
  })
}
