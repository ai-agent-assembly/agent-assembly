// AAASM-5031: Playwright verification for the Overview POSTURE enforcement
// timeline (allow/narrow/deny/scrub mini-bar chart) in light AND dark themes.
//
// Only the network is stubbed — the real app renders — so this exercises the
// component end-to-end against the new GET /api/v1/overview/enforcement-timeline
// endpoint through the fixture harness. Focused artifacts land in
// `verify/5031/overview-timeline-<theme>.png`. Run with:
//
//   pnpm exec playwright test overview-timeline
//
// (Deterministic fixtures + fixed bucket timestamps keep the axis stable.)

import { test, expect, type Page } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

const AGENT = {
  id: 'timeline-agent-001',
  name: 'Timeline Test Agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 1,
  policy_violations_count: 0,
  last_event: '2026-06-01T10:00:00Z',
  tool_names: ['search'],
  recent_events: [],
}

// 24 buckets on a fixed 1h grid starting 2026-06-01T00:00Z, with varied counts
// per verdict lane so every mini-bar reveals its shape deterministically.
const BASE_TS = Date.UTC(2026, 5, 1, 0, 0, 0)
const ENFORCEMENT_TIMELINE = {
  window: '24h',
  bucketSecs: 3600,
  buckets: Array.from({ length: 24 }, (_, i) => ({
    ts: BASE_TS + i * 3_600_000,
    allow: 12 + ((i * 7) % 22),
    narrow: 3 + ((i * 3) % 11),
    deny: (i * 2) % 6,
    scrub: 2 + ((i * 5) % 9),
  })),
}

async function seed(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string }) => {
      // Auth token lives in sessionStorage (AAASM-4322); theme in localStorage.
      sessionStorage.setItem('aa_token', 'timeline-e2e-token')
      localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme },
  )
}

async function mockBackend(page: Page) {
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())
  // AppShell + Overview shell probes.
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (r) =>
    r.request().method() === 'GET' ? r.fulfill({ json: [] }) : r.fallback(),
  )
  // useAgentsQuery reads `data.items`, so the list endpoint must be paginated.
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) =>
    r.fulfill({ json: { items: [AGENT], total: 1 } }),
  )
  await page.route('**/api/v1/alerts**', (r) => r.fulfill({ json: { items: [] } }))
  // The endpoint under test.
  await page.route('**/api/v1/overview/enforcement-timeline**', (r) =>
    r.fulfill({ json: ENFORCEMENT_TIMELINE }),
  )
}

async function navToOverview(page: Page) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  await page.evaluate(() => {
    window.history.pushState({}, '', '/overview')
    window.dispatchEvent(new PopStateEvent('popstate'))
  })
  await expect(page.getByTestId('overview-enforcement-timeline')).toBeVisible()
}

test.describe('AAASM-5031 — Overview enforcement timeline', () => {
  for (const theme of THEMES) {
    test(`enforcement timeline renders in ${theme} theme`, async ({ page }) => {
      await seed(page, theme)
      await mockBackend(page)
      await navToOverview(page)

      expect(await page.evaluate(() => document.documentElement.getAttribute('data-theme'))).toBe(
        theme,
      )

      const card = page.getByTestId('overview-enforcement-timeline')
      // The populated chart (not the empty note) must be showing.
      await expect(page.getByTestId('overview-enforcement-timeline-chart')).toBeVisible()
      await card.scrollIntoViewIfNeeded()

      await card.screenshot({ path: `verify/5031/overview-timeline-${theme}.png` })
    })
  }
})
