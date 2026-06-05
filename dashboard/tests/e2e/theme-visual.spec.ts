// AAASM-2597: Playwright visual e2e for the light / dark dashboard theming.
//
// Follow-up to AAASM-2595 (which added the `data-theme` token system in
// `src/styles.css` + `src/theme/useTheme.ts` + the topbar ThemeToggle). This
// spec guards that theming end-to-end against the real rendered app — no
// component mocks, only the network is stubbed so each page renders
// deterministically.
//
// Two halves:
//   1. Visual — `toHaveScreenshot()` baselines for a set of representative
//      pages in BOTH themes, so a regression (light-on-light text, broken
//      surface re-theme, unreadable contrast) shows up as a pixel diff.
//   2. Behavioural — the toggle flips `data-theme` on <html> and re-themes the
//      surface; the choice persists across reload (localStorage); the OS
//      setting drives the theme on first load; and the nav rail + code/terminal
//      surfaces stay dark in BOTH modes (the AAASM-2595 design intent).
//
// Baselines live in `tests/e2e/theme-visual.spec.ts-snapshots/` and are
// PLATFORM-SPECIFIC (`-chromium-darwin` on macOS, `-chromium-linux` on Linux),
// exactly like `responsive-viewport-visual.spec.ts`. The dashboard has no
// Playwright CI lane (see tests/e2e/README.md) — this is a local visual gate.
// Regenerate with:
//
//   pnpm exec playwright test theme-visual --update-snapshots
//
// See tests/e2e/README.md for the full workflow.

import { test, expect, type Page, type Locator } from '@playwright/test'

const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'
const THEMES: readonly Theme[] = ['light', 'dark'] as const

// ── Deterministic fixtures ────────────────────────────────────────────────────

const AGENT = {
  id: 'theme-agent-001',
  name: 'Theme Test Agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 2,
  policy_violations_count: 0,
  last_event: '2026-06-01T10:00:00Z',
  tool_names: ['search', 'code_exec'],
  recent_events: [],
}

const POLICIES = [
  {
    name: 'default-policy',
    version: '1.0.0',
    rule_count: 5,
    active: true,
    policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
  },
  {
    name: 'experimental',
    version: '0.9.0',
    rule_count: 2,
    active: false,
    policy_yaml: 'metadata:\n  name: experimental\nrules: []\n',
  },
]

// SandboxSummaryCard on the Policies page reads this.
const SANDBOX_SUMMARY = {
  counts: {
    would_be_denies: 7,
    would_be_pending_approvals: 3,
    would_be_redactions: 2,
  },
  generated_at: '2026-06-01T10:00:00Z',
  top_rule: { id: 'deny-write-fs', count: 5 },
  window_secs: 86400,
}

// 3-node lineage (root + two children) so the heatmap SVG renders a stable
// green→red gradient. agent_ids are 32-char hex to match the real id shape.
const VIOLATIONS = {
  window_secs: 86400,
  generated_at: '2026-06-01T10:00:00Z',
  nodes: [
    {
      agent_id: 'cccc0000000000000000000000000001',
      parent_agent_id: null,
      team_id: 'eng-platform',
      depth: 0,
      violation_count: 24,
      top_policies: ['deny-write-fs', 'budget-exceeded'],
    },
    {
      agent_id: 'cccc0000000000000000000000000002',
      parent_agent_id: 'cccc0000000000000000000000000001',
      team_id: 'eng-platform',
      depth: 1,
      violation_count: 6,
      top_policies: ['deny-write-fs'],
    },
    {
      agent_id: 'cccc0000000000000000000000000003',
      parent_agent_id: 'cccc0000000000000000000000000001',
      team_id: 'eng-platform',
      depth: 1,
      violation_count: 0,
      top_policies: [],
    },
  ],
} as const

// ── Page set (representative layout primitives, all deterministic) ─────────────

const PAGES = [
  { name: 'fleet', path: '/agents', ready: 'fleet-page' },
  { name: 'policies', path: '/policies', ready: 'policies-page' },
  { name: 'identity', path: '/identity', ready: 'identity-page' },
  { name: 'settings', path: '/settings', ready: 'settings-page' },
  {
    name: 'violations-heatmap',
    path: '/audit/violations',
    ready: `heatmap-node-${VIOLATIONS.nodes[0].agent_id}`,
  },
  // Live Ops is WS-driven; the stream zone is masked (its rows + reconnect
  // counter are non-deterministic), but the page chrome + pipeline zone still
  // exercise theming.
  { name: 'live-ops', path: '/live', ready: 'live-ops-page', maskTestId: 'live-ops-stream-zone' },
] as const

// ── Helpers ───────────────────────────────────────────────────────────────────

async function seed(page: Page, theme?: Theme) {
  await page.addInitScript(
    (opts: { key: string; theme: string | null }) => {
      localStorage.setItem('aa_token', 'theme-e2e-token')
      if (opts.theme) localStorage.setItem(opts.key, opts.theme)
    },
    { key: THEME_KEY, theme: theme ?? null },
  )
}

async function mockBackend(page: Page) {
  // Block the live event stream so snapshots don't flake on stream rows.
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
  await page.route('**/api/v1/alerts/ws**', (r) => r.abort())

  // Shell probes (issued on every page by the AppShell topbar).
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/policies/active', (r) =>
    r.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )

  // Page data.
  await page.route('**/api/v1/policies', (r) =>
    r.request().method() === 'GET' ? r.fulfill({ json: POLICIES }) : r.fallback(),
  )
  // Fleet list — matches both the bare path and the `?per_page=…` query form.
  await page.route(/\/api\/v1\/agents(\?.*)?$/, (r) => r.fulfill({ json: [AGENT] }))
  await page.route(/\/api\/v1\/agents\/[^/?]+$/, (r) => r.fulfill({ json: AGENT }))
  await page.route('**/api/v1/topology/teams**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/topology/overview**', (r) =>
    r.fulfill({ json: { teams: [] } }),
  )
  await page.route('**/api/v1/audit/sandbox-summary**', (r) =>
    r.fulfill({ json: SANDBOX_SUMMARY }),
  )
  await page.route('**/api/v1/audit/violations-by-lineage*', (r) =>
    r.fulfill({ json: VIOLATIONS }),
  )
}

function getTheme(page: Page): Promise<string | null> {
  return page.evaluate(() => document.documentElement.getAttribute('data-theme'))
}

// The dashboard builds with `base: './'` (relative asset URLs), so a direct
// deep-link `goto()` to a multi-segment path (e.g. /audit/violations) resolves
// assets against the wrong directory and the app never boots. Navigate to the
// root, let the shell mount, then route client-side — same approach as the
// design-fidelity specs.
async function navTo(page: Page, path: string, ready: string) {
  await page.goto('/')
  await page.getByTestId('appshell').waitFor()
  if (path !== '/') {
    await page.evaluate((p) => {
      window.history.pushState({}, '', p)
      window.dispatchEvent(new PopStateEvent('popstate'))
    }, path)
  }
  await expect(page.getByTestId(ready)).toBeVisible()
}

// ── 1. Visual baselines — every page in both themes ───────────────────────────

test.describe('AAASM-2597 — theme visual baselines', () => {
  for (const theme of THEMES) {
    for (const pg of PAGES) {
      test(`${pg.name} renders cleanly in ${theme} theme`, async ({ page }) => {
        await seed(page, theme)
        await mockBackend(page)

        await navTo(page, pg.path, pg.ready)
        // Confirm the theme actually took effect before snapping.
        expect(await getTheme(page)).toBe(theme)

        const masks: Locator[] = [
          page.locator('[data-visreg-mask]'),
          page.getByTestId('appshell-topbar-status'),
        ]
        if ('maskTestId' in pg && pg.maskTestId) {
          masks.push(page.getByTestId(pg.maskTestId))
        }

        await expect(page).toHaveScreenshot(`${pg.name}-${theme}.png`, {
          fullPage: true,
          mask: masks,
          // Absorb 1–2 px sub-pixel AA differences between local + CI hardware;
          // any real theming regression dwarfs this budget.
          maxDiffPixelRatio: 0.01,
        })
      })
    }
  }
})

// ── 2. Behavioural — toggle / persistence / OS-default / rail-stays-dark ───────

test.describe('AAASM-2597 — theme behaviour', () => {
  const bodyBg = (page: Page) =>
    page.evaluate(() => getComputedStyle(document.body).backgroundColor)

  test('toggle flips data-theme on <html> and re-themes the surface', async ({ page }) => {
    await seed(page, 'light')
    await mockBackend(page)
    await navTo(page, '/agents', 'fleet-page')
    expect(await getTheme(page)).toBe('light')

    const paperLight = await bodyBg(page)

    await page.getByTestId('theme-toggle').click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    // The page background must actually change between themes (retry until the
    // style recalc lands).
    await expect.poll(() => bodyBg(page)).not.toBe(paperLight)

    // Toggling back returns to light.
    await page.getByTestId('theme-toggle').click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  })

  test('explicit choice persists across reload (localStorage)', async ({ page }) => {
    // No forced theme: the seed init-script runs on every load, so forcing a
    // theme here would clobber the toggle's choice on reload. Start from the
    // OS default (light) instead.
    await seed(page)
    await mockBackend(page)
    await navTo(page, '/agents', 'fleet-page')
    expect(await getTheme(page)).toBe('light')

    await page.getByTestId('theme-toggle').click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    expect(await page.evaluate((k) => localStorage.getItem(k), THEME_KEY)).toBe('dark')

    await page.reload()
    await expect(page.getByTestId('fleet-page')).toBeVisible()
    // No FOUC: data-theme is dark immediately after reload.
    expect(await getTheme(page)).toBe('dark')
  })

  test('OS setting drives the theme on first load (no stored choice)', async ({ page }) => {
    await seed(page) // token only, no stored theme
    await mockBackend(page)

    await page.emulateMedia({ colorScheme: 'dark' })
    await navTo(page, '/agents', 'fleet-page')
    expect(await getTheme(page)).toBe('dark')

    await page.emulateMedia({ colorScheme: 'light' })
    await page.reload()
    await expect(page.getByTestId('fleet-page')).toBeVisible()
    expect(await getTheme(page)).toBe('light')
  })

  test('nav rail + code/terminal palette stay dark in both themes (design intent)', async ({
    page,
  }) => {
    await seed(page, 'light')
    await mockBackend(page)
    await navTo(page, '/agents', 'fleet-page')
    await expect(page.getByTestId('appshell-nav')).toBeVisible()

    const railBg = () =>
      page.evaluate(() => {
        const nav = document.querySelector('[data-testid="appshell-nav"]')
        return nav ? getComputedStyle(nav).backgroundColor : null
      })

    const railLight = await railBg()
    expect(railLight).not.toBeNull()

    await page.getByTestId('theme-toggle').click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
    const railDark = await railBg()

    // The rail is intentionally identical (dark) in both modes.
    expect(railDark).toBe(railLight)

    // …and it really is dark: parse rgb() and assert low luminance.
    const m = (railLight ?? '').match(/rgb[a]?\((\d+),\s*(\d+),\s*(\d+)/)
    expect(m).not.toBeNull()
    const [r, g, b] = m!.slice(1).map(Number)
    const luminance = (0.299 * r! + 0.587 * g! + 0.114 * b!) / 255
    expect(luminance).toBeLessThan(0.35)

    // The code/terminal palette (--term-*) is likewise NOT overridden in the
    // dark block — the terminal surface is dark in both modes. Assert at the
    // token level so this holds without a terminal panel being on screen.
    const termBg = () =>
      page.evaluate(() =>
        getComputedStyle(document.documentElement).getPropertyValue('--term-bg').trim(),
      )
    const termInDark = await termBg() // currently in dark theme
    await page.getByTestId('theme-toggle').click()
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
    const termInLight = await termBg()

    expect(termInDark).not.toBe('')
    // Identical across themes…
    expect(termInLight).toBe(termInDark)
    // …and dark: #0d0e10-class hex parses to low luminance.
    const hex = termInDark.replace('#', '')
    const tr = parseInt(hex.slice(0, 2), 16)
    const tg = parseInt(hex.slice(2, 4), 16)
    const tb = parseInt(hex.slice(4, 6), 16)
    const termLum = (0.299 * tr + 0.587 * tg + 0.114 * tb) / 255
    expect(termLum).toBeLessThan(0.35)
  })
})
