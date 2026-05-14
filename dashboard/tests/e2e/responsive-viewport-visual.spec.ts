// AAASM-1324: Automated viewport-level visual regression coverage.
//
// AAASM-94 AC #10 requires the dashboard layout to pass visual checks at the
// two canonical desktop widths (1280×800, 1920×1080). The hamburger collapse
// below 1024px is verified functionally elsewhere; this spec covers the
// "layout doesn't silently regress" half via Playwright's toHaveScreenshot().
//
// Snapshots are stored in `tests/e2e/responsive-viewport-visual.spec.ts-snapshots/`
// (Playwright's default per-spec __screenshots__ layout). Regenerate with:
//
//   pnpm exec playwright test responsive-viewport-visual --update-snapshots
//
// See dashboard/tests/e2e/README.md for the full regeneration workflow.

import { test, expect, type Page } from '@playwright/test'

// ── Viewports to cover (AAASM-94 AC #10) ──────────────────────────────────────

const VIEWPORTS = [
  { name: 'desktop-1280', width: 1280, height: 800 },
  { name: 'desktop-1920', width: 1920, height: 1080 },
] as const

// ── Routes covered (per AAASM-1324 scope) ─────────────────────────────────────
//
// The ticket specified /approvals, /agents (Fleet), /policies — three pages
// that exercise different layout primitives (table, cards, list+overlay).

const ROUTES = [
  { path: '/approvals', ready: 'approvals-table' },
  { path: '/agents', ready: 'appshell' },
  { path: '/policies', ready: 'policies-page' },
] as const

// ── Fixture data + auth helpers ───────────────────────────────────────────────

const APPROVAL = {
  id: 'visreg-appr-001',
  agent_id: 'visreg-agent',
  action: 'shell.exec ls',
  reason: 'inspection',
  status: 'pending',
  created_at: '2026-05-12T10:00:00Z',
  routing_status: null,
  team_id: null,
}

const AGENT = {
  id: 'visreg-agent-001',
  name: 'Visreg Test Agent',
  framework: 'langchain',
  version: '0.1.0',
  status: 'active',
  layer: 'sdk',
  session_count: 3,
  policy_violations_count: 0,
  last_event: '2026-05-12T10:00:00Z',
  tool_names: ['search', 'code_exec'],
  recent_events: [],
}

const POLICY_DEFAULT = {
  name: 'default-policy',
  version: '1.0.0',
  rule_count: 5,
  active: true,
  policy_yaml: 'metadata:\n  name: default-policy\nrules: []\n',
}

const POLICY_EXPERIMENTAL = {
  name: 'experimental',
  version: '0.9.0',
  rule_count: 2,
  active: false,
  policy_yaml: 'metadata:\n  name: experimental\nrules: []\n',
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function mockBackend(page: Page) {
  // Block live data sources so the snapshot is deterministic.
  await page.route('**/api/v1/ws/events**', (route) => route.abort())

  await page.route('**/api/v1/approvals**', (route) =>
    route.fulfill({ json: [APPROVAL] }),
  )

  await page.route('**/api/v1/agents', (route) =>
    route.fulfill({ json: [AGENT] }),
  )
  await page.route(/\/api\/v1\/agents\/[^/]+$/, (route) =>
    route.fulfill({ json: AGENT }),
  )

  await page.route('**/api/v1/policies/active', (route) =>
    route.fulfill({ status: 404, json: { detail: 'No active policy' } }),
  )
  await page.route('**/api/v1/policies', (route) =>
    route.fulfill({ json: [POLICY_DEFAULT, POLICY_EXPERIMENTAL] }),
  )

  // Generic fallback for any other dashboard probes — return an empty list so
  // pages don't render error states in the snapshot.
  await page.route('**/api/v1/logs**', (route) => route.fulfill({ json: [] }))
}

// ── Spec body ─────────────────────────────────────────────────────────────────

test.describe('AAASM-1324 viewport visual regression', () => {
  for (const viewport of VIEWPORTS) {
    for (const route of ROUTES) {
      test(`${route.path} renders cleanly at ${viewport.name} (${viewport.width}×${viewport.height})`, async ({
        page,
      }) => {
        await injectToken(page)
        await mockBackend(page)
        await page.setViewportSize({ width: viewport.width, height: viewport.height })

        await page.goto(route.path)
        await expect(page.getByTestId(route.ready)).toBeVisible()

        // Mask regions that legitimately vary between runs:
        //   - the top-bar live region (may show stream status / timestamps)
        //   - any element flagged data-visreg-mask in component code
        const masks = [
          page.getByTestId('appshell-topbar-status'),
          page.locator('[data-visreg-mask]'),
        ]

        await expect(page).toHaveScreenshot(
          `${route.path.replace(/\//g, '-').replace(/^-/, '')}-${viewport.name}.png`,
          {
            fullPage: true,
            mask: masks,
            // Anti-aliased text + sub-pixel layout can produce 1-2 px diffs on
            // CI hardware vs local. Allow a tiny diff threshold to avoid flake;
            // any real layout regression will dwarf this budget.
            maxDiffPixelRatio: 0.01,
          },
        )
      })
    }
  }
})
