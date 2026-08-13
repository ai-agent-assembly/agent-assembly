/**
 * Verification capture for AAASM-5046 — Identity → Roles tab role-capability
 * cards backed by the LIVE `GET /api/v1/iam/roles` endpoint.
 *
 * Evidence-capture spec, not a pixel baseline. Where AAASM-5042 rendered the
 * static built-in catalogue behind a flag banner, this stands the page up with
 * the roles endpoint mocked to the gateway's real policy-RBAC grants, opens the
 * Roles tab, and confirms the cards render from the live grants with the flag
 * banner dropped. Screenshots land in `dashboard/verify/5046/` in light + dark.
 *
 * The `page.route` mock stands in for a running gateway (the preview server has
 * no backend); the payload mirrors the shape `list_roles` returns in aa-api.
 */

import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5046')
const THEME_KEY = 'aa-dashboard-theme'
const BASE_URL = process.env.VERIFY_BASE_URL ?? 'http://localhost:4513'
type Theme = 'light' | 'dark'

// The gateway's real role→capability model (aa-gateway policy-RBAC), as
// returned by GET /api/v1/iam/roles.
const LIVE_ROLES = [
  {
    role: 'org_admin',
    description: 'Full policy mutation rights across all scopes.',
    capabilities: [
      'read:policies',
      'write:policies:global',
      'write:policies:org',
      'write:policies:team',
      'write:policies:agent',
      'write:policies:tool',
    ],
  },
  {
    role: 'team_admin',
    description: 'Can mutate team-scoped policies and below (Agent, Tool).',
    capabilities: ['read:policies', 'write:policies:team', 'write:policies:agent', 'write:policies:tool'],
  },
  {
    role: 'developer',
    description: 'Can mutate agent- and tool-scoped policies only.',
    capabilities: ['read:policies', 'write:policies:agent', 'write:policies:tool'],
  },
  { role: 'viewer', description: 'Read-only access — no writes permitted.', capabilities: ['read:policies'] },
  { role: 'auditor', description: 'Read-only audit access — no writes permitted.', capabilities: ['read:audit'] },
]

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  await page.route('**/api/v1/iam/roles', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(LIVE_ROLES),
    })
  })

  await page.goto(`${BASE_URL}/identity?tab=roles`)
  await expect(page.getByTestId('identity-page')).toBeVisible()
  await expect(page.getByTestId('role-capability-cards')).toBeVisible()
  // Wait for the live grants to resolve — the gateway roles card appears.
  await expect(page.getByTestId('role-card-org_admin')).toBeVisible()
}

test.describe('AAASM-5046 — live role-capability cards verification', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`captures the live role-capability cards in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)

      // All five gateway RBAC role cards render from the live grants.
      for (const role of ['org_admin', 'team_admin', 'developer', 'viewer', 'auditor']) {
        await expect(page.getByTestId(`role-card-${role}`)).toBeVisible()
      }
      // A live capability grant is shown…
      await expect(page.getByTestId('role-card-caps-org_admin')).toContainText('write:policies:global')
      // …and the static-default flag banner is dropped when live grants are present.
      await expect(page.getByTestId('role-cards-grant-flag')).toHaveCount(0)

      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `01-roles-${theme}.png`),
        fullPage: true,
      })
    })
  }
})
