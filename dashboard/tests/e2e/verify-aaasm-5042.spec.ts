/**
 * Verification capture for AAASM-5042 — Identity → Roles tab role-capability
 * cards (design/v1/hi-fi/identity.jsx RolesTab).
 *
 * Evidence-capture spec, not a pixel baseline: it stands the Identity page up
 * with a bypassed auth token, opens the Roles tab, waits for the
 * role-capability card grid, then screenshots it in light and dark themes into
 * `dashboard/verify/5042/` for review next to the hi-fi design.
 *
 * Member counts / assignees come from the in-memory IAM store (no route mock
 * needed); capability grants come from the static built-in catalogue.
 */

import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/5042')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  await page.goto('/identity?tab=roles')
  await expect(page.getByTestId('identity-page')).toBeVisible()
  await expect(page.getByTestId('role-capability-cards')).toBeVisible()
  // Wait for the async members query so counts/assignees are populated.
  await expect(page.getByTestId('role-card-Owner')).toContainText('Alice')
}

test.describe('AAASM-5042 — role-capability cards verification', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`captures the role-capability cards in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)

      // All four built-in role cards render.
      for (const role of ['Owner', 'Admin', 'Member', 'Viewer']) {
        await expect(page.getByTestId(`role-card-${role}`)).toBeVisible()
      }
      // The backend-gated grant flag is present.
      await expect(page.getByTestId('role-cards-grant-flag')).toBeVisible()

      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `01-roles-${theme}.png`),
        fullPage: true,
      })
    })
  }
})
