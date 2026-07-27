import { expect, test, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

// AAASM-5190 evidence: the approval-drawer head no longer invents a verdict for
// a status it cannot interpret.
//
// Rendered from the isolated Storybook harness rather than a product route, for
// the same reason as the AAASM-5075 parity capture: the drawer is not yet
// mounted on a route (its full approval-review flow is backend-blocked, 5095).
// Fabricating a route-level journey here would assert coverage that does not
// exist, so this spec drives the two head states through Storybook and asserts
// on the rendered DOM — the unit suite remains the primary evidence.

const OUT = join('verify', '5190')
mkdirSync(OUT, { recursive: true })

type Theme = 'light' | 'dark'

async function openStory(page: Page, storyId: string, theme: Theme) {
  await page.goto(`/iframe.html?id=${storyId}&viewMode=story`, { waitUntil: 'networkidle' })
  await page.evaluate((t) => {
    document.documentElement.setAttribute('data-theme', t)
    document.body.style.background = 'var(--paper)'
  }, theme)
  // Let the design tokens re-resolve after the theme flip.
  await page.waitForTimeout(200)
  const panel = page.locator('[data-testid="drawer-panel"]')
  await panel.waitFor({ state: 'visible' })
  return panel
}

for (const theme of ['light', 'dark'] as const) {
  test(`unrecognised status renders the absence marker — ${theme}`, async ({ page }) => {
    const panel = await openStory(page, 'trace-approvaldetaildrawer--unrecognised-status', theme)

    const marker = panel.locator('[data-testid="approval-detail-verdict-absent"]')
    await expect(marker).toBeVisible()
    await expect(marker).toHaveAttribute('data-truth-state', 'unknown')
    // The raw wire value is reachable by the operator, not swallowed.
    await expect(marker).toHaveAttribute('title', /escalated/)
    // Crucially: no verdict chip at all — not a PENDING one.
    await expect(panel.locator('[data-testid="verdict-chip"]')).toHaveCount(0)

    await panel.screenshot({ path: join(OUT, `unrecognised-status-${theme}.png`) })
  })

  test(`recognised status still renders its verdict chip — ${theme}`, async ({ page }) => {
    const panel = await openStory(page, 'trace-approvaldetaildrawer--pending', theme)

    await expect(panel.locator('[data-testid="verdict-chip"]')).toHaveAttribute(
      'data-verdict',
      'pending',
    )
    await expect(panel.locator('[data-testid="approval-detail-verdict-absent"]')).toHaveCount(0)

    await panel.screenshot({ path: join(OUT, `recognised-pending-${theme}.png`) })
  })
}
