import { test, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

// AAASM-5075 Trace FE-parity evidence. Captures, in both themes, the square
// VerdictChip gallery the Trace callers now use.
// Rendered from the isolated Storybook harness.
//
// The ApprovalDetailDrawer parity capture that used to live here was removed
// with the drawer itself (AAASM-5166): the drawer was dead — never mounted on
// a route — and its request-detail KV is a strict subset of the now-structured
// ApprovalDetailRow, so the Storybook story it captured no longer exists.

const OUT = join('verify', 'parity-trace')
mkdirSync(OUT, { recursive: true })

type Theme = 'light' | 'dark'

async function applyTheme(page: Page, theme: Theme) {
  await page.evaluate((t) => {
    document.documentElement.setAttribute('data-theme', t)
    document.body.style.background = 'var(--paper)'
  }, theme)
  // Let tokens re-resolve after the theme flip.
  await page.waitForTimeout(200)
}

/** Screenshot a story's `#storybook-root` (in-tree content). */
async function shotRoot(page: Page, storyId: string, name: string, theme: Theme) {
  await page.goto(`/iframe.html?id=${storyId}&viewMode=story`, { waitUntil: 'networkidle' })
  await applyTheme(page, theme)
  const root = page.locator('#storybook-root')
  await root.waitFor({ state: 'visible' })
  await root.screenshot({ path: join(OUT, `${name}-${theme}.png`) })
}

for (const theme of ['light', 'dark'] as const) {
  test(`verdict-chip-square — ${theme}`, async ({ page }) => {
    await shotRoot(page, 'trace-verdictchip--square', 'verdict-chip-square', theme)
  })
}
