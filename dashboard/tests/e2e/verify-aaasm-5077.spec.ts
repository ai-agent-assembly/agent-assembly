import { test, type Page } from '@playwright/test'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

// AAASM-5077 Wave-2 shared-foundation design-parity evidence. Captures the
// shared primitives (VerdictChip pill/square, ApprovalActions inline/drawer) in
// both themes from the isolated Storybook harness, since they are not yet
// mounted on any product route. Non-regression of the existing VerdictChip
// callers is proven by the Gateway's "pill (default)" row rendering unchanged
// beside the new square row, plus the full vitest suite.

const OUT = join('verify', 'parity-foundation')
mkdirSync(OUT, { recursive: true })

type Theme = 'light' | 'dark'

async function shot(page: Page, storyId: string, name: string, theme: Theme) {
  await page.goto(`/iframe.html?id=${storyId}&viewMode=story`, { waitUntil: 'networkidle' })
  await page.evaluate((t) => {
    document.documentElement.setAttribute('data-theme', t)
    document.body.style.background = 'var(--paper)'
    document.body.style.padding = '24px'
  }, theme)
  // Let tokens re-resolve after the theme flip.
  await page.waitForTimeout(200)
  const root = page.locator('#storybook-root')
  await root.waitFor({ state: 'visible' })
  await root.screenshot({ path: join(OUT, `${name}-${theme}.png`) })
}

const CASES: Array<{ id: string; name: string }> = [
  { id: 'trace-verdictchip--gallery', name: 'verdict-chip' },
  { id: 'approvals-approvalactions--inline-small', name: 'approval-actions-inline' },
  { id: 'approvals-approvalactions--drawer-medium', name: 'approval-actions-drawer' },
  { id: 'approvals-approvalactions--disabled', name: 'approval-actions-disabled' },
]

for (const { id, name } of CASES) {
  for (const theme of ['light', 'dark'] as const) {
    test(`${name} — ${theme}`, async ({ page }) => {
      await shot(page, id, name, theme)
    })
  }
}
