import { test, type Page } from '@playwright/test'
import { CAPABILITY_MATRIX_FIXTURE } from '../../src/features/capability/fixtures'

// AAASM-5024 visual verification: matrix summary stats + filter legend +
// editor links, in light and dark themes. Renders the built app against the
// fixture matrix (mocked at the API boundary so the harness is backend-free)
// with a session token so the shell treats us as authenticated.

const OUT = 'verify/AAASM-5024'

async function prime(page: Page, theme: 'light' | 'dark') {
  await page.addInitScript(
    ([t]) => {
      sessionStorage.setItem('aa_token', 'verify-token')
      localStorage.setItem('aa_token', 'verify-token')
      localStorage.setItem('aa-dashboard-theme', t)
    },
    [theme],
  )
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  await page.route('**/api/v1/capability/matrix', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(CAPABILITY_MATRIX_FIXTURE),
    }),
  )
}

for (const theme of ['light', 'dark'] as const) {
  test(`capability page — ${theme}`, async ({ page }) => {
    await prime(page, theme)
    await page.goto('/capability')
    await page.getByRole('grid', { name: 'capability matrix' }).waitFor()
    await page.getByLabel('matrix summary').waitFor()
    await page.getByRole('button', { name: /Open Policy editor/ }).waitFor()
    await page.screenshot({ path: `${OUT}/capability-${theme}.png`, fullPage: true })
  })
}

test('capability cell inspect drawer — footer + edit links (light)', async ({ page }) => {
  await prime(page, 'light')
  await page.goto('/capability')
  const grid = page.getByRole('grid', { name: 'capability matrix' })
  await grid.waitFor()
  // Open a narrowed cell so the drawer lists a responsible policy (edit link).
  await grid.locator('.cap-mx-cell--narrow, .cap-mx-cell--deny').first().click()
  await page.getByRole('dialog', { name: 'capability cell inspect' }).waitFor()
  await page.screenshot({ path: `${OUT}/capability-drawer-light.png`, fullPage: true })
})
