import { test, expect, type Page } from '@playwright/test'

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

// CapabilityPage uses the in-process mock client; no API mocks needed.
// Still block the WebSocket since AppShell tries to open it.
async function blockWs(page: Page) {
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
}

test.describe('Capability Matrix page', () => {
  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await blockWs(page)
  })

  test('renders the matrix at /capability', async ({ page }) => {
    await page.goto('/capability')
    await expect(page.getByTestId('capability-page')).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Capability' })).toBeVisible()
    await expect(page.getByRole('grid', { name: 'capability matrix' })).toBeVisible()
    await expect(page.getByText('research-bot-04', { exact: false })).toBeVisible()
  })

  test('clicking a cell opens the inspect drawer without changing route', async ({ page }) => {
    await page.goto('/capability')
    const grid = page.getByRole('grid', { name: 'capability matrix' })
    await expect(grid).toBeVisible()
    // Click the first interactive (non-NA) cell.
    await grid.locator('.cap-mx-cell:not(.cap-mx-cell--na)').first().click()
    await expect(page.getByRole('dialog', { name: 'capability cell inspect' })).toBeVisible()
    await expect(page).toHaveURL(/\/capability$/)
    // Close on Esc.
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog', { name: 'capability cell inspect' })).toBeHidden()
  })

  test('selecting rows reveals the bulk override bar', async ({ page }) => {
    await page.goto('/capability')
    const firstRowCheckbox = page.getByRole('checkbox', { name: /^select research-bot-04$/ })
    await firstRowCheckbox.check()
    const bulkBar = page.getByRole('region', { name: 'bulk override' })
    await expect(bulkBar).toBeVisible()
    await expect(bulkBar.getByText(/1 agent selected/)).toBeVisible()
    await bulkBar.getByRole('button', { name: 'Clear' }).click()
    await expect(bulkBar).toBeHidden()
  })
})
