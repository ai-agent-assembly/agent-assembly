/**
 * Design-fidelity verification for the F100 SubtreeBurnChart (AAASM-1432).
 *
 * The chart sits on the AgentDetailPage overview tab and visualises 7- or
 * 30-day subtree spend as stacked-area layers (one per direct child) with an
 * aggregate total line on top. This spec asserts the visual contract against
 * `design/v1/hi-fi/costs.jsx` + `design/v1/hi-fi/topology.jsx`:
 *   - chart card structure (title, period selector, recharts SVG)
 *   - one stacked Area per direct child in the fixture
 *   - period selector exposes 7d / 30d toggles wired to active state
 *   - BurnTooltip renders date + per-child rows + total
 *
 * Captures screenshots into `dashboard/docs/verification/aaasm-1432/`.
 *
 * Known accepted divergence (filed in PR comment): AAASM-1055 deliberately
 * shipped a stacked-area chart, not the "treemap layout" mentioned in the
 * AAASM-1432 description. The decision was made in AAASM-1055 to reuse the
 * existing recharts dep instead of pulling d3-treemap; the visual goal
 * (showing which children dominate spend) is met by both shapes.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { AGENT_ID, EVIDENCE_DIR, injectToken, mockApi } from './_fixtures/aaasm-1432'

async function gotoOverviewTab(page: Page) {
  await page.goto('/')
  await page.evaluate(
    (id) => window.history.pushState({}, '', `/agents/${id}`),
    AGENT_ID,
  )
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  // The overview tab is the default landing tab; just wait for the card.
  await page.getByTestId('subtree-burn-chart').waitFor()
}

test.describe('AAASM-1432 — SubtreeBurnChart design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('subtree burn card renders with title, period selector, and chart svg', async ({ page }) => {
    await gotoOverviewTab(page)
    const card = page.getByTestId('subtree-burn-chart')
    await expect(card).toBeVisible()
    await expect(card.locator('.sbc__title')).toHaveText('Budget burn · subtree')
    await expect(card.getByTestId('subtree-burn-period-7d')).toBeVisible()
    await expect(card.getByTestId('subtree-burn-period-30d')).toBeVisible()
    // recharts renders an SVG inside ResponsiveContainer.
    await expect(card.locator('svg.recharts-surface')).toBeVisible()
    await page.screenshot({ path: `${EVIDENCE_DIR}/05-burn-card.png`, fullPage: true })
  })

  test('one stacked area renders per direct child in the fixture', async ({ page }) => {
    await gotoOverviewTab(page)
    // Two fixture children → two recharts Area paths.
    const areas = page.locator('svg.recharts-surface .recharts-area-area')
    await expect(areas).toHaveCount(2)
    // The aggregate total line is rendered on top.
    await expect(page.locator('svg.recharts-surface .recharts-line-curve')).toBeVisible()
    await page.screenshot({ path: `${EVIDENCE_DIR}/06-stacked-areas.png`, fullPage: true })
  })

  test('period selector toggles to 30d and marks it active', async ({ page }) => {
    await gotoOverviewTab(page)
    const sevenDay = page.getByTestId('subtree-burn-period-7d')
    const thirtyDay = page.getByTestId('subtree-burn-period-30d')
    // Default landing should have 7d active.
    await expect(sevenDay).toHaveClass(/sbc__period-btn--active/)
    await thirtyDay.click()
    await expect(thirtyDay).toHaveClass(/sbc__period-btn--active/)
    await expect(sevenDay).not.toHaveClass(/sbc__period-btn--active/)
    await page.screenshot({ path: `${EVIDENCE_DIR}/07-period-toggle.png`, fullPage: true })
  })

  test('tooltip surfaces date + per-child rows + total when an area is hovered', async ({ page }) => {
    await gotoOverviewTab(page)
    // Hover the middle of the chart surface to trigger the recharts tooltip.
    const surface = page.locator('svg.recharts-surface').first()
    const box = await surface.boundingBox()
    expect(box).not.toBeNull()
    await page.mouse.move(box!.x + box!.width / 2, box!.y + box!.height / 2)

    const tooltip = page.getByTestId('subtree-burn-tooltip')
    await expect(tooltip).toBeVisible()
    await expect(tooltip.locator('.sbc__tooltip-date')).toBeVisible()
    await expect(tooltip.locator('.sbc__tooltip-rows .sbc__tooltip-row')).toHaveCount(2)
    await expect(tooltip.locator('.sbc__tooltip-total')).toContainText('Total:')
    await page.screenshot({ path: `${EVIDENCE_DIR}/08-burn-tooltip.png`, fullPage: true })
  })
})
