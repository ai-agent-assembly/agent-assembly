/**
 * Design-fidelity verification for the F100 InheritedPermissionsPanel (AAASM-1432).
 *
 * Walks the rendered panel under the AgentDetailPage `capability` tab and
 * asserts the visual contract against the hi-fi reference at
 * `design/v1/hi-fi/identity.jsx` + `design/v1/hi-fi/styles.css`:
 *   - allow chips resolve to the `--ok` token foreground color
 *   - deny chips resolve to the `--danger` token foreground color
 *   - cascade groups render one section per Capability category
 *   - empty-state contract matches the hi-fi empty card
 *
 * Captures full-page screenshots into `dashboard/docs/verification/aaasm-1432/`
 * for visual review alongside the hi-fi.
 *
 * Known accepted divergence (filed in the PR comment): AAASM-1053 shipped the
 * panel as a capability *tab* on AgentDetailPage rather than the right-side
 * *drawer* mentioned in the F100 spec. The visual contract for the panel
 * itself is unchanged; only the container surface differs.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { AGENT_ID, EVIDENCE_DIR, HIFI_TOKENS, injectToken, mockApi } from './_fixtures/aaasm-1432'

async function gotoCapabilityTab(page: Page) {
  // Vite `base: './'` workaround — pushState then dispatch popstate
  // so React Router picks the new pathname without a hard reload.
  await page.goto('/')
  await page.evaluate(
    (id) => window.history.pushState({}, '', `/agents/${id}`),
    AGENT_ID,
  )
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  await page.getByTestId('agent-detail-tab-capability').click()
  await page.getByTestId('inherited-permissions-panel').waitFor()
}

test.describe('AAASM-1432 — InheritedPermissionsPanel design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('capability tab activates the inherited-permissions panel', async ({ page }) => {
    await gotoCapabilityTab(page)
    await expect(page.getByTestId('inherited-permissions-panel')).toBeVisible()
    await expect(page.getByTestId('ipp-allow-count').locator('.ipp__summary-num')).toHaveText('3')
    await expect(page.getByTestId('ipp-deny-count').locator('.ipp__summary-num')).toHaveText('2')
    await expect(page.getByTestId('ipp-source-count').locator('.ipp__summary-num')).toHaveText('3')
    await page.screenshot({ path: `${EVIDENCE_DIR}/01-permissions-panel.png`, fullPage: true })
  })

  test('allow / deny chips resolve to hi-fi --ok / --danger token foregrounds', async ({ page }) => {
    await gotoCapabilityTab(page)
    const firstAllowChip = page.locator('.ipp__chip--allow').first()
    const firstDenyChip = page.locator('.ipp__chip--deny').first()
    await expect(firstAllowChip).toBeVisible()
    await expect(firstDenyChip).toBeVisible()

    const allowColor = await firstAllowChip.evaluate((el) => getComputedStyle(el).color)
    const denyColor = await firstDenyChip.evaluate((el) => getComputedStyle(el).color)
    expect(allowColor).toBe(HIFI_TOKENS.ok)
    expect(denyColor).toBe(HIFI_TOKENS.danger)

    // Pill geometry from the hi-fi: 12px border-radius, JetBrains Mono.
    const allowRadius = await firstAllowChip.evaluate((el) => getComputedStyle(el).borderRadius)
    expect(allowRadius).toBe('12px')

    await page.screenshot({ path: `${EVIDENCE_DIR}/02-chip-tokens.png`, fullPage: true })
  })

  test('cascade renders one group per Capability category in fixture', async ({ page }) => {
    await gotoCapabilityTab(page)
    // The fixture spans 3 capability families: fs, mcp, net — each is its
    // own .ipp__group section with a group-title header.
    const groups = page.locator('.ipp__group')
    await expect(groups).toHaveCount(3)
    await expect(page.locator('.ipp__group-title').first()).toBeVisible()
    await page.screenshot({ path: `${EVIDENCE_DIR}/03-cascade-groups.png`, fullPage: true })
  })

  test('empty-state renders the hi-fi empty card variant', async ({ page }) => {
    // Override the capabilities route with an empty cascade for this test —
    // the panel's empty branch returns ipp--empty instead of the populated
    // panel, so navigate manually rather than via gotoCapabilityTab().
    await page.route(`**/api/v1/agents/${AGENT_ID}/capabilities`, (r) =>
      r.fulfill({ json: { allow: [], deny: [], sources: [] } }),
    )
    await page.goto('/')
    await page.evaluate((id) => window.history.pushState({}, '', `/agents/${id}`), AGENT_ID)
    await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
    await page.getByTestId('agent-detail-tab-capability').click()

    const empty = page.getByTestId('inherited-permissions-empty')
    await expect(empty).toBeVisible()
    await expect(empty.locator('.ipp__empty-title')).toHaveText('No cascade contribution')
    await page.screenshot({ path: `${EVIDENCE_DIR}/04-empty-state.png`, fullPage: true })
  })
})
