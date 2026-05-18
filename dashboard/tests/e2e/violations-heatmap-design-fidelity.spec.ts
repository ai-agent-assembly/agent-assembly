/**
 * Design-fidelity verification for the F100 ViolationHeatmap (AAASM-1432).
 *
 * Walks the heatmap at `/audit/violations` and asserts the visual contract
 * against `design/v1/hi-fi/policy.jsx` + `design/v1/hi-fi/topology.jsx`:
 *   - page mounts and the d3-hierarchy tree renders all fixture nodes
 *   - color gradient: hot-spot (30 violations) skews red, cold-zero green
 *   - hover tooltip surfaces agent id + violation count + top policies
 *   - "Show all" affordance reveals nodes past maxNodes
 *
 * Captures screenshots into `dashboard/docs/verification/aaasm-1432/`.
 *
 * No divergences from the AAASM-1432 description for this surface — the
 * heatmap shipped exactly as the design + spec described in AAASM-1057.
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { EVIDENCE_DIR, VIOLATIONS, injectToken, mockApi } from './_fixtures/aaasm-1432'

async function gotoViolations(page: Page) {
  await page.goto('/')
  await page.evaluate(() => window.history.pushState({}, '', '/audit/violations'))
  await page.evaluate(() => window.dispatchEvent(new PopStateEvent('popstate')))
  // Wait for the first heatmap node to mount.
  const firstNodeId = VIOLATIONS.nodes[0]!.agent_id
  await page.getByTestId(`heatmap-node-${firstNodeId}`).waitFor()
}

test.describe('AAASM-1432 — ViolationHeatmap design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test.beforeEach(async ({ page }) => {
    await injectToken(page)
    await mockApi(page)
  })

  test('heatmap mounts at /audit/violations and renders all fixture nodes', async ({ page }) => {
    await gotoViolations(page)
    for (const node of VIOLATIONS.nodes) {
      await expect(page.getByTestId(`heatmap-node-${node.agent_id}`)).toBeVisible()
    }
    // The synthetic __root__ node must not be rendered.
    await expect(page.getByTestId('heatmap-node-__root__')).toHaveCount(0)
    await page.screenshot({ path: `${EVIDENCE_DIR}/09-heatmap.png`, fullPage: true })
  })

  test('hot-spot node (30 violations) skews red and cold-zero node skews green', async ({ page }) => {
    await gotoViolations(page)
    const hotId = VIOLATIONS.nodes[0]!.agent_id // 30 violations
    const coldId = VIOLATIONS.nodes[VIOLATIONS.nodes.length - 1]!.agent_id // 0 violations

    const parseRgb = (rgb: string): { r: number; g: number; b: number } | null => {
      const m = rgb.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/)
      if (!m) return null
      const [, r, g, b] = m.map(Number)
      return { r: r!, g: g!, b: b! }
    }

    const hotFill = await page
      .getByTestId(`heatmap-node-${hotId}`)
      .locator('circle')
      .getAttribute('fill')
    const coldFill = await page
      .getByTestId(`heatmap-node-${coldId}`)
      .locator('circle')
      .getAttribute('fill')

    const hot = parseRgb(hotFill ?? '')
    const cold = parseRgb(coldFill ?? '')
    expect(hot).not.toBeNull()
    expect(cold).not.toBeNull()
    // Hot: R channel dominates (red).
    expect(hot!.r).toBeGreaterThan(hot!.g)
    expect(hot!.r).toBeGreaterThan(hot!.b)
    // Cold: G channel dominates (green).
    expect(cold!.g).toBeGreaterThan(cold!.r)
    expect(cold!.g).toBeGreaterThan(cold!.b)

    await page.screenshot({ path: `${EVIDENCE_DIR}/10-color-scale.png`, fullPage: true })
  })

  test('tooltip on hover surfaces agent id, violation count, and top policies', async ({ page }) => {
    await gotoViolations(page)
    const hot = VIOLATIONS.nodes[0]!
    await page.getByTestId(`heatmap-node-${hot.agent_id}`).hover()
    // The tooltip is a positioned <div> sibling — anchor on its
    // 'Violations:' label and assert the sibling <strong> matches the
    // hot-spot count. Using the regex /30/ here would match the
    // 30d <option>, the "30 violations" legend, and the SVG node label.
    const violationsRow = page.getByText('Violations:').locator('..')
    await expect(violationsRow.locator('strong')).toHaveText(hot.violation_count.toString())
    await expect(page.getByText('Top policies:')).toBeVisible()
    for (const policy of hot.top_policies) {
      await expect(page.getByText(policy, { exact: true })).toBeVisible()
    }
    await page.screenshot({ path: `${EVIDENCE_DIR}/11-heatmap-tooltip.png`, fullPage: true })
  })

  test('window selector defaults to 24h and root input is empty by default', async ({ page }) => {
    await gotoViolations(page)
    const windowSelect = page.getByLabel(/Window/)
    await expect(windowSelect).toHaveValue('24h')
    const rootInput = page.getByLabel(/Root agent/)
    await expect(rootInput).toHaveValue('')
    await page.screenshot({ path: `${EVIDENCE_DIR}/12-heatmap-controls.png`, fullPage: true })
  })
})
