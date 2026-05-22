/**
 * Design-fidelity verification for the Live Ops UI (AAASM-1684 — PR-C
 * follow-up under AAASM-1422).
 *
 * Walks the rendered LiveOpsPage and asserts the *visual* contract for
 * the 5-state lifecycle introduced by AAASM-1652 (PR-C of AAASM-1422):
 *
 *   - `FilterBar` status dropdown exposes ALL five `OperationStatus`
 *     options: Running, Pending, Blocked, Completing, Terminated.
 *   - Each `op-row__chip--<state>` class resolves to its expected
 *     token palette (background / border / text). The new `terminated`
 *     chip (CSS rule added in this PR) uses the neutral muted-text
 *     palette so it reads as "informational, archived" rather than
 *     danger-red.
 *
 * Captures full-page screenshots of the filter dropdown + a chip palette
 * legend into `dashboard/docs/verification/aaasm-1684/` for visual
 * review alongside the hi-fi (precedent: AAASM-1395 alerts, AAASM-1383
 * trace, AAASM-1384 topology).
 *
 * NOT covered here (scope-limited per the AAASM-1684 starting comment):
 *
 *   - Live WS-driven row updates (would require `routeWebSocket` or a
 *     real WS test server; the row-merge + override-clear behaviour is
 *     already covered functionally by PR-C's vitest cases).
 *   - Backend integration (PR-A through PR-H Rust tests cover that).
 */

import { test, expect, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1684')

// ── Token RGB values (from src/styles.css). Asserted as RGB because
//    getComputedStyle returns colors in that form. ──────────────────────────

const TOKEN_RGB = {
  // Existing 4 chip palette tokens (LiveOps-local, defined in styles.css
  // under :root). These were not introduced by this PR and are asserted
  // here only to detect accidental drift.
  okBg: 'rgb(212, 228, 210)', // --ok-bg     #d4e4d2
  ok: 'rgb(34, 89, 42)', //         --ok        #22592a
  infoBg: 'rgb(214, 223, 238)', // --info-bg   #d6dfee
  info: 'rgb(29, 58, 122)', //       --info      #1d3a7a
  warnBg: 'rgb(245, 230, 196)', // --warn-bg   #f5e6c4
  warn: 'rgb(138, 90, 0)', //        --warn      #8a5a00
  dangerBg: 'rgb(246, 218, 214)', // --danger-bg #f6dad6
  danger: 'rgb(184, 41, 30)', //   --danger    #b8291e
  // NEW for AAASM-1684 — terminated uses the neutral muted-text palette.
  surfaceSubtleBg: 'rgb(249, 250, 251)', // --surface-subtle-bg  #f9fafb
  surfaceCardBorder: 'rgb(229, 231, 235)', // --surface-card-border #e5e7eb
  textMuted: 'rgb(107, 114, 128)', //        --text-muted          #6b7280
}

async function injectToken(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem('aa_token', 'e2e-test-token')
  })
}

async function bootstrapLiveOpsPage(page: Page) {
  await injectToken(page)
  // No live data needed — we're verifying the chip + filter contracts,
  // not the streaming pipeline. Abort the WS so the page settles into
  // the EmptyState quickly.
  await page.route('**/api/v1/ws/events**', (route) => route.abort())
  // Agents + teams queries are unrelated to the chip palette; fulfill
  // empty so the FilterBar still hydrates without spinning.
  await page.route('**/api/v1/agents**', (route) => route.fulfill({ json: [] }))
  await page.route('**/api/v1/topology/teams**', (route) =>
    route.fulfill({ json: [] }),
  )
  await page.goto('/live')
  await expect(page.getByTestId('live-ops-page')).toBeVisible()
}

test.describe('AAASM-1684 — LiveOps design fidelity', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  test('FilterBar status dropdown lists all 5 lifecycle states', async ({ page }) => {
    await bootstrapLiveOpsPage(page)
    const statusFilter = page.getByTestId('filter-status')
    await expect(statusFilter).toBeVisible()
    const labels = await statusFilter.locator('option').allInnerTexts()
    expect(labels).toEqual(
      expect.arrayContaining(['All', 'Running', 'Pending', 'Blocked', 'Completing', 'Terminated']),
    )
    expect(labels.filter((l) => l !== 'All')).toHaveLength(5)
    await page.screenshot({
      path: resolve(EVIDENCE_DIR, '01-filter-status-5-states.png'),
      fullPage: true,
    })
  })

  test('every chip palette class resolves to its documented token', async ({ page }) => {
    await bootstrapLiveOpsPage(page)

    // Synthesize one chip per state directly in the DOM so we can read
    // getComputedStyle without standing up the streaming pipeline.
    const palette = await page.evaluate(() => {
      const states = ['running', 'pending', 'blocked', 'completing', 'terminated'] as const
      const host = document.createElement('div')
      // Append to body so inherited tokens cascade from :root.
      document.body.appendChild(host)
      try {
        const out: Record<string, { bg: string; border: string; color: string }> = {}
        for (const state of states) {
          const chip = document.createElement('span')
          chip.className = `op-row__chip op-row__chip--${state}`
          chip.textContent = state.toUpperCase()
          host.appendChild(chip)
          const cs = window.getComputedStyle(chip)
          out[state] = {
            bg: cs.backgroundColor,
            border: cs.borderTopColor,
            color: cs.color,
          }
        }
        return out
      } finally {
        host.remove()
      }
    })

    expect(palette.running).toEqual({
      bg: TOKEN_RGB.infoBg,
      border: TOKEN_RGB.info,
      color: TOKEN_RGB.info,
    })
    expect(palette.pending).toEqual({
      bg: TOKEN_RGB.warnBg,
      border: TOKEN_RGB.warn,
      color: TOKEN_RGB.warn,
    })
    expect(palette.blocked).toEqual({
      bg: TOKEN_RGB.dangerBg,
      border: TOKEN_RGB.danger,
      color: TOKEN_RGB.danger,
    })
    expect(palette.completing).toEqual({
      bg: TOKEN_RGB.okBg,
      border: TOKEN_RGB.ok,
      color: TOKEN_RGB.ok,
    })
    // The contract this PR establishes: terminated reads as neutral
    // muted-text, not red. Validates that the new CSS rule resolved.
    expect(palette.terminated).toEqual({
      bg: TOKEN_RGB.surfaceSubtleBg,
      border: TOKEN_RGB.surfaceCardBorder,
      color: TOKEN_RGB.textMuted,
    })

    // Render the 5-chip legend inline so the screenshot captures the
    // visual progression for design review.
    await page.evaluate(() => {
      const states = ['running', 'pending', 'blocked', 'completing', 'terminated'] as const
      const legend = document.createElement('div')
      legend.setAttribute('data-testid', 'design-fidelity-chip-legend')
      legend.style.cssText = 'display:flex;gap:12px;padding:24px;background:#fff'
      for (const state of states) {
        const chip = document.createElement('span')
        chip.className = `op-row__chip op-row__chip--${state}`
        chip.textContent = state.toUpperCase()
        legend.appendChild(chip)
      }
      document.body.prepend(legend)
    })
    await page.getByTestId('design-fidelity-chip-legend').screenshot({
      path: resolve(EVIDENCE_DIR, '02-chip-palette-5-states.png'),
    })
  })
})
