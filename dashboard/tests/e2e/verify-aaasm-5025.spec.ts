/**
 * Verification capture for AAASM-5025 — Live Ops chrome: LIVE/PAUSED pill +
 * pulse, the wired counters/stats strip (fed by `PipelineCanvas`'s
 * `onCounters`), the lane-fate legend, and the header speed controls.
 *
 * This is an evidence-capture spec, not a pixel-baseline: it stands the page
 * up against a mock WS (so the header pill reaches the `LIVE` state) and a
 * few seeded violation frames, lets the client-side pipeline simulation run
 * long enough for the counters to accumulate, then screenshots the page in
 * both light and dark themes into `dashboard/verify/AAASM-5025/` for review
 * next to `design/v1/hi-fi/live-ops.jsx`.
 *
 * The counters strip is driven by the canvas's own particle simulation, not
 * by WS frames, so the numbers climb on their own once the page is visible.
 */

import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/AAASM-5025')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

const AGENTS = [
  { id: 'support-agent', name: 'support-agent', framework: '', metadata: {}, active_sessions: [] },
  { id: 'billing-agent', name: 'billing-agent', framework: '', metadata: {}, active_sessions: [] },
  { id: 'ops-agent', name: 'ops-agent', framework: '', metadata: {}, active_sessions: [] },
]

const TEAMS = [{ team_id: 'support', agent_count: 3, root_agent_count: 1 }]

function violationFrame(id: number, decision: string) {
  return {
    event_type: 'violation',
    id: `evt-${id}`,
    agent_id: AGENTS[id % AGENTS.length].id,
    timestamp: new Date().toISOString(),
    payload: {
      kind: 'audit',
      op_type: 'read',
      resource: 'gmail.send',
      status: decision === 'approval' ? 'blocked' : 'running',
      team: 'support',
      latency_ms: 42,
    },
  }
}

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Mint endpoint the WS ticket flow calls before every connect.
  await page.route('**/api/v1/auth/ws-ticket', (route) =>
    route.fulfill({ json: { ticket: 'e2e-verify-ticket' } }),
  )
  await page.route('**/api/v1/agents**', (route) => route.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/topology/teams**', (route) =>
    route.fulfill({ json: TEAMS }),
  )

  // Accept the WS (keeps the socket open → hook reports `connected` → the
  // header pill reads `LIVE`) and push a handful of seeded frames so the
  // event stream + approval pool have content in the capture.
  await page.routeWebSocket('**/api/v1/ws/events**', (ws) => {
    const decisions = ['allow', 'narrow', 'scrub', 'approval', 'deny']
    decisions.forEach((d, i) => ws.send(JSON.stringify(violationFrame(i, d))))
  })

  await page.goto('/live')
  await expect(page.getByTestId('live-ops-page')).toBeVisible()
  await expect(page.getByTestId('live-ops-counters')).toBeVisible()
  await expect(page.getByTestId('live-ops-legend')).toBeVisible()
  // Let the pipeline simulation run so the counters strip populates.
  await page.waitForTimeout(1800)
}

test.describe('AAASM-5025 — Live Ops chrome verification', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`captures the Live Ops header + strip in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)

      // Pill is LIVE while the mock WS stays connected.
      await expect(page.getByTestId('live-ops-state-pill')).toContainText('LIVE')

      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `01-live-${theme}.png`),
        fullPage: true,
      })

      // Flip to PAUSED via the header control and re-capture the header.
      await page.getByTestId('live-ops-pause').click()
      await expect(page.getByTestId('live-ops-state-pill')).toContainText('PAUSED')
      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `02-paused-${theme}.png`),
        fullPage: true,
      })
    })
  }
})
