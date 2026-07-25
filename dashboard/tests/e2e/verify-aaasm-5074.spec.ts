/**
 * Verification capture for AAASM-5074 — Live-Ops FE parity (Wave 2):
 *   - inline approve / reject (shared ApprovalActions mounted on the
 *     approval-pool cards, wired to /approvals/{id}/approve|reject)
 *   - op-control affordances (row pause/resume/terminate + halt-agent, and
 *     the global halt-all kill switch on the counters bar)
 *   - the ▤ pipeline / ◎ castle-moat view toggle
 *   - the dark-terminal event-stream reskin
 *
 * Evidence-capture spec, not a pixel baseline: it stands the built page up
 * against a mock WS (so the header pill reaches LIVE) seeded with a mix of
 * running / blocked / pending frames, then screenshots the relevant surfaces
 * in both light and dark themes into `dashboard/verify/parity-liveops/` for
 * review next to `design/v1/hi-fi/live-ops.jsx`.
 */

import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(
  process.cwd(),
  process.env.AAASM5074_OUT ?? 'verify/parity-liveops',
)
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

const AGENTS = [
  { id: 'support-agent', name: 'support-agent', framework: '', metadata: {}, active_sessions: [] },
  { id: 'billing-agent', name: 'billing-agent', framework: '', metadata: {}, active_sessions: [] },
  { id: 'ops-agent', name: 'ops-agent', framework: '', metadata: {}, active_sessions: [] },
]

const TEAMS = [{ team_id: 'support', agent_count: 3, root_agent_count: 1 }]

// A spread of lifecycle states so the terminal feed shows the 3 wire-carried
// decision colours and the approval pool has pending cards to act on.
const FRAMES: Array<{ verb: string; resource: string; status: string }> = [
  { verb: 'read', resource: 'gmail.read', status: 'running' },
  { verb: 'write', resource: 'pg.users', status: 'pending' },
  { verb: 'exec', resource: 'shell.exec', status: 'blocked' },
  { verb: 'read', resource: 'gdrive.read', status: 'running' },
  { verb: 'write', resource: 's3.write', status: 'pending' },
  { verb: 'delete', resource: 'github.commit', status: 'running' },
  { verb: 'write', resource: 'http.post', status: 'blocked' },
  { verb: 'read', resource: 'gmail.send', status: 'pending' },
]

function frame(i: number) {
  const f = FRAMES[i % FRAMES.length]
  return {
    event_type: 'violation',
    id: `evt-${i}`,
    agent_id: AGENTS[i % AGENTS.length].id,
    timestamp: new Date().toISOString(),
    payload: {
      kind: 'audit',
      op_type: f.verb,
      resource: f.resource,
      status: f.status,
      team: 'support',
      latency_ms: 42 + i,
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

  await page.route('**/api/v1/auth/ws-ticket', (route) =>
    route.fulfill({ json: { ticket: 'e2e-verify-ticket' } }),
  )
  await page.route('**/api/v1/agents**', (route) => route.fulfill({ json: AGENTS }))
  await page.route('**/api/v1/topology/teams**', (route) =>
    route.fulfill({ json: TEAMS }),
  )
  // Approve / reject + op-control endpoints resolve OK so the inline actions
  // and the confirm-gated controls behave in the capture.
  await page.route('**/api/v1/approvals/**', (route) =>
    route.fulfill({ json: { id: 'evt', status: 'approved' } }),
  )
  await page.route('**/api/v1/ops/**', (route) =>
    route.fulfill({ status: 204, body: '' }),
  )

  await page.routeWebSocket('**/api/v1/ws/events**', (ws) => {
    FRAMES.forEach((_, i) => ws.send(JSON.stringify(frame(i))))
  })

  await page.goto('/live')
  await expect(page.getByTestId('live-ops-page')).toBeVisible()
  await expect(page.getByTestId('live-ops-state-pill')).toContainText('LIVE')
  // Let the client-side pipeline simulation populate the counters strip.
  await page.waitForTimeout(1500)
}

test.describe('AAASM-5074 — Live-Ops FE parity verification', () => {
  test.beforeAll(async () => {
    await mkdir(EVIDENCE_DIR, { recursive: true })
  })

  for (const theme of ['light', 'dark'] as const) {
    test(`captures the parity surfaces in ${theme} theme`, async ({ page }) => {
      await bootstrap(page, theme)

      // 01 — full page: pipeline view + dark-terminal stream + approval pool +
      // solid page-on-call + neutral allow legend + halt-all on the bar.
      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `01-pipeline-full-${theme}.png`),
        fullPage: true,
      })

      // 02 — inline approve/reject: the approvals zone with ApprovalActions
      // mounted on each pending card.
      const approvals = page.getByTestId('live-ops-approvals-zone')
      await expect(approvals.getByTestId('approval-approve-btn').first()).toBeVisible()
      await approvals.screenshot({
        path: resolve(EVIDENCE_DIR, `02-inline-approve-reject-${theme}.png`),
      })

      // 03 — reject reason capture revealed inline on the first card.
      await approvals.getByTestId('approval-reject-btn').first().click()
      await expect(
        approvals.getByTestId('approval-reject-reason').first(),
      ).toBeVisible()
      await approvals.screenshot({
        path: resolve(EVIDENCE_DIR, `03-reject-reason-${theme}.png`),
      })
      // Back out of the reject flow.
      await approvals.getByTestId('approval-reject-cancel').first().click()

      // 04 — op-control row menu: pause / resume / terminate / halt agent.
      await page.getByTestId('row-action-trigger').first().click()
      await expect(page.getByTestId('row-action-halt-agent')).toBeVisible()
      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `04-op-control-menu-${theme}.png`),
        fullPage: true,
      })
      await page.keyboard.press('Escape')

      // 05 — global halt-all confirm dialog from the counters bar.
      await page.getByTestId('live-ops-halt-all').click()
      await expect(page.getByTestId('confirm-dialog')).toBeVisible()
      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `05-halt-all-confirm-${theme}.png`),
        fullPage: true,
      })
      await page.getByTestId('confirm-dialog-cancel').click()

      // 06 — castle-moat view via the segmented toggle.
      await page.getByTestId('live-ops-view-moat').click()
      await expect(page.getByTestId('castle-moat')).toBeVisible()
      await page.waitForTimeout(1200)
      await page.screenshot({
        path: resolve(EVIDENCE_DIR, `06-castle-moat-${theme}.png`),
        fullPage: true,
      })

      // 07 — terminal feed close-up (stream zone) back in the pipeline view.
      await page.getByTestId('live-ops-view-pipeline').click()
      const stream = page.getByTestId('live-ops-stream-zone')
      await expect(stream).toBeVisible()
      await stream.screenshot({
        path: resolve(EVIDENCE_DIR, `07-terminal-feed-${theme}.png`),
      })
    })
  }
})
