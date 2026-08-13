/**
 * Verification capture for AAASM-5073 — the agent-detail FE-parity build:
 *   - Overview 3rd panel: agent-scoped capability matrix (hybrid — added beside
 *     the existing burn-chart + recent-events).
 *   - Capability tab: agent-scoped resource×verb matrix replacing the old
 *     InheritedPermissionsPanel, with granted_by / denied_by_ancestor cascade
 *     provenance folded into the inspect drawer.
 *   - Config tab: FE-derived YAML, backend-only keys marked "— (pending backend)".
 *
 * Evidence-capture spec (not a pixel baseline): stubs the endpoints the page
 * reads, opens the agent-detail drawer, and screenshots the three surfaces in
 * light and dark into `dashboard/verify/parity-agentdetail/` for review beside
 * `design/v1/hi-fi/agent-detail.jsx`.
 */
import { expect, test, type Page } from '@playwright/test'
import { mkdir } from 'node:fs/promises'
import { resolve } from 'node:path'

const EVIDENCE_DIR = resolve(process.cwd(), 'verify/parity-agentdetail')
const THEME_KEY = 'aa-dashboard-theme'
type Theme = 'light' | 'dark'

const AGENT_ID = 'research-bot-04'

const AGENT = {
  id: AGENT_ID,
  name: 'research-bot-04',
  framework: 'langgraph',
  status: 'active',
  version: '0.1.0',
  layer: 'enforced',
  last_event: '2026-05-12T00:00:00Z',
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  session_count: 1421,
  policy_violations_count: 63,
  tool_names: ['gmail.send', 'pg.users'],
  metadata: { owner: 'alice', mode: 'shadow' },
  pid: null,
}

const RESOURCES = [
  { id: 'gmail', name: 'Gmail', group: 'comm', paths: ['gmail/*'] },
  { id: 'gdrive', name: 'Google Drive', group: 'files', paths: ['gdrive/*'] },
  { id: 's3', name: 'AWS S3', group: 'files', paths: ['s3://*'] },
  { id: 'pg', name: 'Postgres', group: 'data', paths: ['pg.public.*'] },
  { id: 'http', name: 'HTTP egress', group: 'infra', paths: ['https://*'] },
]

const MATRIX = {
  resources: RESOURCES,
  sampleCalls: [
    { ts: '09:12:04', agent: AGENT_ID, verb: 'write', resource: 'pg.public.users', currentDecision: 'deny' },
    { ts: '09:11:41', agent: AGENT_ID, verb: 'write', resource: 'gmail/send', currentDecision: 'narrow' },
  ],
  policies: [
    { id: 'P-001', name: 'global default-deny', version: '1', scope: 'global', status: 'active', hits24h: 4210, affects: [AGENT_ID], rules: [] },
    { id: 'P-066', name: 'narrow research-bot writes', version: '3', scope: 'tag:research', status: 'proposed', hits24h: 128, affects: [AGENT_ID], rules: [{ resource: 'pg', verb: ['write'], action: 'narrow', condition: '' }] },
  ],
  agents: [
    {
      id: AGENT_ID,
      name: 'research-bot-04',
      framework: 'langgraph',
      owner: 'alice',
      trust: 62,
      mode: 'shadow',
      status: 'active',
      lastSeen: '2m ago',
      flagged: true,
      caps: {
        gmail: { read: 'allow', write: 'narrow', delete: 'na', exec: 'na', flag: true },
        gdrive: { read: 'allow', write: 'narrow', delete: 'na', exec: 'na' },
        s3: { read: 'allow', write: 'approval', delete: 'deny', exec: 'na' },
        pg: { read: 'allow', write: 'deny', delete: 'deny', exec: 'na', flag: true },
        http: { read: 'allow', write: 'narrow', delete: 'na', exec: 'na' },
      },
    },
  ],
}

const CAPABILITIES = {
  allow: ['file_read', 'network_egress'],
  deny: ['file_write', 'agent_spawn'],
  sources: [
    { scope: 'global', allow: ['file_read'], deny: ['agent_spawn'] },
    { scope: 'team:research', allow: ['network_egress'], deny: ['file_write'] },
  ],
}

async function bootstrap(page: Page, theme: Theme) {
  await page.addInitScript(
    (opts: { themeKey: string; theme: string }) => {
      sessionStorage.setItem('aa_token', 'e2e-verify-token')
      localStorage.setItem(opts.themeKey, opts.theme)
    },
    { themeKey: THEME_KEY, theme },
  )

  // Broadest → narrowest (Playwright matches most-recently-registered first).
  await page.route('**/api/v1/**', (r) => r.fulfill({ json: {} }))
  await page.route('**/api/v1/auth/ws-ticket', (r) => r.fulfill({ json: { ticket: 'e2e-ticket' } }))
  await page.route('**/api/v1/agents**', (r) => r.fulfill({ json: { items: [AGENT], total: 1 } }))
  await page.route('**/api/v1/logs**', (r) => r.fulfill({ json: { items: [], total: 0 } }))
  await page.route('**/api/v1/capability/matrix**', (r) => r.fulfill({ json: MATRIX }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/capabilities`, (r) => r.fulfill({ json: CAPABILITIES }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/subtree-burn**`, (r) =>
    r.fulfill({ json: { total: 0, daily: [], children: [] } }),
  )
  await page.route(`**/api/v1/agents/${AGENT_ID}`, (r) => r.fulfill({ json: AGENT }))
}

async function shot(page: Page, name: string) {
  await page.screenshot({ path: resolve(EVIDENCE_DIR, name), fullPage: true })
}

test.beforeAll(async () => {
  await mkdir(EVIDENCE_DIR, { recursive: true })
})

// Open the agent-detail drawer via the Fleet route. The production build emits
// relative asset paths that 404 on a deep link like `/agents/:id`, so load the
// single-segment Fleet route first, then open the drawer with a row click.
async function openAgentDetail(page: Page, theme: Theme) {
  await bootstrap(page, theme)
  await page.goto('/agents')
  await page.getByTestId('fleet-row-name').first().click()
  await expect(page.getByTestId('agent-detail')).toBeVisible()
}

// Each surface is captured from a fresh drawer open (one tab navigation per
// test) so the modal drawer / tab transitions never interfere across steps.
for (const theme of ['light', 'dark'] as const) {
  test(`overview capability panel — ${theme}`, async ({ page }) => {
    await openAgentDetail(page, theme)
    await expect(page.getByTestId('agent-overview-capability')).toBeVisible()
    await expect(page.getByTestId('agent-overview-capability-matrix')).toBeVisible()
    await shot(page, `overview-matrix-${theme}.png`)
  })

  test(`capability tab matrix — ${theme}`, async ({ page }) => {
    await openAgentDetail(page, theme)
    await page.getByTestId('agent-detail-tab-capability').click()
    await expect(page.getByTestId('agent-capability-tab-matrix')).toBeVisible()

    // Since AAASM-5125/5197 the matrix opens on the verb the loaded grid
    // populates most, not a hard-coded verb: this fixture's 5 resources tie
    // read/write at 5 populated cells each, so it lands on READ (first in
    // VERBS order) — every cell allow, no deny cell to inspect. This capture
    // is specifically about the pg×write deny cell, so select WRITE
    // explicitly before screenshotting and inspecting it.
    await page.getByRole('radio', { name: 'write' }).click()
    await shot(page, `capability-matrix-${theme}.png`)

    // Inspect the pg×write (deny) cell to show the folded cascade provenance.
    await page.locator('.cap-mx-cell--deny').first().click()
    await expect(page.getByTestId('agent-capability-inspect-drawer')).toBeVisible()
    await expect(page.getByTestId('aci-provenance')).toBeVisible()
    await shot(page, `capability-drawer-${theme}.png`)
  })

  test(`config yaml — ${theme}`, async ({ page }) => {
    await openAgentDetail(page, theme)
    await page.getByTestId('agent-detail-tab-config').click()
    await expect(page.getByTestId('agent-config-yaml')).toBeVisible()
    await expect(page.getByTestId('agent-config-pending-line').first()).toBeVisible()
    await shot(page, `config-yaml-${theme}.png`)
  })
}
