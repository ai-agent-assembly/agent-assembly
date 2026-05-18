/**
 * Shared fixtures for AAASM-1432 design-fidelity specs.
 *
 * Three fidelity specs (permissions-panel, budget-burn, violations-heatmap)
 * each render the same agent against deterministic API responses; sharing the
 * fixtures keeps the mock surface in one place and makes drift visible at
 * review time.
 */

import { resolve } from 'node:path'
import type { Page } from '@playwright/test'

export const EVIDENCE_DIR = resolve(process.cwd(), 'docs/verification/aaasm-1432')

export const AGENT_ID = 'agent-aaasm-1432'

export const AGENT = {
  id: AGENT_ID,
  name: 'support-agent',
  framework: 'langgraph',
  version: '0.1.0',
  status: 'active',
  layer: 'enforced',
  session_count: 1,
  policy_violations_count: 3,
  last_event: '2026-05-15T10:00:00Z',
  tool_names: ['search', 'process_refund'],
  recent_events: [],
  recent_traces: [],
  active_sessions: [],
  metadata: { team: 'eng-platform' },
  pid: null,
}

/**
 * EffectivePermissionsResponse — three-scope cascade with allow/deny in each
 * scope so the panel renders both chip variants and the deny-precedence row.
 */
export const CAPABILITIES = {
  allow: ['fs.read', 'mcp.call', 'net.fetch'],
  deny: ['fs.write', 'net.outbound'],
  sources: [
    {
      scope: 'global',
      allow: ['fs.read', 'mcp.call'],
      deny: [],
    },
    {
      scope: 'team:eng-platform',
      allow: ['net.fetch'],
      deny: ['net.outbound'],
    },
    {
      scope: `agent:${AGENT_ID}`,
      allow: [],
      deny: ['fs.write'],
    },
  ],
}

/**
 * SubtreeBurnResponse — two direct children + a flat root contribution across
 * a 7-day window so the stacked-area chart renders multiple layers and the
 * tooltip can surface per-child % of subtree.
 */
function burnPoint(date: string, total: string, perChild: Array<[string, string, string]>) {
  return {
    date,
    total_usd: total,
    per_child: perChild.map(([child_agent_id, child_name, spent_usd]) => ({
      child_agent_id,
      child_name,
      spent_usd,
    })),
  }
}

export const SUBTREE_BURN = {
  agent_id: AGENT_ID,
  period: '7d',
  points: [
    burnPoint('2026-05-09', '12.40', [['child-a', 'planner', '8.20'], ['child-b', 'executor', '4.20']]),
    burnPoint('2026-05-10', '15.10', [['child-a', 'planner', '9.10'], ['child-b', 'executor', '6.00']]),
    burnPoint('2026-05-11', '11.80', [['child-a', 'planner', '7.30'], ['child-b', 'executor', '4.50']]),
    burnPoint('2026-05-12', '18.90', [['child-a', 'planner', '12.40'], ['child-b', 'executor', '6.50']]),
    burnPoint('2026-05-13', '16.20', [['child-a', 'planner', '10.10'], ['child-b', 'executor', '6.10']]),
    burnPoint('2026-05-14', '14.70', [['child-a', 'planner', '9.20'], ['child-b', 'executor', '5.50']]),
    burnPoint('2026-05-15', '21.30', [['child-a', 'planner', '13.40'], ['child-b', 'executor', '7.90']]),
  ],
}

/**
 * ViolationsByLineageResponse — 5-node lineage with one hot spot at 30
 * violations, three mid-tier nodes, and a cold-zero node so the green→
 * yellow→red gradient is fully exercised.
 */
export const VIOLATIONS = {
  window_secs: 86400,
  generated_at: '2026-05-15T10:00:00Z',
  nodes: [
    {
      agent_id: 'aaaa0000000000000000000000000001',
      parent_agent_id: null,
      team_id: 'eng-platform',
      depth: 0,
      violation_count: 30,
      top_policies: ['deny-write-fs', 'budget-exceeded', 'cred-leak'],
    },
    {
      agent_id: 'aaaa0000000000000000000000000002',
      parent_agent_id: 'aaaa0000000000000000000000000001',
      team_id: 'eng-platform',
      depth: 1,
      violation_count: 8,
      top_policies: ['deny-write-fs'],
    },
    {
      agent_id: 'aaaa0000000000000000000000000003',
      parent_agent_id: 'aaaa0000000000000000000000000001',
      team_id: 'eng-platform',
      depth: 1,
      violation_count: 5,
      top_policies: ['deny-outbound'],
    },
    {
      agent_id: 'aaaa0000000000000000000000000004',
      parent_agent_id: 'aaaa0000000000000000000000000002',
      team_id: 'eng-platform',
      depth: 2,
      violation_count: 4,
      top_policies: [],
    },
    {
      agent_id: 'aaaa0000000000000000000000000005',
      parent_agent_id: 'aaaa0000000000000000000000000002',
      team_id: 'eng-platform',
      depth: 2,
      violation_count: 0,
      top_policies: [],
    },
  ],
}

/**
 * Hi-fi token RGB values from `dashboard/src/styles.css` (which mirrors
 * `design/v1/hi-fi/styles.css`). Used to assert background / colour
 * equivalence between the rendered dashboard and the hi-fi mocks.
 */
export const HIFI_TOKENS = {
  ok: 'rgb(34, 89, 42)', //      #22592a
  okBg: 'rgb(212, 228, 210)', // #d4e4d2
  danger: 'rgb(184, 41, 30)', // #b8291e
  dangerBg: 'rgb(246, 218, 214)', // #f6dad6
  warn: 'rgb(138, 90, 0)', //    #8a5a00
  warnBg: 'rgb(245, 230, 196)', // #f5e6c4
  info: 'rgb(29, 58, 122)', //   #1d3a7a
  infoBg: 'rgb(214, 223, 238)', // #d6dfee
  paper: 'rgb(245, 244, 240)', // #f5f4f0
  paper3: 'rgb(235, 233, 226)', // #ebe9e2
}

/**
 * Inject a bearer token before the first navigation so the auth gate
 * doesn't bounce to /login.
 */
export async function injectToken(page: Page): Promise<void> {
  await page.addInitScript(() => localStorage.setItem('aa_token', 'fidelity-token'))
}

/**
 * Mock the API surface needed for all three F100 fidelity specs. Specs may
 * call this once at beforeEach; individual specs that need different shapes
 * can layer additional `page.route(…)` calls after.
 */
export async function mockApi(page: Page): Promise<void> {
  await page.route(`**/api/v1/agents/${AGENT_ID}`, (r) => r.fulfill({ json: AGENT }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/capabilities`, (r) => r.fulfill({ json: CAPABILITIES }))
  await page.route(`**/api/v1/agents/${AGENT_ID}/subtree-burn*`, (r) => r.fulfill({ json: SUBTREE_BURN }))
  await page.route('**/api/v1/audit/violations-by-lineage*', (r) => r.fulfill({ json: VIOLATIONS }))
  // Endpoints the AgentDetailPage / shell pull but the F100 specs don't care about.
  await page.route(`**/api/v1/logs*`, (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/approvals**', (r) => r.fulfill({ json: [] }))
  await page.route('**/api/v1/ws/events**', (r) => r.abort())
}
