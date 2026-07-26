/**
 * Terminal-transcript rendering for the step 2 gateway probe (AAASM-5132).
 *
 * Lives beside the component rather than inside it so the classification is
 * testable on its own — every branch, including the two that were previously
 * untypeable (`warn` and `err`), without driving the component. It is also what
 * keeps `Step2InstallSdk.tsx` a component-only module for fast refresh.
 */
import { TRUTH_STATE_META, isKnown, type Certain } from '../../../lib/truthfulness'
import type { GatewayHealth } from '../api'

export interface Line {
  kind: 'prompt' | 'cmd' | 'out' | 'ok' | 'warn' | 'err'
  text: string
}

/** The request, echoed so the operator can see exactly what was asked. */
const REQUEST_LINES: readonly Line[] = [
  { kind: 'prompt', text: '$ ' },
  { kind: 'cmd', text: 'GET /api/v1/health' },
]

function formatChecks(checks: GatewayHealth['checks']): string {
  const entries = Object.entries(checks)
  if (entries.length === 0) return 'none reported'
  return entries.map(([name, status]) => `${name}=${status}`).join('  ')
}

/**
 * Turn a probe outcome into terminal lines.
 *
 * The one thing this function may never do is emit an `ok` line for anything
 * other than a gateway that answered with `status: "ok"`.
 */
export function buildProbeLines(result: Certain<GatewayHealth>): Line[] {
  if (!isKnown(result)) {
    const meta = TRUTH_STATE_META[result.state]
    return [
      ...REQUEST_LINES,
      { kind: 'err', text: `✗ ${meta.label.toLowerCase()} — the gateway did not answer` },
      { kind: 'err', text: result.detail ?? 'no response' },
    ]
  }

  const health = result.value
  const body: Line[] = [
    ...REQUEST_LINES,
    { kind: 'out', text: `gateway version  ${health.version}` },
    { kind: 'out', text: `api version      ${health.api_version}` },
    { kind: 'out', text: `subsystems       ${formatChecks(health.checks)}` },
  ]

  if (health.status !== 'ok') {
    return [...body, { kind: 'warn', text: `! gateway reachable but reports "${health.status}"` }]
  }
  return [...body, { kind: 'ok', text: '✓ gateway reachable' }]
}
