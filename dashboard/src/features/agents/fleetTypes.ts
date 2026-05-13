import type { Agent } from './api'

/**
 * `policy_violations_count` at or above this threshold marks an agent as
 * "flagged" in the Fleet view (rendered with a danger-tinted row in
 * `design/v1/fleet.jsx`).
 */
export const FLEET_FLAGGED_THRESHOLD = 50

/** Enforcement modes rendered by `ModeChip`. */
export type FleetMode = 'enforce' | 'shadow' | 'off'

const MODE_VALUES: readonly FleetMode[] = ['enforce', 'shadow', 'off']

/**
 * Projection of an `AgentResponse` onto the columns the Fleet page renders.
 *
 * Numeric metrics not yet backed by an analytics endpoint (`trust`,
 * `blocked24h`, `scrubbed24h`) are represented as `null` so table cells can
 * render an unambiguous `—` placeholder rather than misleading zeros.
 */
export interface FleetAgent {
  readonly source: Agent
  readonly id: string
  readonly name: string
  readonly framework: string
  readonly status: string
  readonly owner: string | null
  readonly mode: FleetMode
  readonly flagged: boolean
  readonly lastSeen: string | null
  readonly trust: number | null
  readonly blocked24h: number | null
  readonly scrubbed24h: number | null
  readonly note: string | null
}

function parseMode(raw: string | undefined): FleetMode {
  if (raw && (MODE_VALUES as readonly string[]).includes(raw)) {
    return raw as FleetMode
  }
  return 'enforce'
}

/** Project an `AgentResponse` onto the Fleet page view-model. */
export function toFleetAgent(agent: Agent): FleetAgent {
  const metadata = agent.metadata ?? {}
  return {
    source: agent,
    id: agent.id,
    name: agent.name,
    framework: agent.framework,
    status: agent.status,
    owner: metadata.owner ?? null,
    mode: parseMode(metadata.mode),
    flagged: agent.policy_violations_count >= FLEET_FLAGGED_THRESHOLD,
    lastSeen: agent.last_event ?? null,
    trust: null,
    blocked24h: null,
    scrubbed24h: null,
    note: metadata.note ?? null,
  }
}
