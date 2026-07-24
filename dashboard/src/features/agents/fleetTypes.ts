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

/**
 * Humanize a `lastSeen` ISO 8601 timestamp into a compact relative label
 * ("12s ago", "5m ago", "2h ago", "3d ago"), matching the hi-fi Fleet table in
 * `design/v1/fleet.jsx` (AAASM-5069). The raw ISO stays in the view-model so the
 * column still sorts chronologically; humanizing happens only at render.
 *
 * `null`/unparseable input yields `—`; timestamps in the future clamp to "now".
 */
export function formatLastSeen(iso: string | null, now: number = Date.now()): string {
  if (!iso) return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return iso
  const secs = Math.max(0, Math.floor((now - then) / 1000))
  if (secs < 60) return `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
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
