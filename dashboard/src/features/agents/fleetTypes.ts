import type { Agent } from './api'

/**
 * `policy_violations_count` at or above this threshold marks an agent as
 * "flagged" in the Fleet view (rendered with a danger-tinted row in
 * `design/v1/fleet.jsx`).
 */
export const FLEET_FLAGGED_THRESHOLD = 50

/** One agent's blocked + scrubbed decision counts over the metrics window. */
export interface AgentEnforcementCount {
  readonly blocked: number
  readonly scrubbed: number
}

/**
 * Per-agent enforcement counts keyed by agent id, as returned (folded into a
 * lookup) by `GET /api/v1/analytics/agent-enforcement` (AAASM-5084). Absence of
 * a key means the agent recorded no blocked/scrubbed decisions in the window,
 * which the Fleet view renders as `—` rather than `0`.
 *
 * A Map, not a plain object: `agent_id` is raw wire input, so a value of
 * `constructor`/`__proto__`/etc. must be an ordinary key rather than hitting
 * the prototype setter or colliding with an inherited member (AAASM-5237).
 */
export type AgentEnforcementLookup = ReadonlyMap<string, AgentEnforcementCount>

/** Enforcement modes rendered by `ModeChip`. */
export type FleetMode = 'enforce' | 'shadow' | 'off'

const MODE_VALUES: readonly FleetMode[] = ['enforce', 'shadow', 'off']

/**
 * Projection of an `AgentResponse` onto the columns the Fleet page renders.
 *
 * `blocked24h` / `scrubbed24h` are sourced from the per-agent enforcement
 * endpoint (AAASM-5084) when a lookup is supplied to `toFleetAgent`; an agent
 * absent from that lookup — and any metric with no backing endpoint yet
 * (`trust`) — is represented as `null` so table cells render an unambiguous `—`
 * placeholder rather than a misleading zero.
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

/**
 * Project an `AgentResponse` onto the Fleet page view-model.
 *
 * When an `enforcement` lookup is supplied (from
 * `GET /api/v1/analytics/agent-enforcement`), this agent's `blocked24h` /
 * `scrubbed24h` are filled from it; an agent missing from the lookup — or no
 * lookup at all (the metrics query still loading, or a caller that doesn't need
 * the counts) — leaves both `null`, so the view renders `—`.
 */
export function toFleetAgent(agent: Agent, enforcement?: AgentEnforcementLookup): FleetAgent {
  const metadata = agent.metadata ?? {}
  const counts = enforcement?.get(agent.id)
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
    blocked24h: counts ? counts.blocked : null,
    scrubbed24h: counts ? counts.scrubbed : null,
    note: metadata.note ?? null,
  }
}
