import type { Agent } from './api'

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

/**
 * Per-agent trust scores keyed by agent id, as returned (folded into a lookup)
 * by `GET /api/v1/analytics/trust` (AAASM-5083, ADR 0019). The mapped value is
 * the agent's score on a 0–100 scale, or `null` for a cold-start agent
 * (`< MIN_ACTIONS` governed actions in the window). A key absent from the lookup
 * — an agent that recorded no governed action, or a truncated window that emits
 * no scores at all — is likewise treated as `null` by `toFleetAgent`, so both
 * the "no score" and "cold-start" cases render `—` rather than a fabricated `0`.
 *
 * A Map, not a plain object, for the same prototype-pollution reason as
 * `AgentEnforcementLookup` (AAASM-5237): `agent_id` is raw wire input.
 */
export type AgentTrustLookup = ReadonlyMap<string, number | null>

/** Enforcement modes rendered by `ModeChip`. */
export type FleetMode = 'enforce' | 'shadow' | 'off'

const MODE_VALUES: readonly FleetMode[] = ['enforce', 'shadow', 'off']

/**
 * Projection of an `AgentResponse` onto the columns the Fleet page renders.
 *
 * `blocked24h` / `scrubbed24h` are sourced from the per-agent enforcement
 * endpoint (AAASM-5084), and `trust` from the trust rollup (AAASM-5083), when
 * the corresponding lookup is supplied to `toFleetAgent`; an agent absent from a
 * lookup — or a cold-start agent whose `trust` the endpoint reports as `null` —
 * is represented as `null` so table cells render an unambiguous `—` placeholder
 * rather than a misleading zero.
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
 *
 * Likewise, when a `trust` lookup is supplied (from `GET /api/v1/analytics/trust`,
 * AAASM-5083), this agent's `trust` is filled from it. The endpoint reports a
 * cold-start agent (`< MIN_ACTIONS`) as an explicit `null`, and omits an agent
 * with no governed actions (and every agent when the window is truncated). All
 * three of those — explicit `null`, absent key, and no lookup at all — collapse
 * to `null` here, so the view renders `—`. The score is never coerced to `0`.
 */
export function toFleetAgent(
  agent: Agent,
  enforcement?: AgentEnforcementLookup,
  trust?: AgentTrustLookup,
): FleetAgent {
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
    // AAASM-5103 — consume the backend's audit-derived flag (`is_flagged`,
    // count>0) rather than re-deriving a threshold client-side, so the Fleet and
    // Topology surfaces cannot disagree about whether an agent is flagged.
    flagged: agent.is_flagged,
    lastSeen: agent.last_event ?? null,
    // `?? null` folds a cold-start `null` and an absent key alike to `null`; the
    // score is never coerced to `0` (ADR 0019 truthfulness contract).
    trust: trust?.get(agent.id) ?? null,
    blocked24h: counts ? counts.blocked : null,
    scrubbed24h: counts ? counts.scrubbed : null,
    note: metadata.note ?? null,
  }
}
