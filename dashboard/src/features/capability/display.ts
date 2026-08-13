/**
 * Display folds for capability fields the live endpoint may omit (AAASM-5090).
 *
 * `GET /api/v1/capability/matrix` projects real gateway state and deliberately
 * omits anything it cannot source — trust scores, over-permission flags,
 * per-policy hit counts. Rendering those as `0` would read as a real measurement
 * ("this agent scored zero"), so every such field folds to a single shared
 * placeholder instead.
 *
 * The placeholder itself is re-exported, not re-declared (AAASM-5173): a second
 * `—` constant is a second place it can drift from the shared vocabulary.
 * Prefer `TruthfulValue` from `components/truthfulness` on new surfaces — it
 * also carries *why* the value is missing, which a bare string cannot.
 */
import { NO_DATA } from '../../lib/truthfulness'

export { NO_DATA }

/** Render an optional value, falling back to the no-data placeholder. */
export function orNoData(value: string | number | null | undefined): string {
  return value === null || value === undefined || value === '' ? NO_DATA : String(value)
}

/**
 * Format an ISO 8601 timestamp as a compact relative age (`"2m ago"`).
 *
 * The endpoint returns the registry's raw heartbeat timestamp rather than a
 * pre-rendered phrase, so the relative form is computed at render time and
 * stays correct as the page ages.
 */
export function relativeTime(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return NO_DATA
  const then = Date.parse(iso)
  if (Number.isNaN(then)) return NO_DATA
  const seconds = Math.max(0, Math.round((now - then) / 1000))
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.round(hours / 24)}d ago`
}
