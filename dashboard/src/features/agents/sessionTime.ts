/**
 * Human-readable "running for" label from an ISO start timestamp, matching the
 * `elapsed()` helper in `design/v1/hi-fi/fleet.jsx`: seconds under a minute,
 * minutes under an hour, hours beyond.
 *
 * `now` defaults to the wall clock but is injectable so callers (and tests) get
 * a stable value; the impure `Date.now()` read is confined here rather than run
 * in a component render body.
 */
export function elapsedLabel(startedAt: string, now: number = Date.now()): string {
  const diff = Math.floor((now - new Date(startedAt).getTime()) / 1000)
  if (!Number.isFinite(diff) || diff < 0) return '—'
  if (diff < 60) return `${diff}s`
  if (diff < 3600) return `${Math.floor(diff / 60)}m`
  return `${Math.floor(diff / 3600)}h`
}
