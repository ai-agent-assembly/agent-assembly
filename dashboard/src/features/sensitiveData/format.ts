/**
 * Rendering epoch-nanosecond timestamps and window widths (AAASM-5360).
 *
 * Every timestamp on these routes is epoch **nanoseconds** as a JSON number, and
 * two things follow that are easy to get wrong quietly.
 *
 * **The division has to happen before the `Date`.** `new Date(nanoseconds)` does
 * not throw; it is a date in the year 56 million, and it renders.
 *
 * **A nanosecond count past 2004 is already beyond `Number.MAX_SAFE_INTEGER`,**
 * so the JSON number is not the integer the server sent — at 1.76e18 the
 * representable values are 256 apart, and `1_760_000_000_482_000_000 / 1e6`
 * evaluates to `1760000000481.9999`. `Math.floor` therefore loses a
 * millisecond; `Math.round` does not. The lost precision is sub-microsecond and
 * irrelevant to a governance timeline, but a timestamp that renders `.481` for a
 * `.482` event is the kind of discrepancy that costs someone an afternoon.
 *
 * Everything here is **UTC and fixed-format**, deliberately:
 *
 *  - the API's window bounds are absolute instants, and a local-time rendering
 *    of a governance record is a different instant to every reader;
 *  - a locale-dependent format makes a screenshot, a test and a support ticket
 *    disagree about what they are looking at.
 */

/** Nanoseconds in one millisecond. */
const NS_PER_MS = 1_000_000

/** `2026-08-07 14:02 UTC` — sortable, unambiguous, locale-independent. */
export function formatInstantNs(nanoseconds: number): string {
  const date = new Date(Math.round(nanoseconds / NS_PER_MS))
  if (Number.isNaN(date.getTime())) return 'unknown time'
  const iso = date.toISOString()
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`
}

/** `2026-08-07 14:02:11.482 UTC` — for a single event, where ordering matters. */
export function formatInstantNsPrecise(nanoseconds: number): string {
  const date = new Date(Math.round(nanoseconds / NS_PER_MS))
  if (Number.isNaN(date.getTime())) return 'unknown time'
  return `${date.toISOString().replace('T', ' ').replace('Z', '')} UTC`
}

/** `7 days`, `6 hours`, `90 seconds` — the bucket width a series was built at. */
export function formatDuration(seconds: number): string {
  const plural = (value: number, noun: string) => `${value} ${noun}${value === 1 ? '' : 's'}`
  if (seconds % 86_400 === 0 && seconds >= 86_400) return plural(seconds / 86_400, 'day')
  if (seconds % 3_600 === 0 && seconds >= 3_600) return plural(seconds / 3_600, 'hour')
  if (seconds % 60 === 0 && seconds >= 60) return plural(seconds / 60, 'minute')
  return plural(seconds, 'second')
}

/** `2026-08-01 00:00 UTC → 2026-08-08 00:00 UTC`, for stating what was read. */
export function formatWindow(fromNs: number, toNs: number): string {
  return `${formatInstantNs(fromNs)} → ${formatInstantNs(toNs)}`
}

/**
 * A bar width as a percentage of the largest value in its column.
 *
 * `0` stays `0`: a minimum-width bar for a zero would draw something where
 * nothing happened. A non-zero value is floored at 1% so a genuinely small
 * count is visible rather than invisible — the opposite error, and the one that
 * matters less, because the number is rendered beside it either way.
 */
export function barPercent(value: number, max: number): number {
  if (value <= 0 || max <= 0) return 0
  return Math.max(1, Math.round((value / max) * 100))
}
