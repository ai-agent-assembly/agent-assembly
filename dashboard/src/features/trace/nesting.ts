/**
 * Span nesting depth (AAASM-5109).
 *
 * `TraceSpan.parent_span_id` links a span to the action that invoked it, so the
 * timeline indents a child under its parent rather than rendering one flat run
 * of rows. Depth is *derived* by walking the parent chain — the wire carries a
 * parent id, never a depth — which means the walk has to survive two things the
 * response can contain and the schema does not forbid:
 *
 *  - **A parent id naming a span that is not in this response.** The
 *    audit-reconstruction path (`aa-api/src/routes/traces.rs`,
 *    `build_trace_from_audit`) scans a fixed 10 000-entry window and keeps only
 *    the entries whose session matches, so a chain can legitimately be
 *    truncated part-way. The hops that *did* resolve are real, so they are
 *    kept; the walk simply stops where the evidence stops.
 *
 *  - **A cycle** (`A → B → A`, or a span parented to itself). No producer
 *    should emit one and nothing on the wire validates against it. A cyclic
 *    ancestry is not a deep nesting, it is an unusable one, so the span is
 *    rendered at the root rather than at a depth invented to break the loop.
 *
 * Neither case throws and neither can spin: every walk is bounded by a `seen`
 * set that can only grow to the number of spans in the response.
 */

import type { TraceEvent } from './types'

/**
 * How many levels of indentation are actually drawn.
 *
 * Depth itself is reported honestly in `data-depth` however deep the chain
 * goes; this only bounds the horizontal offset so a pathologically deep trace
 * cannot push a row's text off the panel. Clamping the *drawing* is a layout
 * decision; clamping the *derived depth* would be a claim about the data.
 */
export const MAX_INDENT_DEPTH = 6

/**
 * Derive each span's nesting depth, **positionally aligned with `events`**.
 *
 * A span with no parent, a parent outside this response, or a cyclic ancestry
 * is depth 0. Otherwise the depth is the number of parent hops that resolve
 * inside this response.
 *
 * Returned as an array rather than a `Map` keyed by span id so the caller reads
 * `depths[i]` alongside `events[i]` with no lookup that could miss and no
 * `?? 0` fallback standing in for a case that cannot happen. It is also correct
 * when two spans share an id — which nothing on the wire forbids — where a
 * by-id map would silently collapse them onto one entry.
 */
export function computeSpanDepths(events: readonly TraceEvent[]): readonly number[] {
  const byId = new Map<string, TraceEvent>()
  for (const event of events) byId.set(event.id, event)

  return events.map((event) => depthOf(event, byId))
}

/** Walk one span's ancestry, counting the hops that resolve. */
function depthOf(event: TraceEvent, byId: ReadonlyMap<string, TraceEvent>): number {
  const seen = new Set<string>([event.id])
  let depth = 0
  let cursor: TraceEvent = event

  while (cursor.parentSpanId !== null) {
    const parent = byId.get(cursor.parentSpanId)
    // Truncated chain: the parent is not in this response, so nothing further
    // up can be established. The hops already walked stand.
    if (parent === undefined) return depth
    // Cyclic ancestry establishes no depth at all — render at the root.
    if (seen.has(parent.id)) return 0
    seen.add(parent.id)
    depth += 1
    cursor = parent
  }

  return depth
}
