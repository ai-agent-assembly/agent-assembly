import { describe, expect, it } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { computeSpanDepths } from './nesting'
import type { TraceEvent, TraceSeverity } from './types'

const NO_FIELD = 'TraceSpan has no such field'

/** A span in the shape the real endpoint produces. */
function span(id: string, parentSpanId: string | null = null): TraceEvent {
  return {
    id,
    timestamp: '2026-04-23T14:23:01Z',
    type: 'ToolCallIntercepted',
    agent: 'support-agent',
    parentSpanId,
    durationMs: known(12),
    decision: absent<string>('not-evaluated', 'no decision recorded'),
    payload: absent<unknown>('not-supported', NO_FIELD),
    payloadPreview: absent<string>('not-supported', NO_FIELD),
    severity: absent<TraceSeverity>('not-supported', NO_FIELD),
    redactedFields: absent<readonly string[]>('not-supported', NO_FIELD),
    violationReason: absent<string>('not-supported', NO_FIELD),
  }
}

/**
 * Depths keyed by span id, so assertions read as a shape. The function itself
 * returns positionally, which is what the renderer consumes; zipping here keeps
 * the tests legible without hiding that alignment.
 */
function depths(events: readonly TraceEvent[]): Record<string, number> {
  const result = computeSpanDepths(events)
  expect(result).toHaveLength(events.length)
  return Object.fromEntries(events.map((e, i) => [e.id, result[i]]))
}

describe('computeSpanDepths', () => {
  it('puts a span with no parent at the root', () => {
    expect(depths([span('a'), span('b')])).toEqual({ a: 0, b: 0 })
  })

  it('indents a child one level under its parent', () => {
    expect(depths([span('a'), span('b', 'a')])).toEqual({ a: 0, b: 1 })
  })

  it('counts every resolvable hop in a deep chain', () => {
    const events = [span('a'), span('b', 'a'), span('c', 'b'), span('d', 'c')]
    expect(depths(events)).toEqual({ a: 0, b: 1, c: 2, d: 3 })
  })

  it('does not depend on the order spans arrive in', () => {
    // The gateway sorts by start_time, which is not the same as parents-first.
    const events = [span('d', 'c'), span('b', 'a'), span('a'), span('c', 'b')]
    expect(depths(events)).toEqual({ a: 0, b: 1, c: 2, d: 3 })
  })

  it('keeps the hops that resolve when the chain is truncated', () => {
    // `build_trace_from_audit` scans a bounded window, so a parent can be
    // genuinely missing from the response. `b` is a root as far as this
    // response can tell; `c` is still demonstrably `b`'s child.
    const events = [span('b', 'off-window'), span('c', 'b')]
    expect(depths(events)).toEqual({ b: 0, c: 1 })
  })

  it('roots a span whose parent is not in the response', () => {
    expect(depths([span('a', 'nowhere')])).toEqual({ a: 0 })
  })

  it('roots a two-span cycle instead of recursing', () => {
    // A → B → A. Neither span has a well-founded ancestry, so neither claims a
    // depth. The assertion that matters as much as the value is that this
    // returns at all.
    expect(depths([span('a', 'b'), span('b', 'a')])).toEqual({ a: 0, b: 0 })
  })

  it('roots a span parented to itself', () => {
    expect(depths([span('a', 'a')])).toEqual({ a: 0 })
  })

  it('roots a three-span cycle', () => {
    const events = [span('a', 'c'), span('b', 'a'), span('c', 'b')]
    expect(depths(events)).toEqual({ a: 0, b: 0, c: 0 })
  })

  it('roots only the cyclic spans, leaving a clean sibling chain intact', () => {
    const events = [span('x'), span('y', 'x'), span('a', 'b'), span('b', 'a')]
    expect(depths(events)).toEqual({ x: 0, y: 1, a: 0, b: 0 })
  })

  it('terminates on a span that hangs off a cycle', () => {
    // `d`'s ancestry runs into the A↔B loop. It must return, and it cannot
    // claim a depth derived from a loop.
    const events = [span('a', 'b'), span('b', 'a'), span('d', 'a')]
    expect(depths(events)).toEqual({ a: 0, b: 0, d: 0 })
  })

  it('returns an empty map for an empty trace', () => {
    expect(depths([])).toEqual({})
  })
})
