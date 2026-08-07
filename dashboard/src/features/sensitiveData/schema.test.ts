/**
 * The sensitive-data decoders (AAASM-5360).
 *
 * ## What these prove, and what they deliberately do not
 *
 * They prove the decoders reject the bodies that would otherwise be read as if
 * they conformed — the AAASM-5366 failure. They do **not** prove the API sends
 * conforming bodies; that is AAASM-5359's contract test, and asserting it from
 * here would only assert the fixture.
 *
 * ## Falsification record
 *
 * Each assertion below was run against a deliberately broken build before being
 * trusted:
 *
 *  - Replacing `countersSchema` with `z.looseObject({})` — the "accept whatever
 *    arrived" shortcut — makes exactly two of the fifteen fail:
 *    `rejects a counters block missing the unmeasured-transmission field` and
 *    `names the offending bucket when one point is malformed` (2 failed, 13
 *    passed). Note which one did *not* fail: `rejects a summary whose counters
 *    are absent entirely` stayed green, because the outer `summarySchema` still
 *    requires the key. So that test is not evidence about the counters shape —
 *    only the first two are, and the record says so rather than claiming three.
 *  - Changing `prevention_rate` to a bare `z.number()` (dropping `.nullable()`)
 *    makes `accepts null rates, because null is how the API says "undefined
 *    here"` fail, and nothing else (1 failed, 14 passed). That mutation would
 *    turn every absent rate into an unreadable body — a different untruth from
 *    the one this Epic is about, but an untruth.
 */
import { describe, it, expect } from 'vitest'
import {
  decodeBreakdown,
  decodeEventDetail,
  decodeEvents,
  decodeSummary,
  decodeTimeseries,
  decodeTopOffenders,
} from './schema'
import {
  EVENT,
  FINDINGS,
  SCOPE,
  UNMEASURED_COUNTERS,
  WORKED_EXAMPLE_COUNTERS,
  ZERO_COUNTERS,
  ratesFor,
} from './__tests__/fixtures'

describe('decodeSummary', () => {
  it('accepts a well-formed summary and returns its counters unchanged', () => {
    const result = decodeSummary({
      scope: SCOPE,
      counters: WORKED_EXAMPLE_COUNTERS,
      rates: ratesFor(WORKED_EXAMPLE_COUNTERS),
      by_category: [{ value: 'email_address', finding_count: 2, event_count: 1 }],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    // Both halves of the §8 worked example survive decoding as distinct numbers.
    expect(result.value.counters.event_count).toBe(1)
    expect(result.value.counters.finding_count).toBe(3)
  })

  it('accepts null rates, because null is how the API says "undefined here"', () => {
    const result = decodeSummary({
      scope: SCOPE,
      counters: ZERO_COUNTERS,
      rates: ratesFor(ZERO_COUNTERS),
      by_category: [],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.rates.prevention_rate).toBeNull()
    expect(result.value.rates.unmeasured_transmission_rate).toBeNull()
  })

  it('rejects a counters block missing the unmeasured-transmission field', () => {
    // The field that says whether `prevention_rate` measured anything. A body
    // without it cannot be rendered as a prevention figure at all, so it is an
    // unreadable body rather than a body with one missing extra.
    const partial = Object.fromEntries(
      Object.entries(UNMEASURED_COUNTERS).filter(
        ([key]) => key !== 'unmeasured_transmission_event_count',
      ),
    )
    const result = decodeSummary({
      scope: SCOPE,
      counters: partial,
      rates: ratesFor(UNMEASURED_COUNTERS),
      by_category: [],
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toContain('unmeasured_transmission_event_count')
  })

  it('rejects a summary whose counters are absent entirely', () => {
    const result = decodeSummary({ scope: SCOPE, rates: {}, by_category: [] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toContain('counters')
  })

  it('rejects an empty object rather than reading zero counters off it', () => {
    const result = decodeSummary({})
    expect(result.ok).toBe(false)
  })

  it('strips a field the schema does not name, so a raw value cannot reach a component', () => {
    // ADR 0032 §9 keeps offsets, lengths and raw values off the wire, and the
    // API returns none. This asserts the second line of defence: even if one
    // arrived, Zod drops it before any component can read it.
    const result = decodeEventDetail({
      event: { ...EVENT, matched_offset: 42, raw_value: 'AKIAIOSFODNN7EXAMPLE' },
      findings: FINDINGS,
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(JSON.stringify(result.value)).not.toContain('matched_offset')
    expect(JSON.stringify(result.value)).not.toContain('AKIAIOSFODNN7EXAMPLE')
  })
})

describe('decodeTimeseries', () => {
  it('accepts zeroed buckets, which is how the API renders a gap', () => {
    const result = decodeTimeseries({
      scope: SCOPE,
      bucket_seconds: 86_400,
      points: [
        { start_ns: SCOPE.from_ns, end_ns: SCOPE.to_ns, counters: ZERO_COUNTERS },
        { start_ns: SCOPE.to_ns, end_ns: SCOPE.to_ns, counters: UNMEASURED_COUNTERS },
      ],
    })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.points).toHaveLength(2)
  })

  it('names the offending bucket when one point is malformed', () => {
    const result = decodeTimeseries({
      scope: SCOPE,
      bucket_seconds: 86_400,
      points: [
        { start_ns: 1, end_ns: 2, counters: ZERO_COUNTERS },
        { start_ns: 2, end_ns: 3, counters: { event_count: 'many' } },
      ],
    })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toContain('points.1.counters')
  })
})

describe('decodeBreakdown', () => {
  it('accepts each of the six ADR 0032 §9 dimensions', () => {
    for (const dimension of [
      'category',
      'severity',
      'confidence_band',
      'outcome',
      'detection_method',
      'provider_id',
    ]) {
      const result = decodeBreakdown({ scope: SCOPE, group_by: dimension, buckets: [] })
      expect(result.ok, `${dimension} should decode`).toBe(true)
    }
  })

  it('rejects a grouping the ADR forbids, rather than rendering an unbounded series', () => {
    // `agent_id` is an event-store dimension, not a metric label. The API refuses
    // it with a 400; if one ever came back in a body, this is where it stops.
    const result = decodeBreakdown({ scope: SCOPE, group_by: 'agent_id', buckets: [] })
    expect(result.ok).toBe(false)
  })
})

describe('decodeEvents and decodeEventDetail', () => {
  it('keeps `total` and the page length as separate numbers', () => {
    const result = decodeEvents({ scope: SCOPE, total: 940, events: [EVENT] })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.total).toBe(940)
    expect(result.value.events).toHaveLength(1)
  })

  it('rejects an events body with no total, which would leave the page unable to say what it is showing', () => {
    const result = decodeEvents({ scope: SCOPE, events: [] })
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toContain('total')
  })

  it('decodes a detail body with its findings in ordinal order', () => {
    const result = decodeEventDetail({ event: EVENT, findings: FINDINGS })
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.value.findings.map((f) => f.finding_ordinal)).toEqual([0, 1, 2])
  })
})

describe('decodeTopOffenders', () => {
  it('accepts the four trend directions the API can send', () => {
    for (const trend of ['up', 'down', 'flat', 'new']) {
      const result = decodeTopOffenders({
        scope: SCOPE,
        comparison_from_ns: 1,
        comparison_to_ns: 2,
        dimension: 'agent',
        entries: [
          {
            key: 'research-bot-04',
            counters: UNMEASURED_COUNTERS,
            previous: ZERO_COUNTERS,
            finding_count_delta: 37,
            trend,
          },
        ],
      })
      expect(result.ok, `${trend} should decode`).toBe(true)
    }
  })

  it('rejects a trend value it does not know rather than rendering it as flat', () => {
    const result = decodeTopOffenders({
      scope: SCOPE,
      comparison_from_ns: 1,
      comparison_to_ns: 2,
      dimension: 'agent',
      entries: [
        {
          key: 'x',
          counters: ZERO_COUNTERS,
          previous: ZERO_COUNTERS,
          finding_count_delta: 0,
          trend: 'sideways',
        },
      ],
    })
    expect(result.ok).toBe(false)
  })
})
