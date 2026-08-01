/**
 * Branch coverage for the one fetched figure on the Scrub surface.
 *
 * Every outcome of the request is asserted separately, because the failure this
 * lane exists to prevent is precisely a collapse of those branches into a single
 * comfortable number.
 */
import { describe, it, expect } from 'vitest'
import { scrubbed24hFromQuery, type AgentEnforcementCounts } from '../api'
import { isKnown } from '../../../lib/truthfulness'

const row = (agent_id: string, scrubbed: number, blocked = 0): AgentEnforcementCounts => ({
  agent_id,
  blocked,
  scrubbed,
})

describe('scrubbed24hFromQuery', () => {
  it('sums scrubbed across agents when the API answers', () => {
    const value = scrubbed24hFromQuery({
      data: [row('a1', 3), row('a2', 4)],
    })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(7)
  })

  it('reports a genuine zero when agents were audited and none redacted', () => {
    // A populated response summing to zero IS a real measurement: some agent was
    // audited, and none of its decisions was a redaction.
    const value = scrubbed24hFromQuery({ data: [row('a1', 0, 2)] })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(0)
  })

  it('refuses to read an empty response as zero redactions', () => {
    // The route omits agents with neither a blocked nor a scrubbed decision, so
    // `[]` cannot tell "nothing was redacted" from "nothing is being audited".
    const value = scrubbed24hFromQuery({ data: [] })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toMatch(/cannot be read as zero/)
      // The reason must name the two paths that actually return `200 []` — a
      // swallowed audit-read failure and a caller with no tenant scope. The
      // omission of zero-activity agents is NOT one of them: that omission is
      // what would make `[]` unambiguous, so citing it argues for rendering `0`.
      expect(value.detail).toMatch(/audit-read failure/)
      expect(value.detail).toMatch(/no tenant scope/)
    }
  })

  it('maps a failed request to unavailable, never to a number', () => {
    const value = scrubbed24hFromQuery({ isError: true, error: new Error('HTTP 503') })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unavailable')
      expect(value.detail).toBe('HTTP 503')
    }
  })

  it('maps a request still in flight to unknown, not to a fault', () => {
    const value = scrubbed24hFromQuery({ isPending: true, error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unknown')
  })

  it('maps a 200 with no payload to unknown', () => {
    const value = scrubbed24hFromQuery({ data: null, error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.state).toBe('unknown')
  })

  it('refuses a 200 that is not an array of rows at all', () => {
    // The sibling of the AAASM-5366 catalogue crash: `rows.value.length` on a
    // body that is not an array. The page must say it does not know, not lose
    // itself reading a field off the wrong shape.
    const value = scrubbed24hFromQuery({ data: {}, error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) {
      expect(value.state).toBe('unknown')
      expect(value.detail).toContain('enforcement window')
    }
  })

  it('refuses a row with no scrubbed count rather than summing to NaN', () => {
    // `reduce` over such a row produces `NaN`, which renders beside
    // "redactions / 24h" as a figure nothing measured — the AAASM-5112 defect
    // arriving through a malformed response instead of through a literal.
    const value = scrubbed24hFromQuery({ data: [{ agent_id: 'a1', blocked: 1 }], error: null })
    expect(isKnown(value)).toBe(false)
    if (!isKnown(value)) expect(value.detail).toContain('scrubbed')
  })

  it('does not treat a healthy result’s error: null as a failure', () => {
    const value = scrubbed24hFromQuery({ isPending: false, error: null, data: [row('a1', 5)] })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(5)
  })
})
