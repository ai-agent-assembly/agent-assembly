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

  it('does not treat a healthy result’s error: null as a failure', () => {
    const value = scrubbed24hFromQuery({ isPending: false, error: null, data: [row('a1', 5)] })
    expect(isKnown(value)).toBe(true)
    if (isKnown(value)) expect(value.value).toBe(5)
  })
})
