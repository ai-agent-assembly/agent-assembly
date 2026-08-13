import { describe, expect, it } from 'vitest'
import { decodeEnforcementLookup } from './schema'
import type { AgentEnforcementLookup } from './fleetTypes'

/**
 * Unit coverage for `decodeEnforcementLookup`'s own branches (AAASM-5380 S8).
 *
 * The Overview page test proves the KPIs degrade to absence when this rejects;
 * this proves the decoder itself — the conforming path and every rejection path
 * — so a malformed lookup can never reach `sumEnforcement` as a fabricated
 * `known(NaN)` blocked count. Unlike its sibling wire-array decoders, this one
 * validates the `Map` `useAgentEnforcementQuery` already built, because that is
 * what the Overview fold receives.
 */
describe('decodeEnforcementLookup', () => {
  it('conforms a well-formed lookup and passes the Map through', () => {
    const lookup: AgentEnforcementLookup = new Map([
      ['agent-1', { blocked: 4, scrubbed: 12 }],
      ['agent-2', { blocked: 0, scrubbed: 0 }],
    ])
    const result = decodeEnforcementLookup(lookup)
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.value).toBe(lookup)
      expect(result.value.get('agent-1')).toEqual({ blocked: 4, scrubbed: 12 })
    }
  })

  it('conforms an empty lookup — no agent reported, which is a readable measurement', () => {
    const result = decodeEnforcementLookup(new Map())
    expect(result.ok).toBe(true)
  })

  it('rejects a value that is not a Map at all', () => {
    // A raw wire array — the shape the query builds *from*, not the lookup it
    // builds — must not be mistaken for a readable lookup.
    const result = decodeEnforcementLookup([{ agent_id: 'a', blocked: 1, scrubbed: 2 }])
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toMatch(/not a lookup/i)
  })

  it('rejects a plain object standing in for the lookup', () => {
    const result = decodeEnforcementLookup({ 'agent-1': { blocked: 1, scrubbed: 2 } })
    expect(result.ok).toBe(false)
  })

  it('rejects null and undefined', () => {
    expect(decodeEnforcementLookup(null).ok).toBe(false)
    expect(decodeEnforcementLookup(undefined).ok).toBe(false)
  })

  it('rejects a Map keyed by something other than a string', () => {
    const result = decodeEnforcementLookup(new Map([[42, { blocked: 1, scrubbed: 2 }]]))
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toMatch(/agent id/i)
  })

  it('rejects a row whose blocked count is not a number, naming the agent', () => {
    const result = decodeEnforcementLookup(new Map([['agent-9', { blocked: 'lots', scrubbed: 2 }]]))
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toContain('agent-9')
      expect(result.reason).toMatch(/blocked/i)
    }
  })

  it('rejects a row whose scrubbed count is not a number', () => {
    const result = decodeEnforcementLookup(new Map([['agent-1', { blocked: 1, scrubbed: null }]]))
    expect(result.ok).toBe(false)
  })

  it('rejects a row missing a count entirely', () => {
    const result = decodeEnforcementLookup(new Map([['agent-1', { blocked: 1 }]]))
    expect(result.ok).toBe(false)
  })

  it('rejects a row that is not an object', () => {
    const result = decodeEnforcementLookup(new Map([['agent-1', 3]]))
    expect(result.ok).toBe(false)
  })
})
