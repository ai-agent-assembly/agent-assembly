import { describe, expect, it } from 'vitest'
import { applyOverrideLocal, isOverridableDecision } from '../override'
import { CAPABILITY_MATRIX_FIXTURE } from '../fixtures'

describe('isOverridableDecision', () => {
  it('admits what the endpoint accepts and refuses the rest', () => {
    // The three the projection can produce, so the three an override may record.
    expect(['allow', 'deny', 'na'].every(isOverridableDecision)).toBe(true)
    // The two `apply_override` answers with a 400, plus a value that is not a
    // decision at all — what a `<select>` yields when asked for a missing option.
    expect(['narrow', 'approval', ''].some(isOverridableDecision)).toBe(false)
  })
})

describe('applyOverrideLocal', () => {
  it('updates only the targeted (agent, resource, verb)', () => {
    const next = applyOverrideLocal(CAPABILITY_MATRIX_FIXTURE, {
      agentIds: ['research-bot-04'],
      resourceId: 'gmail',
      verb: 'write',
      decision: 'deny',
    })
    const target = next.agents.find((a) => a.id === 'research-bot-04')!
    expect(target.caps.gmail.write).toBe('deny')
    // unrelated cells untouched
    expect(target.caps.s3.write).toBe('allow')
    // unrelated agents untouched
    const other = next.agents.find((a) => a.id === 'finance-bot')!
    expect(other.caps.gmail.write).toBe('deny')
  })

  it('leaves an agent untouched when it has no cell for the resource', () => {
    const next = applyOverrideLocal(CAPABILITY_MATRIX_FIXTURE, {
      agentIds: ['research-bot-04'],
      resourceId: 'not-a-resource',
      verb: 'write',
      decision: 'deny',
    })
    expect(next.agents).toEqual(CAPABILITY_MATRIX_FIXTURE.agents)
  })
})
