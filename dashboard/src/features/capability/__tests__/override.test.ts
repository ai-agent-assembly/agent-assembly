import { describe, expect, it } from 'vitest'
import { applyOverrideLocal } from '../override'
import { CAPABILITY_MATRIX_FIXTURE } from '../fixtures'

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
