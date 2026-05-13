import { describe, expect, it } from 'vitest'
import { createMockCapabilityClient } from '../../../api/capability'
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
})

describe('createMockCapabilityClient', () => {
  it('returns updated rows on success and persists state across reads', async () => {
    const client = createMockCapabilityClient({ latencyMs: 0 })
    await client.applyOverride({
      agentIds: ['research-bot-04'],
      resourceId: 'gmail',
      verb: 'write',
      decision: 'deny',
    })
    const after = await client.getMatrix()
    const target = after.agents.find((a) => a.id === 'research-bot-04')!
    expect(target.caps.gmail.write).toBe('deny')
  })

  it('rejects when failOverride is enabled (drives the rollback path)', async () => {
    const client = createMockCapabilityClient({ latencyMs: 0, failOverride: true })
    await expect(
      client.applyOverride({
        agentIds: ['research-bot-04'],
        resourceId: 'gmail',
        verb: 'write',
        decision: 'deny',
      }),
    ).rejects.toThrow(/rejected/)
  })
})
