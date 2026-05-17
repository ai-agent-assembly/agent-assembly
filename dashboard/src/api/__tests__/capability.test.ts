import { afterEach, describe, expect, it, vi } from 'vitest'
import { createApiCapabilityClient } from '../capability'
import { api } from '../client'
import type { CapabilityMatrix, OverrideResponse } from '../../features/capability/types'

afterEach(() => {
  vi.restoreAllMocks()
})

function stubMatrix(): CapabilityMatrix {
  return {
    resources: [{ id: 'pg', name: 'Postgres', group: 'data', paths: ['pg.public.*'] }],
    agents: [
      {
        id: 'support-triage',
        name: 'support-triage',
        framework: 'CrewAI',
        owner: 'cx-tools',
        trust: 78,
        mode: 'enforce',
        status: 'active',
        lastSeen: '12s ago',
        caps: {
          pg: { read: 'allow', write: 'approval', delete: 'deny', exec: 'na' },
        },
      },
    ],
    policies: [],
    sampleCalls: [],
  }
}

describe('createApiCapabilityClient', () => {
  it('getMatrix returns the response body cast to CapabilityMatrix', async () => {
    const stub = stubMatrix()
    const getSpy = vi
      .spyOn(api, 'GET')
      // openapi-fetch's GET signature is complex; the runtime contract is `{ data, error }`,
      // and the test only depends on that runtime shape — so we narrow the cast at the
      // call site rather than reconstructing the full overload type here.
      // openapi-fetch's per-path generic return types are awkward to satisfy
      // from a Vitest spy; the runtime contract is `{ data, error }` and that
      // is what the factory consumes, so the mock-side narrow uses `unknown`.
      .mockResolvedValue({ data: stub, error: undefined } as unknown as never)

    const client = createApiCapabilityClient()
    const matrix = await client.getMatrix()

    expect(getSpy).toHaveBeenCalledWith('/api/v1/capability/matrix')
    expect(matrix.agents[0].caps.pg.write).toBe('approval')
    expect(matrix.resources[0].id).toBe('pg')
  })

  it('applyOverride forwards camelCase body and returns updated rows', async () => {
    const stubUpdated: OverrideResponse = { updated: stubMatrix().agents }
    const postSpy = vi
      .spyOn(api, 'POST')
      .mockResolvedValue({ data: stubUpdated, error: undefined } as unknown as never)

    const client = createApiCapabilityClient()
    const res = await client.applyOverride({
      agentIds: ['support-triage'],
      resourceId: 'pg',
      verb: 'write',
      decision: 'deny',
    })

    expect(postSpy).toHaveBeenCalledWith('/api/v1/capability/override', {
      body: {
        agentIds: ['support-triage'],
        resourceId: 'pg',
        verb: 'write',
        decision: 'deny',
      },
    })
    expect(res.updated).toHaveLength(1)
    expect(res.updated[0].id).toBe('support-triage')
  })

  it('applyOverride throws when the gateway returns an error response', async () => {
    vi.spyOn(api, 'POST').mockResolvedValue({
      data: undefined,
      error: { status: 403, detail: 'policy mutation denied' },
    } as unknown as never)

    const client = createApiCapabilityClient()
    await expect(
      client.applyOverride({
        agentIds: ['support-triage'],
        resourceId: 'pg',
        verb: 'write',
        decision: 'deny',
      }),
    ).rejects.toThrow(/capability override rejected by gateway/)
  })

  it('getMatrix throws when the gateway returns an error response', async () => {
    vi.spyOn(api, 'GET').mockResolvedValue({
      data: undefined,
      error: { status: 500, detail: 'internal error' },
    } as unknown as never)

    const client = createApiCapabilityClient()
    await expect(client.getMatrix()).rejects.toThrow(/capability matrix fetch failed/)
  })
})
