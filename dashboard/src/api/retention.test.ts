import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from './client'
import { createRetentionPolicyClient } from './retention'

interface FetchResult {
  data?: unknown
  error?: unknown
}

const DOC = { hot_days: 30, warm_days: 90, cold: { action: 'archive' } }

let get: Mock
let put: Mock
let post: Mock

beforeEach(() => {
  get = vi.spyOn(api, 'GET') as unknown as Mock
  put = vi.spyOn(api, 'PUT') as unknown as Mock
  post = vi.spyOn(api, 'POST') as unknown as Mock
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('createRetentionPolicyClient.get', () => {
  it('returns the retention policy document on success', async () => {
    get.mockResolvedValue({ data: DOC } satisfies FetchResult)
    const client = createRetentionPolicyClient()
    await expect(client.get()).resolves.toEqual(DOC)
    expect(get).toHaveBeenCalledWith('/api/v1/admin/retention-policy')
  })

  it('throws when the gateway returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'denied' } } satisfies FetchResult)
    await expect(createRetentionPolicyClient().get()).rejects.toThrow(/retention policy GET failed/)
  })

  it('throws when the response carries no data', async () => {
    get.mockResolvedValue({ data: undefined } satisfies FetchResult)
    await expect(createRetentionPolicyClient().get()).rejects.toThrow(/no data/)
  })
})

describe('createRetentionPolicyClient.update', () => {
  it('PUTs the request body and returns the updated document', async () => {
    put.mockResolvedValue({ data: DOC } satisfies FetchResult)
    const req = { hot_days: 15 } as never
    await expect(createRetentionPolicyClient().update(req)).resolves.toEqual(DOC)
    expect(put).toHaveBeenCalledWith('/api/v1/admin/retention-policy', { body: req })
  })

  it('throws on a failed update', async () => {
    put.mockResolvedValue({ error: { message: 'boom' } } satisfies FetchResult)
    await expect(createRetentionPolicyClient().update({} as never)).rejects.toThrow(
      /retention policy PUT failed/,
    )
  })
})

describe('createRetentionPolicyClient.run', () => {
  it('POSTs the dry-run flag and returns run stats', async () => {
    const stats = { scanned: 100, archived: 3 }
    post.mockResolvedValue({ data: stats } satisfies FetchResult)
    await expect(createRetentionPolicyClient().run(true)).resolves.toEqual(stats)
    expect(post).toHaveBeenCalledWith('/api/v1/admin/retention-policy/run', {
      body: { dry_run: true },
    })
  })

  it('throws on a failed run', async () => {
    post.mockResolvedValue({ data: undefined } satisfies FetchResult)
    await expect(createRetentionPolicyClient().run(false)).rejects.toThrow(
      /retention policy run failed/,
    )
  })
})
