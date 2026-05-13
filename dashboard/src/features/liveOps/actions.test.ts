import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { pauseOp, resumeOp, terminateOp } from './actions'

const fetchSpy = vi.fn()
const originalFetch = globalThis.fetch
const originalLocalStorage = globalThis.localStorage

function setToken(token: string | null) {
  const store: Record<string, string> = {}
  if (token !== null) store.aa_token = token
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (k: string) => store[k] ?? null,
      setItem: (k: string, v: string) => {
        store[k] = v
      },
      removeItem: (k: string) => {
        delete store[k]
      },
      clear: () => {
        for (const k of Object.keys(store)) delete store[k]
      },
      length: 0,
      key: () => null,
    },
  })
}

function okResponse(): Response {
  return new Response(null, { status: 204 })
}

function errResponse(status: number, body = ''): Response {
  return new Response(body, { status })
}

describe('liveOps/actions', () => {
  beforeEach(() => {
    fetchSpy.mockReset()
    globalThis.fetch = fetchSpy as unknown as typeof fetch
    setToken(null)
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
    if (originalLocalStorage) {
      Object.defineProperty(globalThis, 'localStorage', {
        configurable: true,
        value: originalLocalStorage,
      })
    }
  })

  it.each([
    ['pauseOp', pauseOp, 'pause'],
    ['resumeOp', resumeOp, 'resume'],
    ['terminateOp', terminateOp, 'terminate'],
  ] as const)(
    '%s POSTs to /api/v1/ops/:id/%s',
    async (_name, fn, action) => {
      fetchSpy.mockResolvedValue(okResponse())
      await fn('op-123')
      expect(fetchSpy).toHaveBeenCalledTimes(1)
      const [url, init] = fetchSpy.mock.calls[0]
      expect(url).toBe(`/api/v1/ops/op-123/${action}`)
      expect(init?.method).toBe('POST')
    },
  )

  it('url-encodes the op id', async () => {
    fetchSpy.mockResolvedValue(okResponse())
    await pauseOp('op/with weird:chars')
    expect(fetchSpy.mock.calls[0][0]).toBe(
      '/api/v1/ops/op%2Fwith%20weird%3Achars/pause',
    )
  })

  it('attaches Bearer token from localStorage', async () => {
    setToken('jwt-abc')
    fetchSpy.mockResolvedValue(okResponse())
    await resumeOp('op-1')
    const headers = fetchSpy.mock.calls[0][1].headers
    expect(headers.Authorization).toBe('Bearer jwt-abc')
  })

  it('omits Authorization when no token is stored', async () => {
    fetchSpy.mockResolvedValue(okResponse())
    await resumeOp('op-1')
    const headers = fetchSpy.mock.calls[0][1].headers
    expect(headers.Authorization).toBeUndefined()
  })

  it('rejects with status code on 5xx', async () => {
    fetchSpy.mockResolvedValue(errResponse(500))
    await expect(pauseOp('op-1')).rejects.toThrow(/500/)
  })

  it('includes server body text in 4xx errors', async () => {
    fetchSpy.mockResolvedValue(errResponse(409, 'op already terminated'))
    await expect(terminateOp('op-1')).rejects.toThrow(/op already terminated/)
  })
})
