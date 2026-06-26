import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { api } from './client'

// openapi-fetch resolves `globalThis.fetch` at request time, so stubbing it
// here lets us inspect the Request the auth middleware actually produced.
const fetchMock = vi.fn(
  async () =>
    new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } }),
)

function lastRequest(): Request {
  // openapi-fetch invokes `fetch(request)` with a single Request argument.
  return (fetchMock.mock.calls[0] as unknown as [Request])[0]
}

describe('api client auth middleware', () => {
  beforeEach(() => {
    localStorage.clear()
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('injects the stored JWT as a Bearer token', async () => {
    localStorage.setItem('aa_token', 'jwt-abc')
    // Cast: the concrete path is irrelevant — we only assert on the headers
    // the middleware attaches before the request leaves the client.
    await api.GET('http://localhost/api/v1/health' as never, { fetch: fetchMock } as never)
    expect(lastRequest().headers.get('Authorization')).toBe('Bearer jwt-abc')
  })

  it('omits the Authorization header when no token is stored', async () => {
    await api.GET('http://localhost/api/v1/health' as never, { fetch: fetchMock } as never)
    expect(lastRequest().headers.get('Authorization')).toBeNull()
  })
})
