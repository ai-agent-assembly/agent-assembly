import { afterEach, describe, expect, it, vi } from 'vitest'
import { analyticsFetch } from './analyticsFetch'

// Regression for AAASM-4131: every analytics hook routes through this helper so
// it inherits VITE_API_BASE_URL + the stored bearer token, matching the rest of
// the app's data paths.

function jsonOk(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
  localStorage.clear()
})

describe('analyticsFetch', () => {
  it('prefixes VITE_API_BASE_URL and attaches the Authorization bearer header', async () => {
    vi.stubEnv('VITE_API_BASE_URL', 'https://api.example.test')
    localStorage.setItem('aa_token', 'tok-abc')
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonOk({ ok: true }))

    await analyticsFetch('/api/v1/analytics/kpis?metric=cost')

    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://api.example.test/api/v1/analytics/kpis?metric=cost')
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok-abc')
  })

  it('omits the Authorization header when no token is stored', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonOk({ ok: true }))

    await analyticsFetch('/api/v1/analytics/kpis')

    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined()
  })

  it('throws on a non-OK response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('', { status: 401 }))

    await expect(analyticsFetch('/api/v1/analytics/kpis')).rejects.toThrow('HTTP 401')
  })
})
