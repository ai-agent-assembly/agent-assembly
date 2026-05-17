import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'
import {
  ACCESS_LOG_EVENT_TYPES,
  _accessLogInternal,
  useAccessLogQuery,
  type AccessLogEvent,
  type AccessLogEventType,
} from './accessLog'

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return function Wrapper({ children }: { children: React.ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>
  }
}

describe('accessLog seed + filter (AAASM-1398)', () => {
  beforeEach(() => {
    _accessLogInternal.reset()
  })

  it('exports the full event-type vocabulary', () => {
    // The filter bar in C2 reads ACCESS_LOG_EVENT_TYPES to populate its select.
    expect(ACCESS_LOG_EVENT_TYPES).toEqual([
      'login',
      'logout',
      'policy_change',
      'key_rotate',
      'member_invite',
      'permission_grant',
    ])
  })

  it('seeds 10 events covering every event type at least once', () => {
    const seen = new Set<AccessLogEventType>(
      _accessLogInternal.snapshot().map((e) => e.event_type),
    )
    expect(_accessLogInternal.snapshot()).toHaveLength(10)
    for (const t of ACCESS_LOG_EVENT_TYPES) {
      expect(seen.has(t)).toBe(true)
    }
  })

  it('useAccessLogQuery({}) returns the full seed, newest-first', async () => {
    const { result } = renderHook(() => useAccessLogQuery({}), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.data).toBeDefined())
    const data = result.current.data as AccessLogEvent[]
    expect(data).toHaveLength(10)
    // Sorted reverse-chron: first event is the most recent.
    for (let i = 1; i < data.length; i++) {
      expect(data[i - 1].timestamp >= data[i].timestamp).toBe(true)
    }
  })

  it('identity filter narrows rows to that identity only', async () => {
    const { result } = renderHook(
      () => useAccessLogQuery({ identity: 'alice@agent-assembly.dev' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.data).toBeDefined())
    const data = result.current.data as AccessLogEvent[]
    expect(data.length).toBeGreaterThan(0)
    for (const e of data) expect(e.identity).toBe('alice@agent-assembly.dev')
  })

  it('eventType filter narrows rows to that type only', async () => {
    const { result } = renderHook(
      () => useAccessLogQuery({ eventType: 'key_rotate' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.data).toBeDefined())
    const data = result.current.data as AccessLogEvent[]
    expect(data.length).toBeGreaterThan(0)
    for (const e of data) expect(e.event_type).toBe('key_rotate')
  })

  it('timeRange 24h excludes events older than 24 hours', async () => {
    const { result } = renderHook(
      () => useAccessLogQuery({ timeRange: { kind: '24h' } }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.data).toBeDefined())
    const data = result.current.data as AccessLogEvent[]
    const cutoff = Date.now() - 24 * 60 * 60 * 1000
    for (const e of data) {
      expect(new Date(e.timestamp).getTime()).toBeGreaterThanOrEqual(cutoff)
    }
    // The seed includes events at -1h, -3h, -6h, -20h (in-range) and
    // -48h+ (out-of-range), so a 24-hour cutoff must drop at least one row.
    expect(data.length).toBeLessThan(10)
  })

  it('setFetchOverride swaps the source (proves the eventual fetch swap is one-function)', async () => {
    _accessLogInternal.setFetchOverride(() =>
      Promise.resolve([
        {
          id: 'override-1',
          timestamp: new Date().toISOString(),
          identity: 'overridden',
          event_type: 'login',
          target: 'gateway',
          result: 'success',
          source_ip: '1.2.3.4',
        },
      ]),
    )
    const { result } = renderHook(() => useAccessLogQuery({}), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(result.current.data).toHaveLength(1)
    expect(result.current.data?.[0].id).toBe('override-1')
  })
})
