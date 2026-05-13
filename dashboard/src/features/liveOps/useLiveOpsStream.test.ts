import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useLiveOpsStream } from './useLiveOpsStream'

class MockWebSocket {
  static instances: MockWebSocket[] = []
  static OPEN = 1
  static CLOSED = 3

  static reset() {
    MockWebSocket.instances = []
  }

  readyState = 0
  url: string
  onopen: ((ev?: Event) => void) | null = null
  onmessage: ((ev: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((ev?: Event) => void) | null = null

  constructor(url: string) {
    this.url = url
    MockWebSocket.instances.push(this)
  }

  // ── Test helpers ────────────────────────────────────────
  open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }
  emit(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }
  serverClose() {
    if (this.readyState === MockWebSocket.CLOSED) return
    this.readyState = MockWebSocket.CLOSED
    this.onclose?.()
  }

  // ── WebSocket API ──────────────────────────────────────
  close() {
    this.serverClose()
  }
  send() {
    /* noop */
  }
}

const VIOLATION_EVENT = {
  id: 1,
  agent_id: 'support-agent',
  event_type: 'violation',
  timestamp: '2026-05-13T14:23:01Z',
  payload: { kind: 'audit', received_at_ms: 0, sequence_number: 1, source: 'sdk' },
}

const opts = {
  webSocketCtor: MockWebSocket as unknown as typeof WebSocket,
  initialBackoffMs: 100,
  maxBackoffMs: 1000,
  maxReconnectAttempts: 3,
  maxOps: 50,
}

describe('useLiveOpsStream', () => {
  beforeEach(() => {
    MockWebSocket.reset()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('connects on mount and exposes connecting status', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(result.current.status).toBe('connecting')
  })

  it('transitions to connected on socket open', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
    })
    expect(result.current.status).toBe('connected')
  })

  it('appends violation events to the ops ring (most-recent-first)', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit(VIOLATION_EVENT)
      MockWebSocket.instances[0].emit({ ...VIOLATION_EVENT, id: 2 })
    })
    expect(result.current.ops.map((o) => o.id)).toEqual(['2', '1'])
    expect(result.current.ops[1]).toMatchObject({
      id: '1',
      agent: 'support-agent',
      startedAt: '2026-05-13T14:23:01Z',
      status: 'running',
    })
  })

  it('ignores non-violation event types', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({ ...VIOLATION_EVENT, event_type: 'approval' })
    })
    expect(result.current.ops).toHaveLength(0)
  })

  it('drops malformed frames without throwing', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].onmessage?.({ data: 'not json' })
    })
    expect(result.current.ops).toHaveLength(0)
  })

  it('caps the ring at maxOps', () => {
    const { result } = renderHook(() => useLiveOpsStream({ ...opts, maxOps: 3 }))
    act(() => {
      MockWebSocket.instances[0].open()
      for (let i = 1; i <= 5; i++) {
        MockWebSocket.instances[0].emit({ ...VIOLATION_EVENT, id: i })
      }
    })
    expect(result.current.ops.map((o) => o.id)).toEqual(['5', '4', '3'])
  })

  it('reconnects with exponential backoff after a close', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
    })
    expect(result.current.status).toBe('connected')

    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    expect(result.current.status).toBe('reconnecting')
    expect(MockWebSocket.instances).toHaveLength(1)

    // First reconnect: 100 ms (initialBackoffMs * 2^0)
    act(() => {
      vi.advanceTimersByTime(99)
    })
    expect(MockWebSocket.instances).toHaveLength(1)
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(MockWebSocket.instances).toHaveLength(2)

    // Second close, second reconnect: 200 ms
    act(() => {
      MockWebSocket.instances[1].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(199)
    })
    expect(MockWebSocket.instances).toHaveLength(2)
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(MockWebSocket.instances).toHaveLength(3)
  })

  it('transitions to error after maxReconnectAttempts', () => {
    const { result } = renderHook(() =>
      useLiveOpsStream({ ...opts, maxReconnectAttempts: 2 }),
    )
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    act(() => {
      MockWebSocket.instances[1].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(200)
    })
    act(() => {
      MockWebSocket.instances[2].serverClose()
    })
    expect(result.current.status).toBe('error')
  })

  it('manual reconnect() restarts the connection from error', () => {
    const { result } = renderHook(() =>
      useLiveOpsStream({ ...opts, maxReconnectAttempts: 1 }),
    )
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    act(() => {
      MockWebSocket.instances[1].serverClose()
    })
    expect(result.current.status).toBe('error')

    act(() => {
      result.current.reconnect()
    })
    expect(MockWebSocket.instances.length).toBeGreaterThan(2)
    expect(result.current.status).not.toBe('error')
  })

  it('closes the socket on unmount', () => {
    const { unmount } = renderHook(() => useLiveOpsStream(opts))
    const ws = MockWebSocket.instances[0]
    act(() => {
      ws.open()
    })
    unmount()
    expect(ws.readyState).toBe(MockWebSocket.CLOSED)
  })
})
