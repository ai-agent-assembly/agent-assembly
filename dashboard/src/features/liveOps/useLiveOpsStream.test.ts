import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MockWebSocket, resetMockWebSockets } from '../../test/mockWebSocket'
import { useLiveOpsStream } from './useLiveOpsStream'

const VIOLATION_EVENT = {
  id: 1,
  agent_id: 'support-agent',
  event_type: 'violation',
  timestamp: '2026-05-13T14:23:01Z',
  payload: {
    kind: 'audit',
    received_at_ms: 0,
    sequence_number: 1,
    source: 'sdk',
    op_type: 'tool_call',
    resource: 'web_search',
    status: 'running',
    latency_ms: 41,
    team: 'support',
  },
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
    resetMockWebSockets()
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

  it('populates every LiveOperation field from the structured payload', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit(VIOLATION_EVENT)
    })
    expect(result.current.ops[0]).toEqual({
      id: '1',
      agent: 'support-agent',
      team: 'support',
      opType: 'tool_call',
      resource: 'web_search',
      status: 'running',
      startedAt: '2026-05-13T14:23:01Z',
      latencyMs: 41,
    })
  })

  it('falls back to safe defaults when the payload is missing op fields', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        payload: { kind: 'audit', received_at_ms: 0, sequence_number: 1, source: 'sdk' },
      })
    })
    expect(result.current.ops[0]).toMatchObject({
      opType: 'unknown',
      resource: '',
      status: 'running',
      latencyMs: 0,
      team: undefined,
    })
  })

  it('coerces an unknown status string to running', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        payload: { ...VIOLATION_EVENT.payload, status: 'something-else' },
      })
    })
    expect(result.current.ops[0]?.status).toBe('running')
  })

  it('maps blocked / pending status values through unchanged', () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        id: 10,
        payload: { ...VIOLATION_EVENT.payload, status: 'blocked' },
      })
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        id: 11,
        payload: { ...VIOLATION_EVENT.payload, status: 'pending' },
      })
    })
    expect(result.current.ops.map((o) => o.status)).toEqual(['pending', 'blocked'])
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

  it('appends ?token=… to the WS URL when aa_token is present in localStorage', () => {
    const originalGet = Storage.prototype.getItem
    Storage.prototype.getItem = function (key: string) {
      return key === 'aa_token' ? 'jwt-abc' : originalGet.call(this, key)
    }
    try {
      renderHook(() => useLiveOpsStream(opts))
      expect(MockWebSocket.instances[0].url).toContain('types=violation')
      expect(MockWebSocket.instances[0].url).toContain('token=jwt-abc')
    } finally {
      Storage.prototype.getItem = originalGet
    }
  })

  it('caps reconnect backoff at maxBackoffMs', () => {
    renderHook(() =>
      useLiveOpsStream({
        ...opts,
        initialBackoffMs: 100,
        maxBackoffMs: 250,
        maxReconnectAttempts: 5,
      }),
    )
    // 1st backoff: 100 ms (2^0 * 100)
    act(() => {
      MockWebSocket.instances[0].serverClose()
      vi.advanceTimersByTime(100)
    })
    expect(MockWebSocket.instances).toHaveLength(2)

    // 2nd backoff: 200 ms (2^1 * 100) — still under cap
    act(() => {
      MockWebSocket.instances[1].serverClose()
      vi.advanceTimersByTime(200)
    })
    expect(MockWebSocket.instances).toHaveLength(3)

    // 3rd backoff would be 400 ms (2^2 * 100) but is clamped to 250 ms.
    act(() => {
      MockWebSocket.instances[2].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(249)
    })
    expect(MockWebSocket.instances).toHaveLength(3)
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(MockWebSocket.instances).toHaveLength(4)
  })

  it('successful open resets the backoff counter so the next close starts at initialBackoffMs', () => {
    renderHook(() => useLiveOpsStream(opts))

    // Drive one backoff escalation: close → reconnect waits 100ms.
    act(() => {
      MockWebSocket.instances[0].serverClose()
      vi.advanceTimersByTime(100)
    })
    expect(MockWebSocket.instances).toHaveLength(2)

    // Second close BEFORE the second socket has opened — backoff is now 200ms.
    act(() => {
      MockWebSocket.instances[1].serverClose()
      vi.advanceTimersByTime(200)
    })
    expect(MockWebSocket.instances).toHaveLength(3)

    // Now let the third socket actually open — this should reset the counter.
    act(() => {
      MockWebSocket.instances[2].open()
    })

    // Subsequent close should reconnect after initialBackoffMs again (100), not 400.
    act(() => {
      MockWebSocket.instances[2].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(99)
    })
    expect(MockWebSocket.instances).toHaveLength(3)
    act(() => {
      vi.advanceTimersByTime(1)
    })
    expect(MockWebSocket.instances).toHaveLength(4)
  })
})
