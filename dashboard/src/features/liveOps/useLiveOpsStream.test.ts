import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { WsTicketError } from '../../auth/wsTicket'
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
  mintTicket: () => Promise.resolve('wst_test'),
}

/** Flush the microtask created by `await mintTicket()` inside `connect()`. */
const flushMint = () =>
  act(async () => {
    await Promise.resolve()
  })

describe('useLiveOpsStream', () => {
  beforeEach(() => {
    resetMockWebSockets()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('connects on mount and exposes connecting status', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(result.current.status).toBe('connecting')
  })

  it('transitions to connected on socket open', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
    })
    expect(result.current.status).toBe('connected')
  })

  it('appends violation events to the ops ring (most-recent-first)', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
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

  it('populates every LiveOperation field from the structured payload', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
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

  it('falls back to safe defaults when the payload is missing op fields', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
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

  it('maps a wire call_stack into LiveOperation.callStack with camelCase fields', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        id: 9,
        payload: {
          ...VIOLATION_EVENT.payload,
          call_stack: [
            {
              id: 'n0',
              kind: 'llm',
              label: 'gpt-4o',
              latency_ms: 300,
              children: [
                {
                  id: 'n1',
                  kind: 'tool',
                  label: 'gmail.send',
                  latency_ms: null,
                  children: [],
                },
              ],
            },
          ],
        },
      })
    })
    expect(result.current.ops[0].callStack).toEqual([
      {
        id: 'n0',
        kind: 'llm',
        label: 'gpt-4o',
        latencyMs: 300,
        children: [
          {
            id: 'n1',
            kind: 'tool',
            label: 'gmail.send',
          },
        ],
      },
    ])
  })

  it('omits callStack when wire payload has no call_stack', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit(VIOLATION_EVENT)
    })
    expect(result.current.ops[0].callStack).toBeUndefined()
  })

  it('coerces an unknown status string to running', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        payload: { ...VIOLATION_EVENT.payload, status: 'something-else' },
      })
    })
    expect(result.current.ops[0]?.status).toBe('running')
  })

  it('maps blocked / pending status values through unchanged', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
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

  it('ignores non-violation event types', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit({ ...VIOLATION_EVENT, event_type: 'approval' })
    })
    expect(result.current.ops).toHaveLength(0)
  })

  it('drops malformed frames without throwing', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].onmessage?.({ data: 'not json' })
    })
    expect(result.current.ops).toHaveLength(0)
  })

  it('caps the ring at maxOps', async () => {
    const { result } = renderHook(() => useLiveOpsStream({ ...opts, maxOps: 3 }))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      for (let i = 1; i <= 5; i++) {
        MockWebSocket.instances[0].emit({ ...VIOLATION_EVENT, id: i })
      }
    })
    expect(result.current.ops.map((o) => o.id)).toEqual(['5', '4', '3'])
  })

  it('reconnects with exponential backoff after a close', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
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
    await flushMint()
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
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(3)
  })

  it('transitions to error after maxReconnectAttempts', async () => {
    const { result } = renderHook(() =>
      useLiveOpsStream({ ...opts, maxReconnectAttempts: 2 }),
    )
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    await flushMint()
    act(() => {
      MockWebSocket.instances[1].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(200)
    })
    await flushMint()
    act(() => {
      MockWebSocket.instances[2].serverClose()
    })
    expect(result.current.status).toBe('error')
  })

  it('manual reconnect() restarts the connection from error', async () => {
    const { result } = renderHook(() =>
      useLiveOpsStream({ ...opts, maxReconnectAttempts: 1 }),
    )
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    await flushMint()
    act(() => {
      MockWebSocket.instances[1].serverClose()
    })
    expect(result.current.status).toBe('error')

    act(() => {
      result.current.reconnect()
    })
    await flushMint()
    expect(MockWebSocket.instances.length).toBeGreaterThan(2)
    expect(result.current.status).not.toBe('error')
  })

  it('closes the socket on unmount', async () => {
    const { unmount } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    const ws = MockWebSocket.instances[0]
    act(() => {
      ws.open()
    })
    unmount()
    expect(ws.readyState).toBe(MockWebSocket.CLOSED)
  })

  it('opens with a ticket in the URL, not the JWT', async () => {
    renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    expect(MockWebSocket.instances[0].url).toContain('ticket=wst_test')
    expect(MockWebSocket.instances[0].url).not.toContain('token=')
  })

  it('reconnect mints a fresh ticket', async () => {
    const mintTicket = vi.fn().mockResolvedValue('wst_test')
    renderHook(() => useLiveOpsStream({ ...opts, mintTicket }))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    act(() => {
      vi.advanceTimersByTime(100)
    })
    await flushMint()
    expect(mintTicket.mock.calls.length).toBeGreaterThanOrEqual(2)
  })

  it('mint auth-failure does not spin up a socket', async () => {
    // Hoisted so the reference is stable across re-renders — an inline
    // arrow here would be a fresh function every render, which sits in the
    // reconnect effect's dependency array and would re-run `connect()` forever.
    const mintTicket = () => Promise.reject(new WsTicketError('auth', 'nope'))
    const { result } = renderHook(() => useLiveOpsStream({ ...opts, mintTicket }))
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(0)
    expect(result.current.status).toBe('error')
  })

  it('caps reconnect backoff at maxBackoffMs', async () => {
    renderHook(() =>
      useLiveOpsStream({
        ...opts,
        initialBackoffMs: 100,
        maxBackoffMs: 250,
        maxReconnectAttempts: 5,
      }),
    )
    await flushMint()
    // 1st backoff: 100 ms (2^0 * 100)
    act(() => {
      MockWebSocket.instances[0].serverClose()
      vi.advanceTimersByTime(100)
    })
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(2)

    // 2nd backoff: 200 ms (2^1 * 100) — still under cap
    act(() => {
      MockWebSocket.instances[1].serverClose()
      vi.advanceTimersByTime(200)
    })
    await flushMint()
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
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(4)
  })

  // ── AAASM-1652: ops_change event handling ──────────────────────────────

  const OPS_CHANGE_EVENT = {
    id: 100,
    agent_id: 'support-agent',
    event_type: 'ops_change',
    timestamp: '2026-05-21T10:00:00Z',
    payload: {
      op_id: 'trace-abc:span-1',
      state: 'running',
      updated_at: '2026-05-21T10:00:00Z',
    },
  }

  it('subscribes to both violation and ops_change events in the WS URL', async () => {
    renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    expect(MockWebSocket.instances[0].url).toContain('types=violation,ops_change')
  })

  it('maps ops_change events into LiveOperation rows keyed by op_id', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit(OPS_CHANGE_EVENT)
    })
    expect(result.current.ops).toHaveLength(1)
    expect(result.current.ops[0]).toMatchObject({
      id: 'trace-abc:span-1',
      agent: 'support-agent',
      status: 'running',
      startedAt: '2026-05-21T10:00:00Z',
    })
  })

  it('merges successive ops_change events for the same op_id into one row', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      MockWebSocket.instances[0].emit(OPS_CHANGE_EVENT)
      MockWebSocket.instances[0].emit({
        ...OPS_CHANGE_EVENT,
        id: 101,
        payload: {
          ...OPS_CHANGE_EVENT.payload,
          state: 'paused',
          updated_at: '2026-05-21T10:00:05Z',
        },
      })
    })
    expect(result.current.ops).toHaveLength(1)
    expect(result.current.ops[0]).toMatchObject({
      id: 'trace-abc:span-1',
      status: 'blocked', // paused → blocked translation
      startedAt: '2026-05-21T10:00:05Z',
    })
  })

  it('translates gateway OpState values to dashboard OperationStatus', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    const states: Array<{ state: string; expected: string }> = [
      { state: 'pending', expected: 'pending' },
      { state: 'running', expected: 'running' },
      { state: 'paused', expected: 'blocked' },
      { state: 'completing', expected: 'completing' },
      { state: 'terminated', expected: 'terminated' },
    ]
    act(() => {
      MockWebSocket.instances[0].open()
      states.forEach((s, i) => {
        MockWebSocket.instances[0].emit({
          ...OPS_CHANGE_EVENT,
          id: 200 + i,
          payload: { ...OPS_CHANGE_EVENT.payload, op_id: `t:${i}`, state: s.state },
        })
      })
    })
    const byId = new Map(result.current.ops.map((o) => [o.id, o.status]))
    states.forEach((s, i) => {
      expect(byId.get(`t:${i}`)).toBe(s.expected)
    })
  })

  it('preserves opType / resource learned from earlier violation event when merging', async () => {
    const { result } = renderHook(() => useLiveOpsStream(opts))
    await flushMint()
    act(() => {
      MockWebSocket.instances[0].open()
      // First a violation event lands the row with rich metadata (it
      // uses the monotonic id as key — not op_id — but we override the
      // id to match the op_id so the next ops_change event finds it).
      MockWebSocket.instances[0].emit({
        ...VIOLATION_EVENT,
        id: 'trace-abc:span-1' as unknown as number,
        payload: { ...VIOLATION_EVENT.payload, status: 'running' },
      })
      // Then a transition arrives via ops_change.
      MockWebSocket.instances[0].emit(OPS_CHANGE_EVENT)
    })
    expect(result.current.ops).toHaveLength(1)
    expect(result.current.ops[0]).toMatchObject({
      id: 'trace-abc:span-1',
      opType: 'tool_call', // from the violation event
      resource: 'web_search', // from the violation event
      status: 'running', // from the ops_change event
    })
  })

  it('successful open resets the backoff counter so the next close starts at initialBackoffMs', async () => {
    renderHook(() => useLiveOpsStream(opts))
    await flushMint()

    // Drive one backoff escalation: close → reconnect waits 100ms.
    act(() => {
      MockWebSocket.instances[0].serverClose()
      vi.advanceTimersByTime(100)
    })
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(2)

    // Second close BEFORE the second socket has opened — backoff is now 200ms.
    act(() => {
      MockWebSocket.instances[1].serverClose()
      vi.advanceTimersByTime(200)
    })
    await flushMint()
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
    await flushMint()
    expect(MockWebSocket.instances).toHaveLength(4)
  })
})
