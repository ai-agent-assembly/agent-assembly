import { renderHook, act, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { WsTicketError } from '../../auth/wsTicket'
import { MockWebSocket, resetMockWebSockets } from '../../test/mockWebSocket'
import { useAlertsStream } from './useAlertsStream'
import type { Alert, Silence } from './types'

const defaultOpts = { mintTicket: () => Promise.resolve('wst_test') }

beforeEach(() => {
  resetMockWebSockets()
  vi.stubGlobal('WebSocket', MockWebSocket)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

const ALERT: Alert = {
  id: 'a-1',
  ruleId: 'r-1',
  ruleName: 'Budget > 90%',
  severity: 'CRITICAL',
  status: 'FIRING',
  agentId: 'aa-001',
  firstFiredAt: '2026-05-14T09:00:00Z',
  resolvedAt: null,
  destinationIds: [],
}

const SILENCE: Silence = {
  silenceId: 'sil-1',
  alertId: 'a-1',
  startsAt: '2026-05-14T09:00:00Z',
  expiresAt: '2026-05-14T10:00:00Z',
  reason: null,
  createdBy: 'user-1',
}

describe('useAlertsStream', () => {
  it('connects, transitions to open, and forwards FIRING frames to onFire', async () => {
    const onFire = vi.fn()
    const { result } = renderHook(() => useAlertsStream({ onFire }, defaultOpts))
    expect(result.current).toBe('connecting')

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => {
      MockWebSocket.instances[0].open()
    })
    await waitFor(() => expect(result.current).toBe('open'))

    act(() => {
      MockWebSocket.instances[0].emit({
        type: 'alert.fire',
        ts: '2026-05-14T09:00:00Z',
        alert: ALERT,
      })
    })
    expect(onFire).toHaveBeenCalledWith(ALERT)
  })

  it('canonicalises a frame written in the backend vocabulary (AAASM-5149)', async () => {
    // The socket carries the same payload shape as the REST list. If it were
    // forwarded raw, one pushed frame would write wire-vocabulary rows into the
    // shared alerts cache and undo the list boundary's parse — and the nav
    // badge reads that cache.
    const onFire = vi.fn()
    renderHook(() => useAlertsStream({ onFire }, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))

    act(() => {
      MockWebSocket.instances[0].emit({
        type: 'alert.fire',
        ts: '2026-05-14T09:00:00Z',
        alert: {
          id: 'a-9',
          severity: 'critical',
          status: 'unresolved',
          category: 'budget',
          message: 'Budget threshold 90% crossed',
          timestamp: '2026-05-14T09:00:00Z',
          agent_id: 'aa-002',
        },
      })
    })

    expect(onFire).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 'a-9',
        severity: 'CRITICAL',
        status: 'FIRING',
        agentId: 'aa-002',
        firstFiredAt: '2026-05-14T09:00:00Z',
      }),
    )
  })

  it('drops a frame it cannot read rather than forwarding a half-built alert', async () => {
    // Dropping matches the existing malformed-JSON arm: a push is an increment,
    // not an answer, and the next list refetch re-establishes ground truth.
    const onFire = vi.fn()
    renderHook(() => useAlertsStream({ onFire }, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))

    act(() => {
      MockWebSocket.instances[0].emit({
        type: 'alert.fire',
        ts: '2026-05-14T09:00:00Z',
        alert: { id: 'a-9', severity: 'catastrophic', status: 'acknowledged' },
      })
    })

    expect(onFire).not.toHaveBeenCalled()
  })

  it('forwards RESOLVED and SILENCE frames to the matching handlers', async () => {
    const onResolve = vi.fn()
    const onSilence = vi.fn()
    renderHook(() => useAlertsStream({ onResolve, onSilence }, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => {
      MockWebSocket.instances[0].emit({
        type: 'alert.resolve',
        ts: '...',
        alert: { ...ALERT, status: 'RESOLVED' },
      })
      MockWebSocket.instances[0].emit({
        type: 'alert.silence',
        ts: '...',
        alert: { ...ALERT, status: 'SUPPRESSED' },
        silence: SILENCE,
      })
    })
    expect(onResolve).toHaveBeenCalledWith({ ...ALERT, status: 'RESOLVED' })
    expect(onSilence).toHaveBeenCalledWith({ ...ALERT, status: 'SUPPRESSED' }, SILENCE)
  })

  it('ignores heartbeat frames', async () => {
    const onFire = vi.fn()
    renderHook(() => useAlertsStream({ onFire }, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => {
      MockWebSocket.instances[0].emit({ type: 'heartbeat', ts: '...' })
    })
    expect(onFire).not.toHaveBeenCalled()
  })

  it('reports closed status when the socket drops', async () => {
    const { result } = renderHook(() => useAlertsStream({}, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => MockWebSocket.instances[0].open())
    await waitFor(() => expect(result.current).toBe('open'))
    act(() => MockWebSocket.instances[0].close())
    await waitFor(() => expect(result.current).toBe('closed'))
  })

  it('opens with a ticket in the URL, not the JWT', async () => {
    renderHook(() => useAlertsStream({}, defaultOpts))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    expect(MockWebSocket.instances[0].url).toContain('ticket=wst_test')
    expect(MockWebSocket.instances[0].url).not.toContain('token=')
  })

  it('reconnect mints a fresh ticket', async () => {
    const mintTicket = vi.fn().mockResolvedValue('wst_test')
    renderHook(() => useAlertsStream({}, { mintTicket }))
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => {
      MockWebSocket.instances[0].serverClose()
    })
    await waitFor(
      () => expect(MockWebSocket.instances.length).toBeGreaterThan(1),
      { timeout: 2000 },
    )
    expect(mintTicket.mock.calls.length).toBeGreaterThanOrEqual(2)
  })

  it('mint auth-failure does not spin up a socket', async () => {
    const mintTicket = vi.fn().mockRejectedValue(new WsTicketError('auth', 'nope'))
    const { result } = renderHook(() => useAlertsStream({}, { mintTicket }))
    await waitFor(() => expect(result.current).toBe('closed'))
    expect(MockWebSocket.instances).toHaveLength(0)
  })
})
