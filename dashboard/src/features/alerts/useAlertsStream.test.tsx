import { renderHook, act, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MockWebSocket, resetMockWebSockets } from '../../test/mockWebSocket'
import { useAlertsStream } from './useAlertsStream'
import type { Alert, Silence } from './types'

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
    const { result } = renderHook(() => useAlertsStream({ onFire }))
    expect(result.current).toBe('connecting')

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

  it('forwards RESOLVED and SILENCE frames to the matching handlers', () => {
    const onResolve = vi.fn()
    const onSilence = vi.fn()
    renderHook(() => useAlertsStream({ onResolve, onSilence }))
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

  it('ignores heartbeat frames', () => {
    const onFire = vi.fn()
    renderHook(() => useAlertsStream({ onFire }))
    act(() => {
      MockWebSocket.instances[0].emit({ type: 'heartbeat', ts: '...' })
    })
    expect(onFire).not.toHaveBeenCalled()
  })

  it('reports closed status when the socket drops', async () => {
    const { result } = renderHook(() => useAlertsStream({}))
    act(() => MockWebSocket.instances[0].open())
    await waitFor(() => expect(result.current).toBe('open'))
    act(() => MockWebSocket.instances[0].close())
    await waitFor(() => expect(result.current).toBe('closed'))
  })
})
