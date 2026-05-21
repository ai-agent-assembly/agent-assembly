import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MockWebSocket, resetMockWebSockets } from '../../test/mockWebSocket'
import type { Approval } from './api'
import { useApprovalsStream } from './useApprovalsStream'

beforeEach(() => {
  resetMockWebSockets()
  vi.stubGlobal('WebSocket', MockWebSocket)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function makeApproval(id: string, overrides: Partial<Approval> = {}): Approval {
  return {
    id,
    agent_id: 'agent-1',
    action: 'send_email',
    reason: 'r',
    status: 'pending',
    created_at: '2026-05-20T12:00:00Z',
    expires_at: '2026-05-20T12:01:00Z',
    routing_status: null,
    team_id: null,
    ...overrides,
  }
}

function setup(initial: Approval[] = []) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  queryClient.setQueryData<Approval[]>(['approvals'], initial)
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
  const { result } = renderHook(() => useApprovalsStream(), { wrapper })
  return { queryClient, result }
}

describe('useApprovalsStream WS handler', () => {
  it('moves a matching active row to expired on payload.status=expired', () => {
    const a1 = makeApproval('req-1')
    const { queryClient } = setup([a1])

    act(() => { MockWebSocket.instances[0].open() })
    act(() => {
      MockWebSocket.instances[0].emit({
        event_type: 'approval',
        agent_id: 'agent-1',
        timestamp: '2026-05-20T12:01:00Z',
        payload: {
          request_id: 'req-1',
          action: 'send_email',
          condition_triggered: 'r',
          status: 'expired',
          submitted_at: 1716206400,
          timeout_secs: 60,
          expires_at: 1716206460,
        },
      })
    })

    expect(queryClient.getQueryData<Approval[]>(['approvals'])).toEqual([])
    expect(queryClient.getQueryData<Approval[]>(['approvals', 'expired']))
      .toEqual([{ ...a1, status: 'expired' }])
  })

  it('no-ops on expired event for an id not in the active list', () => {
    const a1 = makeApproval('req-1')
    const { queryClient } = setup([a1])

    act(() => { MockWebSocket.instances[0].open() })
    act(() => {
      MockWebSocket.instances[0].emit({
        event_type: 'approval',
        agent_id: 'agent-1',
        timestamp: '2026-05-20T12:01:00Z',
        payload: {
          request_id: 'unknown-id',
          action: 'send_email',
          condition_triggered: 'r',
          status: 'expired',
          submitted_at: 1716206400,
          timeout_secs: 60,
          expires_at: 1716206460,
        },
      })
    })

    expect(queryClient.getQueryData<Approval[]>(['approvals'])).toEqual([a1])
    expect(queryClient.getQueryData<Approval[]>(['approvals', 'expired'])).toBeUndefined()
  })

  it('still injects pending frames into the active list (no regression)', () => {
    const { queryClient } = setup([])

    act(() => { MockWebSocket.instances[0].open() })
    act(() => {
      MockWebSocket.instances[0].emit({
        event_type: 'approval',
        agent_id: 'agent-7',
        timestamp: '2026-05-20T12:00:00Z',
        payload: {
          request_id: 'req-new',
          action: 'write_file',
          condition_triggered: 'sensitive_path',
          status: 'pending',
          submitted_at: 1716206400,
          timeout_secs: 60,
          expires_at: 1716206460,
        },
      })
    })

    const active = queryClient.getQueryData<Approval[]>(['approvals'])
    expect(active).toHaveLength(1)
    expect(active?.[0].id).toBe('req-new')
    expect(active?.[0].status).toBe('pending')
  })
})
