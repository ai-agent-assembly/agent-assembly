import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { WsTicketError } from '../../auth/wsTicket'
import { MockWebSocket, resetMockWebSockets } from '../../test/mockWebSocket'
import type { Approval } from './api'
import { useApprovalsStream, type UseApprovalsStreamOptions } from './useApprovalsStream'

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

const defaultOpts: UseApprovalsStreamOptions = {
  mintTicket: () => Promise.resolve('wst_test'),
}

function setup(initial: Approval[] = [], opts: UseApprovalsStreamOptions = defaultOpts) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  queryClient.setQueryData<Approval[]>(['approvals'], initial)
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
  const { result } = renderHook(() => useApprovalsStream(opts), { wrapper })
  return { queryClient, result }
}

describe('useApprovalsStream WS handler', () => {
  it('moves a matching active row to expired on payload.status=expired', async () => {
    const a1 = makeApproval('req-1')
    const { queryClient } = setup([a1])

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
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

  it('no-ops on expired event for an id not in the active list', async () => {
    const a1 = makeApproval('req-1')
    const { queryClient } = setup([a1])

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
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

  it('still injects pending frames into the active list (no regression)', async () => {
    const { queryClient } = setup([])

    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
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

  it('opens with a ticket in the URL, not the JWT', async () => {
    setup([])
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    expect(MockWebSocket.instances[0].url).toContain('ticket=wst_test')
    expect(MockWebSocket.instances[0].url).not.toContain('token=')
  })

  it('reconnect mints a fresh ticket', async () => {
    const mintTicket = vi.fn().mockResolvedValue('wst_test')
    setup([], { mintTicket })
    await waitFor(() => expect(MockWebSocket.instances.length).toBeGreaterThan(0))
    act(() => { MockWebSocket.instances[0].serverClose() })
    await waitFor(
      () => expect(MockWebSocket.instances.length).toBeGreaterThan(1),
      { timeout: 2000 },
    )
    expect(mintTicket.mock.calls.length).toBeGreaterThanOrEqual(2)
  })

  it('mint auth-failure does not spin up a socket', async () => {
    const mintTicket = vi.fn().mockRejectedValue(new WsTicketError('auth', 'nope'))
    const { result } = setup([], { mintTicket })
    await waitFor(() => expect(mintTicket).toHaveBeenCalled())
    expect(MockWebSocket.instances).toHaveLength(0)
    expect(result.current.connected).toBe(false)
  })
})
