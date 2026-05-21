import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { describe, it, expect } from 'vitest'
import type { Approval } from './api'
import { expireApproval, useExpiredApprovals } from './useExpiredApprovals'

function makeApproval(id: string): Approval {
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
  }
}

function setup(initial: Approval[] = []) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  queryClient.setQueryData<Approval[]>(['approvals'], initial)
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
  const { result } = renderHook(() => useExpiredApprovals(), { wrapper })
  return { queryClient, result }
}

describe('useExpiredApprovals', () => {
  it('starts with an empty expired list', () => {
    const { result } = setup()
    expect(result.current.expired).toEqual([])
  })

  it('moves a matching row out of the active cache and into the expired list', () => {
    const a1 = makeApproval('a1')
    const a2 = makeApproval('a2')
    const { queryClient, result } = setup([a1, a2])

    act(() => { result.current.expire('a1') })

    expect(queryClient.getQueryData<Approval[]>(['approvals'])).toEqual([a2])
    expect(result.current.expired).toEqual([{ ...a1, status: 'expired' }])
  })

  it('is idempotent — calling expire twice does not duplicate', () => {
    const a1 = makeApproval('a1')
    const { result } = setup([a1])

    act(() => { result.current.expire('a1') })
    act(() => { result.current.expire('a1') })

    expect(result.current.expired).toHaveLength(1)
  })

  it('no-ops when the id is not in the active list (stale event)', () => {
    const a1 = makeApproval('a1')
    const { queryClient, result } = setup([a1])

    act(() => { result.current.expire('not-here') })

    expect(queryClient.getQueryData<Approval[]>(['approvals'])).toEqual([a1])
    expect(result.current.expired).toEqual([])
  })

  it('module-level expireApproval works without the hook (WS handler path)', () => {
    const a1 = makeApproval('a1')
    const a2 = makeApproval('a2')
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    queryClient.setQueryData<Approval[]>(['approvals'], [a1, a2])

    expireApproval(queryClient, 'a2')

    expect(queryClient.getQueryData<Approval[]>(['approvals'])).toEqual([a1])
    expect(queryClient.getQueryData<Approval[]>(['approvals', 'expired']))
      .toEqual([{ ...a2, status: 'expired' }])
  })
})
