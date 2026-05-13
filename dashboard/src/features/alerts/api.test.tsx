import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  useAlertsQuery,
  useAlertQuery,
  useAlertRulesQuery,
  useCreateAlertRuleMutation,
  useUpdateAlertRuleMutation,
  useDeleteAlertRuleMutation,
  useSilenceAlertMutation,
  useDestinationsQuery,
  useCreateDestinationMutation,
  useUpdateDestinationMutation,
  useDeleteDestinationMutation,
  useTestDestinationMutation,
} from './api'
import { alertsQueryKeys } from './endpoints'
import {
  DEFAULT_ALERT_FILTERS,
  type Alert,
  type AlertRule,
  type AlertRuleInput,
  type Destination,
  type DestinationInput,
  type Silence,
} from './types'

// ── Test scaffolding ──────────────────────────────────────────────────────

interface FetchCall {
  url: string
  init: RequestInit
}

let calls: FetchCall[]
let nextResponse: { ok: boolean; status: number; body: unknown }

beforeEach(() => {
  calls = []
  nextResponse = { ok: true, status: 200, body: undefined }
  localStorage.setItem('aa_token', 'test-token')
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit = {}) => {
      calls.push({ url, init })
      return {
        ok: nextResponse.ok,
        status: nextResponse.status,
        json: async () => nextResponse.body,
      } as Response
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
  localStorage.clear()
})

function wrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const Wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return { client, Wrapper }
}

// ── Fixtures ──────────────────────────────────────────────────────────────

const FIXTURE_ALERT: Alert = {
  id: 'a-1',
  ruleId: 'r-1',
  ruleName: 'Budget > 90%',
  severity: 'CRITICAL',
  status: 'FIRING',
  agentId: 'aa-001',
  firstFiredAt: '2026-05-13T09:12:00Z',
  resolvedAt: null,
  destinationIds: ['slack-ops'],
}

const FIXTURE_RULE: AlertRule = {
  id: 'r-1',
  name: 'Budget > 90%',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 90,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  destinationIds: ['slack-ops'],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
  createdAt: '2026-05-13T00:00:00Z',
  updatedAt: '2026-05-13T00:00:00Z',
}

const FIXTURE_RULE_INPUT: AlertRuleInput = {
  name: 'Budget > 90%',
  description: '',
  metric: 'budget_spent_pct',
  operator: '>',
  threshold: 90,
  evaluationWindowSeconds: 300,
  severity: 'CRITICAL',
  destinationIds: ['slack-ops'],
  dedupWindowSeconds: 600,
  suppressionLabels: {},
  enabled: true,
}

const FIXTURE_DESTINATION: Destination = {
  id: 'd-1',
  kind: 'webhook',
  name: 'Ops webhook',
  enabled: true,
  createdAt: '2026-05-13T00:00:00Z',
  updatedAt: '2026-05-13T00:00:00Z',
  config: { url: 'https://hooks.internal/aaasm' },
}

const FIXTURE_DESTINATION_INPUT: DestinationInput = {
  kind: 'webhook',
  name: 'Ops webhook',
  enabled: true,
  config: { url: 'https://hooks.internal/aaasm' },
}

const FIXTURE_SILENCE: Silence = {
  silenceId: 'sil-1',
  alertId: 'a-1',
  startsAt: '2026-05-13T09:30:00Z',
  expiresAt: '2026-05-13T10:30:00Z',
  reason: null,
  createdBy: 'user-1',
}

// ── Queries ───────────────────────────────────────────────────────────────

describe('useAlertsQuery', () => {
  it('fetches /api/v1/alerts with filter query string and Bearer token', async () => {
    nextResponse = { ok: true, status: 200, body: [FIXTURE_ALERT] }
    const { Wrapper } = wrapper()
    const filters = { ...DEFAULT_ALERT_FILTERS, severities: ['CRITICAL'] as const }
    const { result } = renderHook(() => useAlertsQuery(filters), { wrapper: Wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual([FIXTURE_ALERT])
    expect(calls[0].url).toBe('/api/v1/alerts?severity=CRITICAL&range=24h')
    expect((calls[0].init.headers as Record<string, string>).Authorization).toBe(
      'Bearer test-token',
    )
  })

  it('returns isError on non-2xx response', async () => {
    nextResponse = { ok: false, status: 500, body: 'boom' }
    const { Wrapper } = wrapper()
    const { result } = renderHook(() => useAlertsQuery(DEFAULT_ALERT_FILTERS), {
      wrapper: Wrapper,
    })
    await waitFor(() => expect(result.current.isError).toBe(true))
  })
})

describe('useAlertQuery', () => {
  it('is disabled when id is null', () => {
    const { Wrapper } = wrapper()
    const { result } = renderHook(() => useAlertQuery(null), { wrapper: Wrapper })
    expect(result.current.fetchStatus).toBe('idle')
    expect(calls).toHaveLength(0)
  })

  it('fetches /api/v1/alerts/{id} when id is provided', async () => {
    nextResponse = { ok: true, status: 200, body: FIXTURE_ALERT }
    const { Wrapper } = wrapper()
    const { result } = renderHook(() => useAlertQuery('a-1'), { wrapper: Wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(calls[0].url).toBe('/api/v1/alerts/a-1')
  })
})

describe('useAlertRulesQuery + mutations', () => {
  it('lists rules', async () => {
    nextResponse = { ok: true, status: 200, body: [FIXTURE_RULE] }
    const { Wrapper } = wrapper()
    const { result } = renderHook(() => useAlertRulesQuery(), { wrapper: Wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(calls[0].url).toBe('/api/v1/alerts/rules')
  })

  it('create mutation POSTs JSON and invalidates the rules cache key', async () => {
    nextResponse = { ok: true, status: 201, body: FIXTURE_RULE }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useCreateAlertRuleMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync(FIXTURE_RULE_INPUT)
    expect(calls[0].init.method).toBe('POST')
    expect(calls[0].init.body).toBe(JSON.stringify(FIXTURE_RULE_INPUT))
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.alertRules] })
  })

  it('update mutation PUTs to /rules/{id} and invalidates', async () => {
    nextResponse = { ok: true, status: 200, body: FIXTURE_RULE }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useUpdateAlertRuleMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync({ id: 'r-1', input: FIXTURE_RULE_INPUT })
    expect(calls[0].url).toBe('/api/v1/alerts/rules/r-1')
    expect(calls[0].init.method).toBe('PUT')
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.alertRules] })
  })

  it('delete mutation DELETEs and invalidates', async () => {
    nextResponse = { ok: true, status: 204, body: undefined }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useDeleteAlertRuleMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync('r-1')
    expect(calls[0].init.method).toBe('DELETE')
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.alertRules] })
  })
})

describe('useSilenceAlertMutation', () => {
  it('POSTs snake_case body and invalidates alerts', async () => {
    nextResponse = { ok: true, status: 201, body: FIXTURE_SILENCE }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useSilenceAlertMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync({
      alertId: 'a-1',
      durationSeconds: 3600,
      reason: 'maintenance',
    })
    expect(calls[0].url).toBe('/api/v1/alerts/silence')
    const body = JSON.parse(calls[0].init.body as string)
    expect(body).toEqual({
      alert_id: 'a-1',
      duration_seconds: 3600,
      reason: 'maintenance',
    })
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.alerts] })
  })
})

describe('destinations hooks', () => {
  it('lists destinations', async () => {
    nextResponse = { ok: true, status: 200, body: [FIXTURE_DESTINATION] }
    const { Wrapper } = wrapper()
    const { result } = renderHook(() => useDestinationsQuery(), { wrapper: Wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(calls[0].url).toBe('/api/v1/alerts/destinations')
  })

  it('create mutation POSTs and invalidates destinations', async () => {
    nextResponse = { ok: true, status: 201, body: FIXTURE_DESTINATION }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useCreateDestinationMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync(FIXTURE_DESTINATION_INPUT)
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.destinations] })
  })

  it('update mutation PUTs and invalidates', async () => {
    nextResponse = { ok: true, status: 200, body: FIXTURE_DESTINATION }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useUpdateDestinationMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync({ id: 'd-1', input: FIXTURE_DESTINATION_INPUT })
    expect(calls[0].init.method).toBe('PUT')
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.destinations] })
  })

  it('delete mutation DELETEs and invalidates', async () => {
    nextResponse = { ok: true, status: 204, body: undefined }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useDeleteDestinationMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync('d-1')
    expect(calls[0].init.method).toBe('DELETE')
    expect(spy).toHaveBeenCalledWith({ queryKey: [alertsQueryKeys.destinations] })
  })

  it('test mutation POSTs to /destinations/{id}/test and does not invalidate the list', async () => {
    nextResponse = {
      ok: true,
      status: 200,
      body: { deliveredAt: '2026-05-13T00:00:00Z', connectorResponseStatus: 200, connectorResponseBody: 'ok' },
    }
    const { client, Wrapper } = wrapper()
    const spy = vi.spyOn(client, 'invalidateQueries')
    const { result } = renderHook(() => useTestDestinationMutation(), { wrapper: Wrapper })
    await result.current.mutateAsync({ id: 'd-1', severity: 'LOW' })
    expect(calls[0].url).toBe('/api/v1/alerts/destinations/d-1/test')
    expect(calls[0].init.method).toBe('POST')
    expect(spy).not.toHaveBeenCalled()
  })
})
