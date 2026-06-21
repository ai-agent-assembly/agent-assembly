import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import {
  auditEventHref,
  extractDecision,
  payloadSummary,
  useAuditLogQuery,
  type LogEntry,
} from './logs'

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

describe('extractDecision', () => {
  it('reads an explicit decision and upper-cases it', () => {
    expect(extractDecision('{"decision":"allow"}')).toBe('ALLOW')
  })

  it('falls back to shadow_decision when no explicit decision', () => {
    expect(extractDecision('{"shadow_decision":"deny"}')).toBe('DENY')
  })

  it('returns null when neither field is present', () => {
    expect(extractDecision('{"model":"gpt-4o"}')).toBeNull()
  })

  it('returns null for malformed JSON', () => {
    expect(extractDecision('not-json')).toBeNull()
  })
})

describe('payloadSummary', () => {
  it('summarises an LLMCall with token + latency detail', () => {
    const s = payloadSummary(
      'LLMCall',
      '{"model":"gpt-4o","prompt_tokens":100,"completion_tokens":20,"latency_ms":680}',
    )
    expect(s).toContain('gpt-4o')
    expect(s).toContain('100+20 tok')
    expect(s).toContain('680ms')
  })

  it('flags PII on an LLMCall', () => {
    const s = payloadSummary('LLMCall', '{"model":"gpt-4o","pii_detected":true}')
    expect(s).toContain('PII detected')
  })

  it('summarises a PolicyViolation as action — reason', () => {
    const s = payloadSummary(
      'PolicyViolation',
      '{"blocked_action":"gmail/send","reason":"needs approval"}',
    )
    expect(s).toBe('gmail/send — needs approval')
  })

  it('falls back to a truncated dump for unknown event types', () => {
    expect(payloadSummary('Mystery', '{"a":1}')).toBe('{"a":1}')
  })

  it('returns an em dash for malformed payloads', () => {
    expect(payloadSummary('LLMCall', 'not-json')).toBe('—')
  })
})

describe('auditEventHref', () => {
  it('builds the stable /audit/event/:seq detail path', () => {
    expect(auditEventHref(1048)).toBe('/audit/event/1048')
  })
})

describe('useAuditLogQuery', () => {
  let get: Mock
  beforeEach(() => {
    get = vi.spyOn(api, 'GET') as unknown as Mock
  })
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('omits filters from the query when unset', async () => {
    get.mockResolvedValue({ data: [] })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', { params: { query: {} } })
  })

  it('forwards agent and event-type filters as query params', async () => {
    get.mockResolvedValue({ data: [] })
    const { result } = renderHook(
      () => useAuditLogQuery({ agentId: 'abc123', eventType: 'PolicyViolation' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', {
      params: { query: { agent_id: 'abc123', event_type: 'PolicyViolation' } },
    })
  })

  it('returns the fetched entries', async () => {
    const entries: LogEntry[] = [
      {
        seq: 1,
        timestamp: '2026-05-11T14:00:00Z',
        agent_id: 'a',
        session_id: 's',
        event_type: 'LLMCall',
        payload: '{}',
      },
    ]
    get.mockResolvedValue({ data: entries })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toEqual(entries)
  })

  it('throws when the gateway returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch audit log')
  })
})
