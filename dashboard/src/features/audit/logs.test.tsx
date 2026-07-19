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

  it('ignores an empty-string decision and falls through to null', () => {
    expect(extractDecision('{"decision":""}')).toBeNull()
  })

  it('ignores a non-string decision and falls back to shadow_decision', () => {
    expect(extractDecision('{"decision":1,"shadow_decision":"redact"}')).toBe('REDACT')
  })

  it('returns null for a non-object JSON payload', () => {
    expect(extractDecision('"just-a-string"')).toBeNull()
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

  it('upper-cases a FileOp operation and renders a MB size suffix', () => {
    const s = payloadSummary(
      'FileOp',
      '{"operation":"write","path":"/tmp/out.bin","bytes":2097152}',
    )
    expect(s).toBe('WRITE /tmp/out.bin · 2.0 MB')
  })

  it('omits the size suffix for a FileOp with no byte count', () => {
    const s = payloadSummary('FileOp', '{"operation":"read","path":"/etc/hosts"}')
    expect(s).toBe('READ /etc/hosts')
  })

  it('coerces a non-string FileOp operation to an empty verb (no [object Object])', () => {
    const s = payloadSummary('FileOp', '{"operation":{"verb":"x"},"path":"/p"}')
    expect(s).not.toContain('[object Object]')
    expect(s).toBe(' /p')
  })

  it('renders an empty verb for a missing FileOp operation', () => {
    const s = payloadSummary('FileOp', '{"path":"/p"}')
    expect(s).toBe(' /p')
  })

  it('summarises a ToolCall with an error marker when it did not succeed', () => {
    const s = payloadSummary(
      'ToolCall',
      '{"tool_name":"db_query","tool_source":"mcp","succeeded":false,"latency_ms":12}',
    )
    expect(s).toBe('db_query (mcp) · ✕ error · 12ms')
  })

  it('summarises a NetworkCall as protocol://host → status', () => {
    const s = payloadSummary(
      'NetworkCall',
      '{"protocol":"https","host":"api.example.com","status_code":200,"latency_ms":54}',
    )
    expect(s).toBe('https://api.example.com → 200 · 54ms')
  })

  it('summarises an ApprovalEvent as rejected when not approved', () => {
    const s = payloadSummary(
      'ApprovalEvent',
      '{"approval_id":"ap-1","approved":false,"approver_id":"u-9","wait_time_ms":4200}',
    )
    expect(s).toBe('ap-1 rejected by u-9 after 4s')
  })

  it('truncates an oversized unknown-type dump to 100 chars', () => {
    const big = JSON.stringify({ note: 'x'.repeat(200) })
    const s = payloadSummary('Mystery', big)
    expect(s).toHaveLength(100)
  })
})

describe('auditEventHref', () => {
  it('builds the stable /audit/event/:seq detail path', () => {
    expect(auditEventHref(1048)).toBe('/audit/event/1048')
  })

  it('handles a zero seq without dropping the segment', () => {
    expect(auditEventHref(0)).toBe('/audit/event/0')
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
    get.mockResolvedValue({ data: { items: [], page: 1, per_page: 50, total: 0 } })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', { params: { query: {} } })
  })

  it('forwards agent and event-type filters as query params', async () => {
    get.mockResolvedValue({ data: { items: [], page: 1, per_page: 50, total: 0 } })
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
    get.mockResolvedValue({ data: { items: entries, page: 1, per_page: 50, total: entries.length } })
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
