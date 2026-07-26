import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { api } from '../../api/client'
import { isKnown, type Certain } from '../../lib/truthfulness'
import {
  AUDIT_EVENT_GROUPS,
  AUDIT_EVENT_TYPES,
  AUDIT_MAX_PAGES,
  AUDIT_PAGE_SIZE,
  auditCoverage,
  auditEventHref,
  coverageStatement,
  eventGroupOf,
  extractTraceId,
  extractVerdict,
  isKnownEventType,
  isSuppressedDenial,
  payloadSummary,
  useAuditLogQuery,
  type AuditLogWindow,
  type LogEntry,
} from './logs'

function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
}

/** Assert a `Certain` is known and return its value, for terse expectations. */
function value<T>(certain: Certain<T>): T {
  if (!isKnown(certain)) {
    throw new Error(`expected a known value, got ${JSON.stringify(certain)}`)
  }
  return certain.value
}

describe('extractVerdict — proto enum wire shape', () => {
  // ── THE regression this whole ticket is about (AAASM-5117) ───────────────
  // `aa-gateway/src/service/policy_service.rs` writes `"decision":
  // response.decision`, and prost types a proto enum field as `i32`. Every
  // shipped enforce-mode deployment therefore carries an integer here. A
  // string-only reader silently returns "no verdict" for every single row.
  it.each([
    [1, 'ALLOW'],
    [2, 'DENY'],
    [3, 'PENDING'],
    [4, 'REDACT'],
  ])('maps proto discriminant %i to %s', (discriminant, expected) => {
    const { enforced } = extractVerdict(`{"decision":${discriminant}}`)
    expect(isKnown(enforced)).toBe(true)
    expect(value(enforced)).toBe(expected)
  })

  it('reads a real gateway payload verbatim', () => {
    // Field-for-field the object `record_audit` serialises.
    const payload = JSON.stringify({
      action_type: 2,
      decision: 2,
      reason: 'tool denied by policy',
      policy_rule: 'deny-gmail-send',
      latency_us: 412,
      trace_id: 'trace-abc',
      span_id: 'span-1',
      org_id: 'acme',
      team_id: 'research',
    })
    const verdict = extractVerdict(payload)
    expect(value(verdict.enforced)).toBe('DENY')
    expect(verdict.suppressed).toBeNull()
    expect(verdict.dryRun).toBe(false)
  })

  it('reads a real runtime payload verbatim', () => {
    // Field-for-field the object `build_payload` serialises.
    const payload = JSON.stringify({
      event_id: '550e8400-e29b-41d4-a716-446655440000',
      action_type: 'TOOL_CALL',
      source: 'sdk',
      decision: 1,
      detail: { kind: 'tool_call', tool_name: 'pg.users', tool_source: 'mcp', succeeded: true },
    })
    expect(value(extractVerdict(payload).enforced)).toBe('ALLOW')
  })

  // Every value the page must refuse to turn into a verdict. The case name is a
  // parameter so a failure still names the specific contract that broke.
  it.each([
    ['DECISION_UNSPECIFIED (0), the proto default', '{"decision":0}', 'unknown'],
    ['a discriminant this build does not know', '{"decision":97}', 'unknown'],
    ['an unrecognised decision string', '{"decision":"probably-fine"}', 'unknown'],
    ['no decision field at all', '{"event_id":"x"}', 'not-evaluated'],
  ])('reports %s as an explicit absence, never a verdict', (_case, payload, state) => {
    const { enforced } = extractVerdict(payload)
    expect(isKnown(enforced)).toBe(false)
    expect(enforced).toMatchObject({ state })
  })

  it('reports unknown for malformed JSON', () => {
    expect(extractVerdict('not-json').enforced).toMatchObject({ known: false, state: 'unknown' })
  })

  it('reports unknown for a non-object JSON payload', () => {
    expect(extractVerdict('"just-a-string"').enforced).toMatchObject({
      known: false,
      state: 'unknown',
    })
  })

  it('ignores an empty-string decision and falls through', () => {
    expect(extractVerdict('{"decision":""}').enforced).toMatchObject({ known: false })
  })
})

// ── AAASM-5117 review blocker: observe mode ────────────────────────────────
// `transform_for_observe_mode` (aa-gateway/src/engine/mod.rs:144-171) replaces a
// Deny with Allow and returns a ShadowEvent, so the shipped payload is
// `{"decision":1,"dry_run":true,"shadow_decision":"deny",...}`. Reporting only
// the enforced value paints an observe-mode deployment — the recommended
// onboarding posture — as a wall of green allows over suppressed denials.
describe('extractVerdict — observe mode must never read as a bare allow', () => {
  const SUPPRESSED_DENY = JSON.stringify({
    action_type: 2,
    decision: 1,
    reason: '',
    policy_rule: '',
    latency_us: 300,
    dry_run: true,
    shadow_decision: 'deny',
    shadow_reason: 'tool denied by policy',
  })

  it('surfaces the suppressed verdict alongside the enforced one', () => {
    const verdict = extractVerdict(SUPPRESSED_DENY)
    // The action really was allowed to proceed — that stays true...
    expect(value(verdict.enforced)).toBe('ALLOW')
    // ...but the suppressed denial travels with it, in the same value, so no
    // consumer can render or count the allow without seeing it.
    expect(verdict.dryRun).toBe(true)
    expect(value(verdict.suppressed as Certain<string>)).toBe('DENY')
    expect(verdict.suppressedReason).toBe('tool denied by policy')
    expect(isSuppressedDenial(verdict)).toBe(true)
  })

  it('recognises a suppressed pending approval', () => {
    // engine/mod.rs:155 maps RequiresApproval to shadow_decision "pending".
    const verdict = extractVerdict('{"decision":1,"dry_run":true,"shadow_decision":"pending"}')
    expect(value(verdict.suppressed as Certain<string>)).toBe('PENDING')
    expect(isSuppressedDenial(verdict)).toBe(true)
  })

  it('does not mark an ordinary enforce-mode allow as suppressed', () => {
    const verdict = extractVerdict('{"decision":1,"reason":"","policy_rule":""}')
    expect(verdict.suppressed).toBeNull()
    expect(verdict.dryRun).toBe(false)
    expect(isSuppressedDenial(verdict)).toBe(false)
  })

  it('recovers the suppressed reason for the summary, which the rewrite empties', () => {
    // convert.rs:194-201 blanks `reason` and `policy_rule` on the rewritten
    // Allow response, so `shadow_reason` is the only surviving explanation.
    expect(value(payloadSummary(SUPPRESSED_DENY))).toBe('tool denied by policy')
  })

  it('still reads a payload that carries only shadow_decision', () => {
    const verdict = extractVerdict('{"shadow_decision":"deny"}')
    expect(isKnown(verdict.enforced)).toBe(false)
    expect(value(verdict.suppressed as Certain<string>)).toBe('DENY')
  })
})

describe('event-type vocabulary', () => {
  it('lists exactly the 22 aa_core::audit::AuditEventType variants', () => {
    expect(AUDIT_EVENT_TYPES).toHaveLength(22)
    expect(AUDIT_EVENT_TYPES).toContain('ToolCallIntercepted')
    expect(AUDIT_EVENT_TYPES).toContain('SandboxHostFnRateLimited')
  })

  it('carries none of the hi-fi fixture names the backend never emits', () => {
    for (const invented of ['LLMCall', 'ToolCall', 'FileOp', 'NetworkCall', 'ApprovalEvent']) {
      expect(AUDIT_EVENT_TYPES as readonly string[]).not.toContain(invented)
      expect(isKnownEventType(invented)).toBe(false)
    }
  })

  it('assigns every real variant to exactly one group', () => {
    const grouped = AUDIT_EVENT_GROUPS.flatMap((g) => g.members as readonly string[])
    expect(new Set(grouped).size).toBe(grouped.length)
    for (const variant of AUDIT_EVENT_TYPES) {
      expect(grouped).toContain(variant)
      expect(eventGroupOf(variant)).not.toBe('other')
    }
  })

  it('routes an unrecognised variant to the "other" bucket rather than dropping it', () => {
    expect(eventGroupOf('SomeFutureVariant')).toBe('other')
  })
})

describe('payloadSummary — real payload shapes', () => {
  it('summarises a runtime tool_call detail', () => {
    const s = payloadSummary(
      JSON.stringify({
        action_type: 'TOOL_CALL',
        decision: 1,
        detail: { kind: 'tool_call', tool_name: 'pg.users', tool_source: 'mcp', succeeded: true },
      }),
    )
    expect(value(s)).toBe('pg.users (mcp) · ✓ ok')
  })

  it('marks a failed tool call', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'tool_call', tool_name: 't', tool_source: 'mcp', succeeded: false } }),
    )
    expect(value(s)).toContain('✕ error')
  })

  it('summarises an llm_call from model + provider', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'llm_call', model: 'claude-3-5-sonnet', provider: 'anthropic' } }),
    )
    expect(value(s)).toBe('claude-3-5-sonnet · anthropic')
  })

  it('summarises a file_op with the verb upper-cased', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'file_op', operation: 'write', path: '/tmp/out.bin', source: 'ebpf' } }),
    )
    expect(value(s)).toBe('WRITE /tmp/out.bin · ebpf')
  })

  it('summarises a network_call as protocol://host:port', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'network_call', protocol: 'https', host: 'api.example.com', port: 443 } }),
    )
    expect(value(s)).toBe('https://api.example.com:443')
  })

  it('summarises a process_exec with its exit code', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'process_exec', command: '/bin/sh', exit_code: 0 } }),
    )
    expect(value(s)).toBe('/bin/sh · exit 0')
  })

  it('summarises an approval detail', () => {
    const s = payloadSummary(
      JSON.stringify({ detail: { kind: 'approval', approval_id: 'ap-1', approved: false } }),
    )
    expect(value(s)).toBe('ap-1 denied')
  })

  // ── AAASM-5119: the literal "undefined — undefined" regression ───────────
  it('never renders "undefined" for a gateway policy-violation payload', () => {
    // The gateway carries `reason` / `policy_rule`, NOT the mock's
    // `blocked_action`, so the old reader printed `undefined — undefined`.
    const s = payloadSummary(
      JSON.stringify({
        action_type: 2,
        decision: 2,
        reason: 'External recipient requires approval',
        policy_rule: 'deny-external-mail',
      }),
    )
    expect(value<string>(s)).toBe('External recipient requires approval — deny-external-mail')
    expect(value<string>(s)).not.toContain('undefined')
  })

  it('summarises a runtime policy_violation detail without inventing fields', () => {
    const s = payloadSummary(
      JSON.stringify({
        detail: {
          kind: 'policy_violation',
          policy_rule: 'deny-gmail',
          blocked_action: 'gmail/send',
          reason: 'external recipient',
        },
      }),
    )
    expect(value<string>(s)).toBe('gmail/send — external recipient · rule deny-gmail')
  })

  it('omits a missing detail field instead of printing undefined', () => {
    const s = payloadSummary(JSON.stringify({ detail: { kind: 'llm_call', model: 'gpt-4o' } }))
    expect(value<string>(s)).toBe('gpt-4o')
  })

  it('falls back to the readable action_type when nothing else is present', () => {
    const s = payloadSummary(JSON.stringify({ action_type: 'TOOL_CALL', source: 'sdk' }))
    expect(value(s)).toBe('TOOL_CALL')
  })

  // ── AAASM-5119: no more 100-character raw JSON dumps ─────────────────────
  it('reports an absence rather than dumping raw JSON', () => {
    const s = payloadSummary(JSON.stringify({ event_id: 'e', source: 'sdk', action_type: 7 }))
    expect(isKnown(s)).toBe(false)
    expect(s).toMatchObject({ state: 'unknown' })
  })

  it('reports an absence for a null detail', () => {
    expect(payloadSummary('{"detail":null}')).toMatchObject({ known: false })
  })

  it('reports an absence for an unrecognised detail kind', () => {
    expect(payloadSummary('{"detail":{"kind":"mystery"}}')).toMatchObject({ known: false })
  })

  it('reports an absence for malformed JSON', () => {
    expect(payloadSummary('not-json')).toMatchObject({ known: false, state: 'unknown' })
  })

  it('reports an absence for a JSON array payload', () => {
    expect(payloadSummary('[1,2,3]')).toMatchObject({ known: false })
  })
})

describe('extractTraceId', () => {
  it('reads a non-empty trace_id from the payload', () => {
    expect(value(extractTraceId('{"trace_id":"trace-abc"}'))).toBe('trace-abc')
  })

  it('reports an absence when trace_id is missing', () => {
    expect(extractTraceId('{"model":"gpt-4o"}')).toMatchObject({ known: false })
  })

  it('reports an absence for an empty-string trace_id', () => {
    expect(extractTraceId('{"trace_id":""}')).toMatchObject({ known: false })
  })

  it('reports an absence for malformed JSON', () => {
    expect(extractTraceId('not-json')).toMatchObject({ known: false, state: 'unknown' })
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

describe('auditCoverage / coverageStatement', () => {
  function window_(partial: Partial<AuditLogWindow>): AuditLogWindow {
    return {
      entries: [],
      total: { known: true, value: 0 },
      pagesFetched: 1,
      capped: false,
      ...partial,
    }
  }

  function rows(n: number): LogEntry[] {
    return Array.from({ length: n }, (_, i) => ({
      seq: i,
      timestamp: '2026-07-26T10:00:00Z',
      agent_id: 'a',
      session_id: 's',
      event_type: 'ToolCallIntercepted',
      payload: '{}',
    }))
  }

  it('reports completeness only when the whole filtered set is loaded', () => {
    const c = auditCoverage(window_({ entries: rows(12), total: { known: true, value: 12 } }))
    expect(c.complete).toBe(true)
    expect(c.moreAvailable).toBe(false)
    expect(coverageStatement(c)).toContain('Complete')
  })

  it('never claims completeness while rows remain', () => {
    const c = auditCoverage(window_({ entries: rows(50), total: { known: true, value: 4820 } }))
    expect(c.complete).toBe(false)
    expect(c.moreAvailable).toBe(true)
    const statement = coverageStatement(c)
    expect(statement).toContain('Partial — 50 of 4820')
    expect(statement).toContain('not the complete trail')
    expect(statement).not.toContain('Complete')
  })

  it('says so when the page-fetch ceiling was hit rather than capping silently', () => {
    const c = auditCoverage(
      window_({ entries: rows(2000), total: { known: true, value: 9000 }, capped: true }),
    )
    expect(c.capped).toBe(true)
    expect(c.moreAvailable).toBe(false)
    expect(coverageStatement(c)).toContain('page-fetch limit was reached')
  })

  it('refuses to claim completeness when the gateway reported no total', () => {
    const c = auditCoverage(
      window_({ entries: rows(30), total: { known: false, state: 'unknown' } }),
    )
    expect(c.complete).toBe(false)
    expect(coverageStatement(c)).toContain('Coverage unknown')
  })

  it('reports the audit log as unavailable before any window exists', () => {
    const c = auditCoverage(undefined)
    expect(c.complete).toBe(false)
    expect(c.total).toMatchObject({ known: false, state: 'unavailable' })
    // Distinct from "the gateway gave us no total": nothing was read at all.
    expect(coverageStatement(c)).toContain('Coverage unavailable')
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

  function pageOf(items: LogEntry[], total: number, page = 1) {
    return { data: { items, page, per_page: AUDIT_PAGE_SIZE, total } }
  }

  function rows(n: number, from = 0): LogEntry[] {
    return Array.from({ length: n }, (_, i) => ({
      seq: from + i,
      timestamp: '2026-07-26T10:00:00Z',
      agent_id: 'a',
      session_id: 's',
      event_type: 'ToolCallIntercepted',
      payload: '{}',
    }))
  }

  it('requests the gateway maximum per_page instead of accepting the 50-row default', async () => {
    get.mockResolvedValue(pageOf([], 0))
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', {
      params: { query: { page: 1, per_page: AUDIT_PAGE_SIZE } },
    })
  })

  it('forwards agent and event-type filters as query params', async () => {
    get.mockResolvedValue(pageOf([], 0))
    const { result } = renderHook(
      () => useAuditLogQuery({ agentId: 'abc123', eventType: 'PolicyViolation' }),
      { wrapper: makeWrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledWith('/api/v1/logs', {
      params: {
        query: {
          page: 1,
          per_page: AUDIT_PAGE_SIZE,
          agent_id: 'abc123',
          event_type: 'PolicyViolation',
        },
      },
    })
  })

  it('surfaces the envelope total so the caller can see what it is missing', async () => {
    get.mockResolvedValue(pageOf(rows(AUDIT_PAGE_SIZE), 4820))
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.entries).toHaveLength(AUDIT_PAGE_SIZE)
    expect(result.current.data?.total).toEqual({ known: true, value: 4820 })
  })

  it('concatenates the requested number of pages', async () => {
    get.mockResolvedValueOnce(pageOf(rows(AUDIT_PAGE_SIZE), 250, 1))
    get.mockResolvedValueOnce(pageOf(rows(AUDIT_PAGE_SIZE, AUDIT_PAGE_SIZE), 250, 2))
    const { result } = renderHook(() => useAuditLogQuery({ pages: 2 }), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.entries).toHaveLength(2 * AUDIT_PAGE_SIZE)
    expect(result.current.data?.pagesFetched).toBe(2)
    expect(get).toHaveBeenCalledTimes(2)
  })

  it('stops early on a short page rather than issuing a pointless request', async () => {
    get.mockResolvedValueOnce(pageOf(rows(3), 3, 1))
    const { result } = renderHook(() => useAuditLogQuery({ pages: 5 }), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledTimes(1)
    expect(result.current.data?.capped).toBe(false)
  })

  it('clamps the requested depth to the page-fetch ceiling', async () => {
    get.mockResolvedValue(pageOf(rows(AUDIT_PAGE_SIZE), 1_000_000))
    const { result } = renderHook(() => useAuditLogQuery({ pages: 999 }), {
      wrapper: makeWrapper(),
    })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(get).toHaveBeenCalledTimes(AUDIT_MAX_PAGES)
    expect(result.current.data?.capped).toBe(true)
  })

  it('reports an unknown total when the gateway omits it', async () => {
    get.mockResolvedValue({ data: { items: [], page: 1, per_page: AUDIT_PAGE_SIZE } })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.total).toMatchObject({ known: false, state: 'unknown' })
  })

  it('throws when the gateway returns an error', async () => {
    get.mockResolvedValue({ error: { message: 'boom' } })
    const { result } = renderHook(() => useAuditLogQuery(), { wrapper: makeWrapper() })
    await waitFor(() => expect(result.current.isError).toBe(true))
    expect(result.current.error?.message).toBe('Failed to fetch audit log')
  })
})
