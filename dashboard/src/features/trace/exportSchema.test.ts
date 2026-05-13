import { describe, expect, it } from 'vitest'
import { traceExportSchema, type TraceExport } from './exportSchema'

const VALID_EXPORT: TraceExport = {
  version: '1',
  exportedAt: '2026-05-13T22:00:00.000Z',
  agentId: 'agent-001',
  sessionId: 'session-abc',
  events: [
    {
      id: 'evt-1',
      timestamp: '2026-04-23T14:23:01Z',
      type: 'policy_violation',
      agent: 'support-agent',
      durationMs: 12,
      payloadPreview: 'preview',
      payload: { foo: 'bar' },
      severity: 'critical',
      redactedFields: ['user_id'],
      violationReason: 'refund > $100',
    },
  ],
}

describe('traceExportSchema', () => {
  it('parses a valid export without error', () => {
    expect(() => traceExportSchema.parse(VALID_EXPORT)).not.toThrow()
  })

  it('parses an export with zero events', () => {
    const empty = { ...VALID_EXPORT, events: [] }
    expect(() => traceExportSchema.parse(empty)).not.toThrow()
  })

  it('rejects an export missing the version literal', () => {
    const { version: _omit, ...broken } = VALID_EXPORT
    void _omit
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects an export whose exportedAt is not ISO-8601', () => {
    const broken = { ...VALID_EXPORT, exportedAt: 'yesterday' }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects an event with an unknown severity string', () => {
    const broken = {
      ...VALID_EXPORT,
      events: [{ ...VALID_EXPORT.events[0], severity: 'fatal' as unknown as 'critical' }],
    }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('accepts events without optional severity / redactedFields / violationReason', () => {
    const minimal = {
      ...VALID_EXPORT,
      events: [
        {
          id: 'evt-2',
          timestamp: '2026-04-23T14:23:01Z',
          type: 'llm_call',
          agent: 'support-agent',
          durationMs: 100,
          payloadPreview: 'preview',
          payload: {},
        },
      ],
    }
    expect(() => traceExportSchema.parse(minimal)).not.toThrow()
  })
})
