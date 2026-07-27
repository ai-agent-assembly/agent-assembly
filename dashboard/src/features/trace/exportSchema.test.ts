import { describe, expect, it } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { traceExportSchema, type TraceExport } from './exportSchema'
import type { TraceSeverity } from './types'

const NOT_ON_TRACE_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

const VALID_EXPORT: TraceExport = {
  version: '2',
  exportedAt: '2026-05-13T22:00:00.000Z',
  agentId: 'agent-001',
  sessionId: 'session-abc',
  events: [
    {
      id: 'evt-1',
      timestamp: '2026-04-23T14:23:01Z',
      type: 'PolicyViolation',
      agent: 'support-agent',
      parentSpanId: null,
      durationMs: known(12),
      decision: known('deny'),
      payloadPreview: known('preview'),
      payload: known({ foo: 'bar' }),
      severity: known<TraceSeverity>('critical'),
      redactedFields: known(['user_id']),
      violationReason: known('refund > $100'),
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
    const broken: Partial<TraceExport> = { ...VALID_EXPORT }
    delete broken.version
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects a v1 export, which had no way to say why a value was missing', () => {
    const v1 = { ...VALID_EXPORT, version: '1' }
    expect(() => traceExportSchema.parse(v1)).toThrow()
  })

  it('rejects an export whose exportedAt is not ISO-8601', () => {
    const broken = { ...VALID_EXPORT, exportedAt: 'yesterday' }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects a bare value where a Certain envelope is required', () => {
    // The v1 shape: a naked number that cannot distinguish 0 from unmeasured.
    const broken = {
      ...VALID_EXPORT,
      events: [{ ...VALID_EXPORT.events[0], durationMs: 12 }],
    }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects an event with an unknown severity string inside the envelope', () => {
    const broken = {
      ...VALID_EXPORT,
      events: [{ ...VALID_EXPORT.events[0], severity: { known: true, value: 'fatal' } }],
    }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('rejects an absence whose state is not part of the truthfulness vocabulary', () => {
    const broken = {
      ...VALID_EXPORT,
      events: [
        { ...VALID_EXPORT.events[0], violationReason: { known: false, state: 'missing' } },
      ],
    }
    expect(() => traceExportSchema.parse(broken)).toThrow()
  })

  it('accepts an event whose severity / redactedFields / violationReason are absences', () => {
    // What the real endpoint produces: `TraceSpan` has no field to source these
    // from, so they export as labelled absences rather than as omitted keys.
    const realShaped = {
      ...VALID_EXPORT,
      events: [
        {
          id: 'evt-2',
          timestamp: '2026-04-23T14:23:01Z',
          type: 'ToolCallIntercepted',
          agent: 'support-agent',
          parentSpanId: 'evt-1',
          durationMs: absent<number>(
            'unknown',
            'This span recorded no end time, so its duration was never measured',
          ),
          decision: absent<string>('not-evaluated', 'This span recorded no governance decision'),
          payloadPreview: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
          payload: absent<unknown>('not-supported', NOT_ON_TRACE_SPAN),
          severity: absent<TraceSeverity>('not-supported', NOT_ON_TRACE_SPAN),
          redactedFields: absent<string[]>('not-supported', NOT_ON_TRACE_SPAN),
          violationReason: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
        },
      ],
    }
    expect(() => traceExportSchema.parse(realShaped)).not.toThrow()
  })

  it('preserves the absence detail through a parse round-trip', () => {
    const parsed = traceExportSchema.parse({
      ...VALID_EXPORT,
      events: [
        {
          ...VALID_EXPORT.events[0],
          durationMs: absent<number>('unknown', 'This span recorded no end time'),
        },
      ],
    })
    expect(parsed.events[0].durationMs).toEqual({
      known: false,
      state: 'unknown',
      detail: 'This span recorded no end time',
    })
  })
})
