import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { absent, known } from '../../lib/truthfulness'
import { buildTraceExport, downloadTraceJson } from './export'
import { traceExportSchema } from './exportSchema'
import type { TraceEvent, TraceSeverity } from './types'

const NOT_ON_TRACE_SPAN =
  'TraceSpan carries only span_id, parent_span_id, operation, decision and timestamps'

const NEVER_MEASURED = 'This span recorded no end time, so its duration was never measured'

/** Held separately so the copy-not-alias assertion has an identity to compare against. */
const REDACTED_FIELDS = ['user_id']

const EVENTS: TraceEvent[] = [
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
    redactedFields: known(REDACTED_FIELDS),
    violationReason: known('refund > $100'),
  },
  {
    // Shaped as `mapSpanToEvent` builds it from a real `TraceSpan`: everything
    // the span schema cannot carry is an explicit absence, not an omitted key.
    id: 'evt-2',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'ToolCallIntercepted',
    agent: 'support-agent',
    parentSpanId: 'evt-1',
    durationMs: absent<number>('unknown', NEVER_MEASURED),
    decision: absent<string>('not-evaluated', 'This span recorded no governance decision'),
    payloadPreview: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
    payload: absent<unknown>('not-supported', NOT_ON_TRACE_SPAN),
    severity: absent<TraceSeverity>('not-supported', NOT_ON_TRACE_SPAN),
    redactedFields: absent<readonly string[]>('not-supported', NOT_ON_TRACE_SPAN),
    violationReason: absent<string>('not-supported', NOT_ON_TRACE_SPAN),
  },
]

describe('buildTraceExport', () => {
  it('returns an object that parses against traceExportSchema', () => {
    const fixedNow = new Date('2026-05-13T22:00:00.000Z')
    const result = buildTraceExport('agent-001', 'session-abc', EVENTS, fixedNow)

    expect(() => traceExportSchema.parse(result)).not.toThrow()
    expect(result.version).toBe('2')
    expect(result.exportedAt).toBe('2026-05-13T22:00:00.000Z')
    expect(result.agentId).toBe('agent-001')
    expect(result.sessionId).toBe('session-abc')
    expect(result.events).toHaveLength(2)
  })

  it('always includes every event (filtering is a view concern)', () => {
    const result = buildTraceExport('a', 's', EVENTS)
    expect(result.events.map(e => e.id)).toEqual(['evt-1', 'evt-2'])
  })

  it('returns event copies (no aliasing with the input array)', () => {
    const result = buildTraceExport('a', 's', EVENTS)
    expect(result.events[0]).not.toBe(EVENTS[0])

    const exported = result.events[0].redactedFields
    expect(exported).not.toBe(EVENTS[0].redactedFields)
    if (!exported.known) throw new Error('expected the redacted field list to be known')
    // The array inside the envelope is copied too, not aliased.
    expect(exported.value).not.toBe(REDACTED_FIELDS)
    expect(exported.value).toEqual(['user_id'])
  })

  it('carries an absent redactedFields through with its state and detail intact', () => {
    const result = buildTraceExport('a', 's', EVENTS)
    expect(result.events[1].redactedFields).toEqual({
      known: false,
      state: 'not-supported',
      detail: NOT_ON_TRACE_SPAN,
    })
  })

  it('distinguishes a measured 0 duration from one that was never measured', () => {
    // The whole reason the format went to version 2: v1 wrote a bare number, so
    // "this span took 0 ms" and "this span's duration was never measured" both
    // landed in the file as `0` or a missing key. The envelope keeps them apart.
    const measured: TraceEvent = { ...EVENTS[0], id: 'zero', durationMs: known(0) }
    const unmeasured: TraceEvent = {
      ...EVENTS[0],
      id: 'never',
      durationMs: absent<number>('unknown', NEVER_MEASURED),
    }

    const written = JSON.parse(
      JSON.stringify(buildTraceExport('a', 's', [measured, unmeasured])),
    ) as { version: string; events: { id: string; durationMs: unknown }[] }

    expect(written.version).toBe('2')
    expect(written.events[0].durationMs).toEqual({ known: true, value: 0 })
    expect(written.events[1].durationMs).toEqual({
      known: false,
      state: 'unknown',
      detail: NEVER_MEASURED,
    })
  })
})

describe('downloadTraceJson', () => {
  let createObjectURL: ReturnType<typeof vi.fn>
  let revokeObjectURL: ReturnType<typeof vi.fn>
  let originalCreate: typeof URL.createObjectURL
  let originalRevoke: typeof URL.revokeObjectURL

  beforeEach(() => {
    createObjectURL = vi.fn().mockReturnValue('blob:fake-url')
    revokeObjectURL = vi.fn()
    originalCreate = URL.createObjectURL
    originalRevoke = URL.revokeObjectURL
    URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL
    URL.revokeObjectURL = revokeObjectURL as unknown as typeof URL.revokeObjectURL
  })

  afterEach(() => {
    URL.createObjectURL = originalCreate
    URL.revokeObjectURL = originalRevoke
    vi.restoreAllMocks()
  })

  it('creates a blob URL, clicks a hidden anchor, and revokes the URL', () => {
    const clickSpy = vi.fn()
    const originalCreateElement = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
      const el = originalCreateElement(tagName)
      if (tagName === 'a') {
        el.click = clickSpy
      }
      return el
    })

    downloadTraceJson('agent-001', 'session-abc', EVENTS)

    expect(createObjectURL).toHaveBeenCalledOnce()
    const blob = createObjectURL.mock.calls[0][0] as Blob
    expect(blob.type).toBe('application/json')

    expect(clickSpy).toHaveBeenCalledOnce()
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:fake-url')
  })

  it('names the download `trace-<agentId>-<sessionId>.json`', () => {
    let capturedAnchor: HTMLAnchorElement | null = null
    const originalCreateElement = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
      const el = originalCreateElement(tagName)
      if (tagName === 'a') {
        capturedAnchor = el as HTMLAnchorElement
        el.click = vi.fn()
      }
      return el
    })

    downloadTraceJson('agent-001', 'session-abc', EVENTS)

    expect(capturedAnchor).not.toBeNull()
    expect(capturedAnchor!.download).toBe('trace-agent-001-session-abc.json')
  })

  it('writes JSON whose content parses against traceExportSchema', async () => {
    let blobText = ''
    createObjectURL.mockImplementation((blob: Blob) => {
      blob.text().then(text => { blobText = text })
      return 'blob:fake-url'
    })
    const originalCreateElement = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tagName: string) => {
      const el = originalCreateElement(tagName)
      if (tagName === 'a') el.click = vi.fn()
      return el
    })

    downloadTraceJson('agent-001', 'session-abc', EVENTS)

    // Blob.text() is async; flush microtasks.
    await new Promise(r => setTimeout(r, 0))
    const parsed = JSON.parse(blobText)
    expect(() => traceExportSchema.parse(parsed)).not.toThrow()
    expect(parsed.events).toHaveLength(2)
    // The downloaded file states why a value is missing, not merely that it is.
    expect(parsed.events[1].payloadPreview).toEqual({
      known: false,
      state: 'not-supported',
      detail: NOT_ON_TRACE_SPAN,
    })
  })
})
