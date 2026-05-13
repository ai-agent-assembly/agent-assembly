import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { buildTraceExport, downloadTraceJson } from './export'
import { traceExportSchema } from './exportSchema'
import type { TraceEvent } from './types'

const EVENTS: TraceEvent[] = [
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
  {
    id: 'evt-2',
    timestamp: '2026-04-23T14:23:02Z',
    type: 'llm_call',
    agent: 'support-agent',
    durationMs: 100,
    payloadPreview: 'preview',
    payload: {},
  },
]

describe('buildTraceExport', () => {
  it('returns an object that parses against traceExportSchema', () => {
    const fixedNow = new Date('2026-05-13T22:00:00.000Z')
    const result = buildTraceExport('agent-001', 'session-abc', EVENTS, fixedNow)

    expect(() => traceExportSchema.parse(result)).not.toThrow()
    expect(result.version).toBe('1')
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
    expect(result.events[0].redactedFields).not.toBe(EVENTS[0].redactedFields)
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
  })
})
