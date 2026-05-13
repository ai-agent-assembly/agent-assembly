import type { TraceEvent } from './types'
import type { TraceExport } from './exportSchema'

/**
 * Build a versioned, schema-shaped trace export object from raw events.
 * Pure function so it can be unit-tested without DOM access.
 */
export function buildTraceExport(
  agentId: string,
  sessionId: string,
  events: readonly TraceEvent[],
  now: Date = new Date(),
): TraceExport {
  return {
    version: '1',
    exportedAt: now.toISOString(),
    agentId,
    sessionId,
    // Spread to mutable copies — TraceEvent uses readonly arrays, the
    // schema-inferred TraceExport uses mutable arrays. Same data, no aliasing.
    events: events.map(e => ({
      ...e,
      redactedFields: e.redactedFields ? [...e.redactedFields] : undefined,
    })),
  }
}

/**
 * Trigger a JSON file download in the browser for the given trace.
 * Uses a hidden `<a download>` + `URL.createObjectURL` per AAASM-1071's
 * "how to approach" guidance. Revokes the object URL after the click
 * fires so we don't leak blob references.
 */
export function downloadTraceJson(
  agentId: string,
  sessionId: string,
  events: readonly TraceEvent[],
): void {
  const payload = buildTraceExport(agentId, sessionId, events)
  const json = JSON.stringify(payload, null, 2)
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = `trace-${agentId}-${sessionId}.json`
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
  URL.revokeObjectURL(url)
}
