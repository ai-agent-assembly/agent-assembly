import { isKnown, known, propagateAbsence, type Certain } from '../../lib/truthfulness'
import type { TraceEvent } from './types'
import type { TraceExport } from './exportSchema'

/**
 * Copy a certain readonly array into the mutable shape the inferred
 * `TraceExport` type uses. Same data, no aliasing; an absence passes through
 * with its state and detail intact.
 */
function exportableList(value: Certain<readonly string[]>): Certain<string[]> {
  return isKnown(value) ? known([...value.value]) : propagateAbsence(value)
}

/**
 * Build a versioned, schema-shaped trace export object from raw events.
 * Pure function so it can be unit-tested without DOM access.
 *
 * The `Certain` envelopes are written out as-is, so the downloaded file states
 * which values the gateway actually supplied and why the rest are missing.
 */
export function buildTraceExport(
  agentId: string,
  sessionId: string,
  events: readonly TraceEvent[],
  now: Date = new Date(),
): TraceExport {
  return {
    version: '2',
    exportedAt: now.toISOString(),
    agentId,
    sessionId,
    events: events.map(e => ({
      ...e,
      redactedFields: exportableList(e.redactedFields),
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
  anchor.remove()
  URL.revokeObjectURL(url)
}
