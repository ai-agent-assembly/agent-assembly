import { extractDecision, payloadSummary, type LogEntry } from './logs'

/**
 * Client-side export helpers for the Audit Log page (AAASM-5022).
 *
 * Both artifacts are generated entirely in the browser from the rows the page
 * has already loaded and filtered — there is **no** server-side export or
 * compliance-report endpoint on the gateway today. The pure `build*` functions
 * are DOM-free so they can be unit-tested; the `download*` wrappers add the
 * `<a download>` + `URL.createObjectURL` plumbing (same approach as
 * `features/trace/export.ts`).
 */

/** Columns emitted by the CSV export, in order. */
const CSV_HEADER = [
  'seq',
  'timestamp',
  'agent_id',
  'event_type',
  'decision',
  'summary',
  'session_id',
] as const

/** RFC 4180 cell escaping: quote a field only when it contains a delimiter. */
function csvCell(value: unknown): string {
  const s = value == null ? '' : String(value)
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/**
 * Serialize the given (already-filtered) rows to a CSV string. The `decision`
 * and `summary` columns are derived from the payload the same way the table
 * renders them, so the file matches what the operator sees on screen.
 */
export function buildAuditCsv(rows: readonly LogEntry[]): string {
  const lines = [CSV_HEADER.join(',')]
  for (const e of rows) {
    lines.push(
      [
        e.seq,
        e.timestamp,
        e.agent_id,
        e.event_type,
        extractDecision(e.payload) ?? '',
        payloadSummary(e.event_type, e.payload),
        e.session_id,
      ]
        .map(csvCell)
        .join(','),
    )
  }
  return lines.join('\r\n')
}

/** Describes the filters in effect when an export is triggered. */
export interface AuditExportContext {
  readonly typeFilter: string
  readonly agentFilter: string
  readonly search: string
}

/**
 * Build a human-readable compliance summary over the currently-filtered rows:
 * the window's event-type breakdown, decision verdicts, and the full list of
 * policy violations. This is a real report derived from the loaded data, not a
 * placeholder — but it is scoped to the fetched window because no dedicated
 * compliance endpoint exists yet.
 */
export function buildComplianceReport(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  now: Date = new Date(),
): string {
  const typeCounts: Record<string, number> = {}
  const decisionCounts: Record<string, number> = {}
  const violations: LogEntry[] = []
  for (const e of rows) {
    typeCounts[e.event_type] = (typeCounts[e.event_type] ?? 0) + 1
    const decision = extractDecision(e.payload)
    if (decision) decisionCounts[decision] = (decisionCounts[decision] ?? 0) + 1
    if (e.event_type === 'PolicyViolation') violations.push(e)
  }
  const agents = Array.from(new Set(rows.map((e) => e.agent_id))).sort()

  const lines: string[] = []
  lines.push('# Audit Compliance Report')
  lines.push('')
  lines.push(`Generated: ${now.toISOString()}`)
  lines.push(
    `Scope: type=${ctx.typeFilter}, agent=${ctx.agentFilter}, search=${ctx.search || '(none)'}`,
  )
  lines.push(`Total events in report: ${rows.length}`)
  lines.push(`Agents covered: ${agents.length ? agents.join(', ') : '(none)'}`)
  lines.push('')
  lines.push('## Events by type')
  for (const [type, count] of Object.entries(typeCounts).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${type}: ${count}`)
  }
  lines.push('')
  lines.push('## Decision verdicts')
  const decisionEntries = Object.entries(decisionCounts).sort((a, b) => b[1] - a[1])
  if (decisionEntries.length === 0) {
    lines.push('- (no explicit verdicts)')
  } else {
    for (const [decision, count] of decisionEntries) lines.push(`- ${decision}: ${count}`)
  }
  lines.push('')
  lines.push(`## Policy violations (${violations.length})`)
  if (violations.length === 0) {
    lines.push('- None in scope.')
  } else {
    for (const v of violations) {
      lines.push(`- [${v.timestamp}] ${v.agent_id}: ${payloadSummary(v.event_type, v.payload)}`)
    }
  }
  lines.push('')
  return lines.join('\n')
}

/** Trigger a browser download of `text` under `filename` with the given MIME. */
function downloadText(text: string, filename: string, mime: string): void {
  const blob = new Blob([text], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

/** File-safe UTC timestamp fragment (`2026-05-11T140211Z`) for export names. */
function stamp(now: Date): string {
  return now.toISOString().replace(/[:.]/g, '').replace(/(\.\d+)?$/, '')
}

/** Download the filtered rows as a CSV file. */
export function downloadAuditCsv(rows: readonly LogEntry[], now: Date = new Date()): void {
  downloadText(buildAuditCsv(rows), `audit-log-${stamp(now)}.csv`, 'text/csv;charset=utf-8')
}

/** Download the compliance summary as a Markdown file. */
export function downloadComplianceReport(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  now: Date = new Date(),
): void {
  downloadText(
    buildComplianceReport(rows, ctx, now),
    `compliance-report-${stamp(now)}.md`,
    'text/markdown;charset=utf-8',
  )
}
