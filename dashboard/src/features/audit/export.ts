import {
  coverageStatement,
  extractDecision,
  payloadSummary,
  type AuditCoverage,
  type LogEntry,
} from './logs'
import { TRUTH_STATE_META, isKnown, type Certain } from '../../lib/truthfulness'

/**
 * Client-side export helpers for the Audit Log page (AAASM-5022).
 *
 * Both artifacts are generated entirely in the browser from the rows the page
 * has already loaded and filtered — there is **no** server-side export or
 * compliance-report endpoint on the gateway today. The pure `build*` functions
 * are DOM-free so they can be unit-tested; the `download*` wrappers add the
 * `<a download>` + `URL.createObjectURL` plumbing (same approach as
 * `features/trace/export.ts`).
 *
 * ── Why every entry point takes an {@link AuditCoverage} (AAASM-5120) ───────
 *
 * These files were being handed the newest 50 rows and titled as the complete
 * immutable compliance trail. That is the most consequential lie this surface
 * can tell: a reviewer who reads "Policy violations (0)" over an unlabelled
 * window concludes there were none, when what happened is that the window
 * stopped short. Coverage is therefore a *required* argument rather than an
 * optional annotation — there is no call shape that produces an artifact which
 * fails to state what it covers.
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
  'export_scope',
] as const

/** RFC 4180 cell escaping: quote a field only when it contains a delimiter. */
function csvCell(value: unknown): string {
  const s = value == null ? '' : String(value)
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
}

/**
 * Render a possibly-absent value for a spreadsheet cell.
 *
 * An absence becomes its state label (`Not evaluated`, `Unknown`), never an
 * empty cell: a blank reads as "nothing happened here", which is precisely the
 * claim the data cannot support. The labels are also visibly not verdicts, so
 * they cannot be mistaken for one when the column is sorted or pivoted.
 */
function csvCertain<T>(value: Certain<T>): string {
  return isKnown(value) ? String(value.value) : TRUTH_STATE_META[value.state].label
}

/**
 * Compact machine-readable coverage tag, e.g. `partial:150/4820`.
 *
 * Repeated on every row rather than written once in a preamble: a CSV has no
 * comment syntax, and any header block a parser might carry is exactly what a
 * downstream `tail -n +2` or a spreadsheet re-save drops. A column survives
 * slicing, sorting, and copy-paste into another sheet.
 */
export function coverageTag(coverage: AuditCoverage): string {
  const total = isKnown(coverage.total) ? String(coverage.total.value) : 'unknown'
  if (coverage.complete) return `complete:${coverage.loaded}/${total}`
  return `${coverage.capped ? 'partial-capped' : 'partial'}:${coverage.loaded}/${total}`
}

/**
 * Serialize the given (already-filtered) rows to a CSV string.
 *
 * The `decision` and `summary` columns are derived from the payload the same
 * way the table renders them, so the file matches what the operator sees on
 * screen. `export_scope` states what fraction of the trail the file covers.
 */
export function buildAuditCsv(rows: readonly LogEntry[], coverage: AuditCoverage): string {
  const scope = coverageTag(coverage)
  const lines = [CSV_HEADER.join(',')]
  for (const e of rows) {
    lines.push(
      [
        e.seq,
        e.timestamp,
        e.agent_id,
        e.event_type,
        csvCertain(extractDecision(e.payload)),
        csvCertain(payloadSummary(e.payload)),
        e.session_id,
        scope,
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
 * policy violations.
 *
 * Every count in it is scoped to the loaded window, which the report says in
 * its title, in its first section, and again above each count that a partial
 * window could make misleading. The report is a real derivation of the loaded
 * data — it is not, and does not claim to be, the complete governance record,
 * because no server-side compliance endpoint exists to produce one.
 */
export function buildComplianceReport(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  coverage: AuditCoverage,
  now: Date = new Date(),
): string {
  const typeCounts: Record<string, number> = {}
  const decisionCounts: Record<string, number> = {}
  const noVerdictCounts: Record<string, number> = {}
  const violations: LogEntry[] = []
  for (const e of rows) {
    typeCounts[e.event_type] = (typeCounts[e.event_type] ?? 0) + 1
    const decision = extractDecision(e.payload)
    if (isKnown(decision)) {
      decisionCounts[decision.value] = (decisionCounts[decision.value] ?? 0) + 1
    } else {
      const label = TRUTH_STATE_META[decision.state].label
      noVerdictCounts[label] = (noVerdictCounts[label] ?? 0) + 1
    }
    if (e.event_type === 'PolicyViolation') violations.push(e)
  }
  // Explicit comparator so the agent list is ordered locale-safely and stably
  // rather than by raw UTF-16 code units (S2871).
  const agents = Array.from(new Set(rows.map((e) => e.agent_id))).sort((a, b) => a.localeCompare(b))

  const lines: string[] = []
  lines.push(
    coverage.complete
      ? '# Audit Compliance Report'
      : '# Audit Compliance Report — PARTIAL WINDOW',
  )
  lines.push('')
  if (!coverage.complete) {
    lines.push(
      '> **This report does not cover the complete audit trail.** It is derived',
    )
    lines.push(
      '> from the entries currently loaded in the dashboard, not from the whole',
    )
    lines.push('> immutable record. Every count below is scoped accordingly.')
    lines.push('')
  }
  lines.push(`Generated: ${now.toISOString()}`)
  lines.push(
    `Scope: type=${ctx.typeFilter}, agent=${ctx.agentFilter}, search=${ctx.search || '(none)'}`,
  )
  lines.push(`Coverage: ${coverageStatement(coverage)}`)
  lines.push(`Entries in this report: ${rows.length}`)
  lines.push(`Entries loaded from the gateway: ${coverage.loaded}`)
  lines.push(
    `Entries matching the server-side filter: ${
      isKnown(coverage.total) ? coverage.total.value : 'unknown (the gateway reported no total)'
    }`,
  )
  lines.push(`Agents covered (audit id digests): ${agents.length ? agents.join(', ') : '(none)'}`)
  lines.push('')
  lines.push('## Events by type')
  for (const [type, count] of Object.entries(typeCounts).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${type}: ${count}`)
  }
  lines.push('')
  lines.push('## Decision verdicts')
  const decisionEntries = Object.entries(decisionCounts).sort((a, b) => b[1] - a[1])
  if (decisionEntries.length === 0) {
    lines.push('- (no entry in this window carries a policy verdict)')
  } else {
    for (const [decision, count] of decisionEntries) lines.push(`- ${decision}: ${count}`)
  }
  const noVerdictEntries = Object.entries(noVerdictCounts).sort((a, b) => b[1] - a[1])
  if (noVerdictEntries.length > 0) {
    lines.push('')
    lines.push('### Entries carrying no verdict')
    for (const [label, count] of noVerdictEntries) lines.push(`- ${label}: ${count}`)
  }
  lines.push('')
  lines.push(`## Policy violations (${violations.length})`)
  if (violations.length === 0) {
    // "None" is a claim about the window, never about the trail — saying it
    // unqualified over a partial window is how a review concludes there were no
    // violations when the window simply stopped short.
    lines.push(
      coverage.complete
        ? '- None among the entries matching the current filter.'
        : '- None in the loaded window. This does NOT mean there were none in the trail.',
    )
  } else {
    for (const v of violations) {
      const summary = payloadSummary(v.payload)
      lines.push(
        `- [${v.timestamp}] ${v.agent_id}: ${
          isKnown(summary) ? summary.value : TRUTH_STATE_META[summary.state].label
        }`,
      )
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

/**
 * `complete` / `partial` filename fragment, so the coverage survives even when
 * the file is passed on with no context but its name.
 */
function scopeSlug(coverage: AuditCoverage): string {
  return coverage.complete ? 'complete' : 'partial'
}

/** Download the filtered rows as a CSV file. */
export function downloadAuditCsv(
  rows: readonly LogEntry[],
  coverage: AuditCoverage,
  now: Date = new Date(),
): void {
  downloadText(
    buildAuditCsv(rows, coverage),
    `audit-log-${scopeSlug(coverage)}-${stamp(now)}.csv`,
    'text/csv;charset=utf-8',
  )
}

/** Download the compliance summary as a Markdown file. */
export function downloadComplianceReport(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  coverage: AuditCoverage,
  now: Date = new Date(),
): void {
  downloadText(
    buildComplianceReport(rows, ctx, coverage, now),
    `compliance-report-${scopeSlug(coverage)}-${stamp(now)}.md`,
    'text/markdown;charset=utf-8',
  )
}
