import {
  coverageStatement,
  extractVerdict,
  isSuppressedDenial,
  payloadSummary,
  type AuditCoverage,
  type AuditVerdict,
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
  'dry_run',
  'suppressed_decision',
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
 * The `decision` cell for one row.
 *
 * A row whose denial was suppressed by observe mode does **not** render as a
 * bare `ALLOW`. The suffix is deliberately inside the same cell rather than only
 * in the neighbouring `suppressed_decision` column: the first thing anyone does
 * with an audit CSV is filter or pivot on `decision`, and a naive
 * `decision == "ALLOW"` must not silently sweep up suppressed denials. Failing
 * that filter closed — the row simply does not match `ALLOW` — is the safe
 * direction. The machine-readable split stays available in the two columns
 * beside it.
 */
function csvDecision(verdict: AuditVerdict): string {
  const enforced = csvCertain(verdict.enforced)
  if (!isSuppressedDenial(verdict)) return enforced
  const suppressed = csvCertain(verdict.suppressed as Certain<string>)
  return `${enforced} (observe-mode; suppressed ${suppressed})`
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
    const verdict = extractVerdict(e.payload)
    lines.push(
      [
        e.seq,
        e.timestamp,
        e.agent_id,
        e.event_type,
        csvDecision(verdict),
        String(verdict.dryRun),
        verdict.suppressed ? csvCertain(verdict.suppressed) : '',
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

/** One row's summary as report text, folding an absence to its state label. */
function summaryText(entry: LogEntry): string {
  const summary = payloadSummary(entry.payload)
  return isKnown(summary) ? summary.value : TRUTH_STATE_META[summary.state].label
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
/**
 * Everything the report needs, derived from the rows in one pass.
 *
 * Kept as a single tally rather than recomputed per section so the sections
 * cannot disagree — a "Policy violations (0)" heading over a body listing two
 * suppressed denials would be a worse failure than either number alone.
 */
interface ReportTally {
  readonly typeCounts: Record<string, number>
  readonly decisionCounts: Record<string, number>
  readonly noVerdictCounts: Record<string, number>
  readonly suppressedCounts: Record<string, number>
  readonly violations: LogEntry[]
  readonly suppressed: { entry: LogEntry; verdict: AuditVerdict }[]
  readonly agents: string[]
}

/** The verdict key a row is counted under in the "Decision verdicts" table. */
function verdictTallyKey(verdict: AuditVerdict, enforced: string): string {
  // A suppressed denial is tallied under its own key rather than folded into the
  // enforced ALLOW total. "ALLOW: 40" over an observe-mode window is the
  // fabricated all-clear this report exists to prevent.
  if (!isSuppressedDenial(verdict)) return enforced
  return `${enforced} (observe-mode; suppressed ${csvCertain(verdict.suppressed as Certain<string>)})`
}

function tallyRows(rows: readonly LogEntry[]): ReportTally {
  const typeCounts: Record<string, number> = {}
  const decisionCounts: Record<string, number> = {}
  const noVerdictCounts: Record<string, number> = {}
  const suppressedCounts: Record<string, number> = {}
  const violations: LogEntry[] = []
  const suppressed: { entry: LogEntry; verdict: AuditVerdict }[] = []

  for (const e of rows) {
    typeCounts[e.event_type] = (typeCounts[e.event_type] ?? 0) + 1
    const verdict = extractVerdict(e.payload)
    const wasSuppressed = isSuppressedDenial(verdict)

    if (isKnown(verdict.enforced)) {
      const key = verdictTallyKey(verdict, verdict.enforced.value)
      decisionCounts[key] = (decisionCounts[key] ?? 0) + 1
    } else {
      const label = TRUTH_STATE_META[verdict.enforced.state].label
      noVerdictCounts[label] = (noVerdictCounts[label] ?? 0) + 1
    }

    if (wasSuppressed) {
      const label = csvCertain(verdict.suppressed as Certain<string>)
      suppressedCounts[label] = (suppressedCounts[label] ?? 0) + 1
      suppressed.push({ entry: e, verdict })
    }

    // A denial suppressed by observe mode IS a policy violation — the gateway
    // simply recorded it under the rewritten event type
    // (`policy_service.rs:891`). Counting only `PolicyViolation` rows would let
    // this section report zero over a window full of blocked-but-permitted
    // actions.
    if (e.event_type === 'PolicyViolation' || wasSuppressed) violations.push(e)
  }

  return {
    typeCounts,
    decisionCounts,
    noVerdictCounts,
    suppressedCounts,
    violations,
    suppressed,
    // Explicit comparator so the agent list is ordered locale-safely and stably
    // rather than by raw UTF-16 code units (S2871).
    agents: Array.from(new Set(rows.map((e) => e.agent_id))).sort((a, b) => a.localeCompare(b)),
  }
}

/** Descending by count — the order every tally table in the report uses. */
function byCountDesc(counts: Record<string, number>): [string, number][] {
  return Object.entries(counts).sort((a, b) => b[1] - a[1])
}

/**
 * The title carries every caveat that applies, so a reader who sees only the
 * first line of the file still knows what they are holding.
 */
function reportTitle(coverage: AuditCoverage, tally: ReportTally): string {
  const caveats = [
    coverage.complete ? null : 'PARTIAL WINDOW',
    tally.suppressed.length > 0 ? 'OBSERVE MODE' : null,
  ].filter(Boolean)
  if (caveats.length === 0) return '# Audit Compliance Report'
  return `# Audit Compliance Report — ${caveats.join(', ')}`
}

function observeModeBanner(tally: ReportTally): string[] {
  const n = tally.suppressed.length
  if (n === 0) return []
  const subject = n === 1 ? 'entry in this window was' : 'entries in this window were'
  return [
    `> **${n} ${subject} allowed only because enforcement was off.**`,
    '> Observe mode rewrote the decision to ALLOW and recorded the verdict it',
    '> suppressed. Those rows are NOT allows, and the actions they describe were',
    '> not blocked. See "Suppressed by observe mode" below.',
    '',
  ]
}

function partialWindowBanner(coverage: AuditCoverage): string[] {
  if (coverage.complete) return []
  return [
    '> **This report does not cover the complete audit trail.** It is derived',
    '> from the entries currently loaded in the dashboard, not from the whole',
    '> immutable record. Every count below is scoped accordingly.',
    '',
  ]
}

function reportHeader(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  coverage: AuditCoverage,
  tally: ReportTally,
  now: Date,
): string[] {
  const filterTotal = isKnown(coverage.total)
    ? String(coverage.total.value)
    : 'unknown (the gateway reported no total)'
  return [
    `Generated: ${now.toISOString()}`,
    `Scope: type=${ctx.typeFilter}, agent=${ctx.agentFilter}, search=${ctx.search || '(none)'}`,
    `Coverage: ${coverageStatement(coverage)}`,
    `Entries in this report: ${rows.length}`,
    `Entries loaded from the gateway: ${coverage.loaded}`,
    `Entries matching the server-side filter: ${filterTotal}`,
    `Agents covered (audit id digests): ${tally.agents.length ? tally.agents.join(', ') : '(none)'}`,
  ]
}

function eventsByTypeSection(tally: ReportTally): string[] {
  return [
    '## Events by type',
    ...byCountDesc(tally.typeCounts).map(([type, count]) => `- ${type}: ${count}`),
  ]
}

function decisionVerdictsSection(tally: ReportTally): string[] {
  const decisions = byCountDesc(tally.decisionCounts)
  const body =
    decisions.length === 0
      ? ['- (no entry in this window carries a policy verdict)']
      : decisions.map(([decision, count]) => `- ${decision}: ${count}`)

  const noVerdict = byCountDesc(tally.noVerdictCounts)
  const noVerdictBlock =
    noVerdict.length === 0
      ? []
      : [
          '',
          '### Entries carrying no verdict',
          ...noVerdict.map(([label, count]) => `- ${label}: ${count}`),
        ]

  return ['## Decision verdicts', ...body, ...noVerdictBlock]
}

function suppressedSection(tally: ReportTally): string[] {
  const heading = `## Suppressed by observe mode (${tally.suppressed.length})`
  if (tally.suppressed.length === 0) {
    return [heading, '- No entry in this window had a verdict suppressed by observe mode.']
  }
  const counts = byCountDesc(tally.suppressedCounts).map(
    ([label, count]) => `- Would have been ${label}: ${count}`,
  )
  const entries = tally.suppressed.map(({ entry, verdict }) => {
    const why = verdict.suppressedReason ?? summaryText(entry)
    const wouldHaveBeen = csvCertain(verdict.suppressed as Certain<string>)
    return `- [${entry.timestamp}] ${entry.agent_id} — recorded as ${entry.event_type}, would have been ${wouldHaveBeen}: ${why}`
  })
  return [heading, ...counts, '', ...entries]
}

function violationsSection(tally: ReportTally, coverage: AuditCoverage): string[] {
  const heading = `## Policy violations (${tally.violations.length})`
  if (tally.violations.length > 0) {
    return [heading, ...tally.violations.map((v) => `- [${v.timestamp}] ${v.agent_id}: ${summaryText(v)}`)]
  }
  // "None" is a claim about the window, never about the trail — saying it
  // unqualified over a partial window is how a review concludes there were no
  // violations when the window simply stopped short. It is also only sayable at
  // all because suppressed denials are counted into `violations` above.
  return [
    heading,
    coverage.complete
      ? '- None among the entries matching the current filter, and no verdict was suppressed by observe mode.'
      : '- None in the loaded window. This does NOT mean there were none in the trail.',
  ]
}

/**
 * Build a human-readable compliance summary over the currently-filtered rows:
 * the window's event-type breakdown, decision verdicts, suppressed verdicts, and
 * the full list of policy violations.
 *
 * Every count in it is scoped to the loaded window, which the report says in its
 * title, in its first section, and again above each count that a partial window
 * could make misleading. The report is a real derivation of the loaded data — it
 * is not, and does not claim to be, the complete governance record, because no
 * server-side compliance endpoint exists to produce one.
 *
 * Assembled by composing section builders rather than by appending to a buffer:
 * each section is independently readable and testable, and the document's shape
 * is visible in one place instead of having to be reconstructed by following
 * fifty `push` calls through two levels of branching.
 */
export function buildComplianceReport(
  rows: readonly LogEntry[],
  ctx: AuditExportContext,
  coverage: AuditCoverage,
  now: Date = new Date(),
): string {
  const tally = tallyRows(rows)
  return [
    reportTitle(coverage, tally),
    '',
    ...observeModeBanner(tally),
    ...partialWindowBanner(coverage),
    ...reportHeader(rows, ctx, coverage, tally, now),
    '',
    ...eventsByTypeSection(tally),
    '',
    ...decisionVerdictsSection(tally),
    '',
    ...suppressedSection(tally),
    '',
    ...violationsSection(tally, coverage),
    '',
  ].join('\n')
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
