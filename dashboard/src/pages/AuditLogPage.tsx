import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ignorePromise } from '../lib/ignorePromise'
import {
  AUDIT_EVENT_GROUPS,
  auditCoverage,
  auditEventHref,
  coverageStatement,
  eventGroupOf,
  extractTraceId,
  extractVerdict,
  isSuppressedDenial,
  payloadSummary,
  useAuditLogQuery,
  type AuditDecision,
  type AuditVerdict,
  type LogEntry,
} from '../features/audit/logs'
import { downloadAuditCsv, downloadComplianceReport } from '../features/audit/export'
import { AbsenceMarker, StatusState } from '../components/truthfulness'
import { isKnown, type Certain } from '../lib/truthfulness'
import { useToast } from '../components/Toast'
import './AuditLogPage.css'

/**
 * Display metadata per event type — label + chip variant for the table.
 *
 * One entry per `aa_core::audit::AuditEventType` variant (AAASM-5118). The
 * previous table listed six names invented by the hi-fi fixture, of which only
 * `PolicyViolation` exists on the backend.
 */
const EVENT_META = new Map<string, { label: string; chip: string; icon: string }>([
  ['ToolCallIntercepted', { label: 'Tool Call', chip: 'info', icon: '⚙' }],
  ['ToolDispatched', { label: 'Tool Dispatched', chip: 'info', icon: '⚙' }],
  ['PolicyViolation', { label: 'Policy Violation', chip: 'danger', icon: '⚑' }],
  ['MessageBlocked', { label: 'Message Blocked', chip: 'danger', icon: '⊘' }],
  ['CredentialLeakBlocked', { label: 'Credential Blocked', chip: 'danger', icon: '⊘' }],
  ['ApprovalRequested', { label: 'Approval Requested', chip: 'info', icon: '◷' }],
  ['ApprovalGranted', { label: 'Approval Granted', chip: 'ok', icon: '✓' }],
  ['ApprovalDenied', { label: 'Approval Denied', chip: 'danger', icon: '✕' }],
  ['ApprovalTimedOut', { label: 'Approval Timed Out', chip: 'warn', icon: '◷' }],
  ['ApprovalRouted', { label: 'Approval Routed', chip: 'info', icon: '⇄' }],
  ['ApprovalEscalated', { label: 'Approval Escalated', chip: 'warn', icon: '⇄' }],
  ['BudgetLimitApproached', { label: 'Budget Warning', chip: 'warn', icon: '◈' }],
  ['BudgetLimitExceeded', { label: 'Budget Exceeded', chip: 'danger', icon: '◈' }],
  ['AgentForceDeregistered', { label: 'Agent Deregistered', chip: 'warn', icon: '⊘' }],
  ['A2ACallIntercepted', { label: 'A2A Call', chip: 'info', icon: '⇥' }],
  ['A2AImpersonationAttempted', { label: 'A2A Impersonation', chip: 'danger', icon: '⚑' }],
  ['SandboxStarted', { label: 'Sandbox Started', chip: '', icon: '▣' }],
  ['SandboxFilesystemBlocked', { label: 'Sandbox FS Blocked', chip: 'danger', icon: '▣' }],
  ['SandboxCpuTimeout', { label: 'Sandbox CPU Timeout', chip: 'warn', icon: '▣' }],
  ['SandboxOomKilled', { label: 'Sandbox OOM Killed', chip: 'warn', icon: '▣' }],
  ['SandboxTerminated', { label: 'Sandbox Terminated', chip: '', icon: '▣' }],
  ['SandboxHostFnRateLimited', { label: 'Sandbox Rate Limited', chip: 'warn', icon: '▣' }],
])

/**
 * Chip variant + lowercased label for the decision verdict carried in the
 * payload. Keyed by the four real `assembly.common.v1.Decision` variants — the
 * mock's invented `APPROVE` key matched no proto variant and is gone.
 */
// AuditDecision is a closed 4-member app union; `readDecisionValue` in
// features/audit/logs.ts validates the wire payload into it before this table
// is ever indexed — narrow-union Record gap (AAASM-5245 gap 2).
// eslint-disable-next-line no-restricted-syntax
const DECISION_META: Record<AuditDecision, { chip: string; label: string }> = {
  ALLOW: { chip: 'ok', label: 'allow' },
  DENY: { chip: 'danger', label: 'deny' },
  PENDING: { chip: 'info', label: 'pending' },
  REDACT: { chip: 'scrub', label: 'redact' },
}

/**
 * Event families whose summary is machine output (identifiers, paths, hosts)
 * and reads better monospaced.
 */
const MONO_SUMMARY_GROUPS = new Set(['tool', 'sandbox', 'a2a'])

function chipClass(variant: string): string {
  return variant ? `audit-chip audit-chip--${variant}` : 'audit-chip'
}

function prettyPayload(payload: string): string {
  try {
    return JSON.stringify(JSON.parse(payload), null, 2)
  } catch {
    return payload
  }
}

/**
 * Shorten a 32-char audit id digest for display without hiding that it is a
 * digest. The full value stays in `title` and in the copy action.
 */
function shortDigest(hex: string): string {
  return hex.length > 14 ? `${hex.slice(0, 14)}…` : hex
}

/** Render a verdict chip, or the shared absence affordance. */
function VerdictChip({
  decision,
  testId,
}: Readonly<{ decision: Certain<AuditDecision>; testId: string }>) {
  if (!isKnown(decision)) {
    return <AbsenceMarker state={decision.state} detail={decision.detail} testId={testId} />
  }
  const meta = DECISION_META[decision.value]
  return (
    <span className={chipClass(meta.chip)} data-testid={testId}>
      {meta.label}
    </span>
  )
}

/**
 * The decision cell: what was enforced, plus what observe mode suppressed.
 *
 * The suppressed verdict is rendered as a second, restrictively-toned chip
 * rather than folded into the first. An observe-mode row genuinely *was*
 * allowed — the action proceeded — so hiding the `allow` would misreport what
 * happened; but showing it alone reports a governance all-clear over a denial.
 * Both facts are on screen, and the one that carries the risk is the one
 * coloured. See `features/audit/logs.ts::extractVerdict` for the wire evidence.
 */
function DecisionCell({
  verdict,
  seq,
  idPrefix,
}: Readonly<{ verdict: AuditVerdict; seq: number; idPrefix: string }>) {
  return (
    <span className="audit-decision-cell">
      <VerdictChip decision={verdict.enforced} testId={`${idPrefix}-${seq}`} />
      {verdict.suppressed !== null && (
        <span
          className="audit-chip audit-chip--observe"
          data-testid={`audit-suppressed-${seq}`}
          title={
            verdict.suppressedReason
              ? `Observe mode suppressed this verdict — ${verdict.suppressedReason}`
              : 'Observe mode suppressed this verdict; the action was allowed to proceed.'
          }
        >
          ⊙ observe: {isKnown(verdict.suppressed) ? verdict.suppressed.value.toLowerCase() : 'unknown'}
        </span>
      )}
    </span>
  )
}

/**
 * Audit Log page (`/audit`, AAASM-3510) — the governance trail across all
 * agents, per `design/v2/hi-fi/audit-log.jsx` (authoritative per ADR 0025;
 * byte-identical to the v1 file the original port cited). A filterable event
 * table (clickable type-stats strip, agent select, free-text search) over
 * `GET /api/v1/logs`, with an expandable per-row payload detail and a stable
 * `/audit/event/:seq` cross-link mirroring the IAM Access Log.
 *
 * The layout is the mock's; the *schema* is not. The mock is driven by a
 * hand-written fixture whose event types, payload fields and decision spelling
 * none of the backend producers emit, so every reader on this page is written
 * against the gateway and runtime instead — see `features/audit/logs.ts` for
 * the verified wire shapes.
 *
 * Theme-token only — inverts under `:root[data-theme="dark"]` with no JS.
 */
export function AuditLogPage() {
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [agentFilter, setAgentFilter] = useState<string>('all')
  const [q, setQ] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)
  const [pages, setPages] = useState(1)
  const { toast } = useToast()

  // The type/agent filters are applied client-side so toggling them never
  // refetches; the server query stays broad and the stats strip can show live
  // per-type counts over the whole loaded window.
  const { data, isPending, isError, isFetching, refetch } = useAuditLogQuery({ pages })
  const all = useMemo<LogEntry[]>(() => data?.entries ?? [], [data])
  const coverage = useMemo(() => auditCoverage(data), [data])

  const agents = useMemo(
    () => ['all', ...Array.from(new Set(all.map((e) => e.agent_id)))],
    [all],
  )

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const e of all) {
      const group = eventGroupOf(e.event_type)
      c[group] = (c[group] ?? 0) + 1
    }
    return c
  }, [all])

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return all.filter((e) => {
      if (typeFilter !== 'all' && eventGroupOf(e.event_type) !== typeFilter) return false
      if (agentFilter !== 'all' && e.agent_id !== agentFilter) return false
      if (needle) {
        const summary = payloadSummary(e.payload)
        const summaryText = isKnown(summary) ? summary.value : ''
        const hay =
          `${e.agent_id} ${e.event_type} ${summaryText} ${e.session_id}`.toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [all, typeFilter, agentFilter, q])

  const stats = [
    { key: 'all', label: 'Total', count: all.length },
    ...AUDIT_EVENT_GROUPS.map((group) => ({
      key: group.key,
      label: group.label,
      count: counts[group.key] ?? 0,
    })),
  ]

  // Both header exports run over the currently-filtered rows (client-side —
  // there is no server export/compliance endpoint), so what downloads always
  // matches what the operator has narrowed the table to. Coverage travels with
  // them so neither artifact can present the window as the whole trail.
  const handleExportCsv = () => {
    if (filtered.length === 0) {
      toast('No rows to export', 'info')
      return
    }
    downloadAuditCsv(filtered, coverage)
    const scope = coverage.complete ? 'complete' : 'partial'
    toast(
      `Exported ${filtered.length} row${filtered.length === 1 ? '' : 's'} to CSV (${scope} window)`,
      'success',
    )
  }

  const handleComplianceReport = () => {
    downloadComplianceReport(filtered, { typeFilter, agentFilter, search: q }, coverage)
    toast(
      coverage.complete
        ? `Compliance report generated (${filtered.length} events)`
        : `Compliance report generated over a PARTIAL window (${filtered.length} events)`,
      coverage.complete ? 'success' : 'info',
    )
  }

  // Pick the body section with an explicit branch rather than a nested ternary
  // (error → loading → table), keeping the render tree readable.
  let body: React.ReactNode
  if (isError) {
    body = (
      <StatusState
        state="unavailable"
        title="Audit log unavailable"
        description="The gateway did not return the governance trail. No entries are shown — this is not an empty trail."
        testId="audit-error"
        action={
          <button type="button" className="audit-btn" onClick={() => ignorePromise(refetch())}>
            Retry
          </button>
        }
      />
    )
  } else if (isPending) {
    body = <StatusState state="unknown" title="Loading audit log…" testId="audit-loading" />
  } else {
    body = (
      <div className="audit-table-wrap">
        <table className="audit-table" data-testid="audit-table">
          <thead>
            <tr>
              <th style={{ width: 52 }}>seq</th>
              <th style={{ width: 100 }}>time</th>
              <th style={{ width: 170 }}>agent (audit id digest)</th>
              <th style={{ width: 150 }}>event type</th>
              <th style={{ width: 96 }}>decision</th>
              <th>summary</th>
              <th style={{ width: 90 }}>session</th>
              <th style={{ width: 64 }}></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} className="audit-empty-cell" data-testid="audit-empty">
                  no entries match
                </td>
              </tr>
            ) : (
              filtered.map((e) => {
                const meta = EVENT_META.get(e.event_type) ?? {
                  label: e.event_type,
                  chip: '',
                  icon: '·',
                }
                const verdict = extractVerdict(e.payload)
                const summary = payloadSummary(e.payload)
                const trace = extractTraceId(e.payload)
                const isExp = expanded === e.seq
                // A denial observe mode suppressed still scans as a violation
                // row: the gateway recorded it under a rewritten, benign event
                // type, so the event type alone would let it pass unnoticed.
                const isViolation = e.event_type === 'PolicyViolation' || isSuppressedDenial(verdict)
                const group = eventGroupOf(e.event_type)
                const rowCls = [
                  'audit-row',
                  isExp ? 'audit-row--expanded' : '',
                  !isExp && isViolation ? 'audit-row--violation' : '',
                ]
                  .filter(Boolean)
                  .join(' ')

                return (
                  <Fragment key={e.seq}>
                    <tr
                      className={rowCls}
                      data-testid={`audit-row-${e.seq}`}
                      onClick={() => setExpanded(isExp ? null : e.seq)}
                    >
                      <td className="audit-mono audit-session">{e.seq}</td>
                      <td>
                        {/* The wire timestamp is UTC; on a compliance surface an
                            unlabelled clock time invites the reader to assume it
                            is local. Label the zone explicitly (AAASM-5172). */}
                        <div className="audit-cell-time">{e.timestamp.slice(11, 19)} UTC</div>
                        <div className="audit-cell-date">{e.timestamp.slice(0, 10)}</div>
                      </td>
                      <td>
                        {/* The audit id is SHA256(agent DID)[..16]; the fleet's
                            AgentResponse.id is SHA256("{org}/{team}/{DID}")[..16].
                            The two can never be equal, and nothing on the wire
                            carries the agent's name or DID here, so the cell
                            shows the digest for what it is rather than linking
                            to an agent page that could not resolve it
                            (AAASM-5151). */}
                        <span
                          className="audit-agent-id audit-mono"
                          data-testid={`audit-agent-id-${e.seq}`}
                          title={`Audit agent id digest ${e.agent_id} — not resolvable to a registered agent name (AAASM-5151)`}
                        >
                          {shortDigest(e.agent_id)}
                        </span>
                      </td>
                      <td>
                        <span className={chipClass(meta.chip)}>
                          {meta.icon} {meta.label}
                        </span>
                      </td>
                      <td>
                        <DecisionCell verdict={verdict} seq={e.seq} idPrefix="audit-decision" />
                      </td>
                      <td>
                        {isKnown(summary) ? (
                          <span
                            data-testid={`audit-summary-${e.seq}`}
                            className={[
                              'audit-summary',
                              isViolation ? 'audit-summary--violation' : '',
                              MONO_SUMMARY_GROUPS.has(group) ? 'audit-summary--mono' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                          >
                            {summary.value}
                          </span>
                        ) : (
                          <AbsenceMarker
                            state={summary.state}
                            detail={summary.detail}
                            testId={`audit-summary-${e.seq}`}
                          />
                        )}
                      </td>
                      <td className="audit-session">{e.session_id}</td>
                      <td>
                        {/* The mock (design/v1/hi-fi/audit-log.jsx:145,197-199)
                            carries a ▼/▲ disclosure glyph reflecting the row's
                            expand state; the port dropped it for the View link
                            alone. Both are restored — the glyph mirrors the
                            row's click-to-expand, the link is the stable
                            cross-reference (AAASM-5172). */}
                        <span
                          className="audit-expand-glyph"
                          aria-hidden="true"
                          data-testid={`audit-expand-glyph-${e.seq}`}
                        >
                          {isExp ? '▲' : '▼'}
                        </span>
                        <Link
                          to={auditEventHref(e.seq)}
                          className="audit-event-link"
                          data-testid={`audit-event-link-${e.seq}`}
                          onClick={(ev) => ev.stopPropagation()}
                        >
                          View →
                        </Link>
                      </td>
                    </tr>

                    {isExp && (
                      <tr>
                        <td colSpan={8} className="audit-detail-cell">
                          <div className="audit-detail" data-testid={`audit-detail-${e.seq}`}>
                            <div>
                              <div className="audit-detail__section-title">metadata</div>
                              <div className="audit-kv">
                                <span className="audit-kv__k">seq</span>
                                <span className="audit-kv__v">{e.seq}</span>
                                <span className="audit-kv__k">timestamp</span>
                                <span className="audit-kv__v">{e.timestamp}</span>
                                <span className="audit-kv__k">agent id</span>
                                <span className="audit-kv__v" data-testid={`audit-agent-full-${e.seq}`}>
                                  {e.agent_id}
                                </span>
                                <span className="audit-kv__k">session</span>
                                <span className="audit-kv__v">{e.session_id}</span>
                                <span className="audit-kv__k">trace</span>
                                <span className="audit-kv__v">
                                  {isKnown(trace) ? (
                                    <span data-testid={`audit-trace-${e.seq}`}>{trace.value}</span>
                                  ) : (
                                    <AbsenceMarker
                                      state={trace.state}
                                      detail={trace.detail}
                                      testId={`audit-trace-${e.seq}`}
                                    />
                                  )}
                                </span>
                                <span className="audit-kv__k">decision</span>
                                <span className="audit-kv__v">
                                  <DecisionCell
                                    verdict={verdict}
                                    seq={-e.seq}
                                    idPrefix="audit-detail-decision"
                                  />
                                </span>
                              </div>
                            </div>
                            <div>
                              <div className="audit-detail__section-title">payload</div>
                              <pre className="audit-payload">{prettyPayload(e.payload)}</pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    )
  }

  return (
    <div className="audit-page" data-testid="audit-log-page">
      <header className="audit-head">
        <div>
          <h1 className="audit-head__title">Audit Log</h1>
          <p className="audit-head__sub">
            Governance trail — intercepted and dispatched tool calls, policy
            violations, credential blocks, approval decisions, budget limits,
            agent-to-agent calls, and sandbox outcomes across all agents.
          </p>
        </div>
        <div className="audit-head__actions">
          <Link to="/audit/violations" className="audit-btn">
            Violations heatmap →
          </Link>
          <button
            type="button"
            className="audit-btn"
            onClick={handleExportCsv}
            data-testid="audit-export-csv"
          >
            ⏏ Export CSV
          </button>
          <button
            type="button"
            className="audit-btn audit-btn--primary"
            onClick={handleComplianceReport}
            data-testid="audit-compliance-report"
          >
            Compliance report →
          </button>
        </div>
      </header>

      {/* The coverage banner is above the stats strip on purpose: every number
          below it is a count over the loaded window, and an operator has to
          read what the window is before reading a total drawn from it. It is
          rendered only once a window exists — the loading and failure cases are
          stated by the body, and describing an unasked question as "unknown
          coverage" would put a governance caveat where there is not yet a
          claim. */}
      {data && (
        // <output> carries an implicit `status` role, so this is the same
        // announcement contract with better assistive-tech support (S6819).
        // Deliberately not applied to `components/truthfulness/StatusState`,
        // which is the shared primitive — its markup is AAASM-5173's to change.
        <output
          className={`audit-coverage${coverage.complete ? '' : ' audit-coverage--partial'}`}
          data-testid="audit-coverage"
        >
          <span className="audit-coverage__text">{coverageStatement(coverage)}</span>
          {coverage.moreAvailable && (
            <button
              type="button"
              className="audit-btn audit-coverage__more"
              data-testid="audit-load-more"
              disabled={isFetching}
              onClick={() => setPages((p) => p + 1)}
            >
              {isFetching ? 'Loading…' : 'Load more'}
            </button>
          )}
        </output>
      )}

      <div
        className="audit-stats"
        style={{ gridTemplateColumns: `repeat(${stats.length}, 1fr)` }}
        data-testid="audit-stats"
      >
        {stats.map(({ key, label, count }) => {
          const active = typeFilter === key
          return (
            <button
              type="button"
              key={key}
              data-testid={`audit-stat-${key}`}
              className={`audit-stat${active ? ' audit-stat--active' : ''}`}
              onClick={() => setTypeFilter(active ? 'all' : key)}
            >
              <div
                className={`audit-stat__count${
                  key === 'policy' && !active ? ' audit-stat__count--danger' : ''
                }`}
              >
                {count}
              </div>
              <div className="audit-stat__label">{label}</div>
            </button>
          )
        })}
      </div>

      <div className="audit-filterbar" data-testid="audit-filterbar">
        <div className="audit-search">
          <span aria-hidden="true">⌕</span>
          <input
            type="search"
            aria-label="Search audit log"
            placeholder="search agent, action, session…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            data-testid="audit-search"
          />
        </div>
        <span className="audit-divider" />
        <span className="audit-filter-label">agent id</span>
        <select
          className="audit-select"
          aria-label="Filter by agent id digest"
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          data-testid="audit-agent-filter"
        >
          {agents.map((a) => (
            <option key={a} value={a} title={a}>
              {a === 'all' ? 'all' : shortDigest(a)}
            </option>
          ))}
        </select>
        <span className="audit-divider" />
        <span className="audit-filter-label">type</span>
        <div className="audit-type-filters" data-testid="audit-type-filters">
          {['all', ...AUDIT_EVENT_GROUPS.map((g) => g.key)].map((v) => {
            const active = typeFilter === v
            const label = v === 'all' ? 'all' : AUDIT_EVENT_GROUPS.find((g) => g.key === v)!.label
            return (
              <button
                type="button"
                key={v}
                className={`audit-type-btn${active ? ' audit-type-btn--active' : ''}`}
                aria-pressed={active}
                data-testid={`audit-type-btn-${v}`}
                onClick={() => setTypeFilter(v)}
              >
                {label}
              </button>
            )
          })}
        </div>
        {/* One counter, denominated in the same units as the banner beside it:
            `filtered / total-matching-the-server-filter`. An earlier revision
            read `N / N loaded` next to `Partial — N of 4820`, two true numbers
            that together invite the reading that N is the whole set. */}
        <span className="audit-count" data-testid="audit-count">
          {filtered.length} / {isKnown(coverage.total) ? coverage.total.value : '?'}
        </span>
      </div>

      {body}
    </div>
  )
}
