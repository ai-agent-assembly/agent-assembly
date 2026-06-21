import { Fragment, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ignorePromise } from '../lib/ignorePromise'
import {
  AUDIT_EVENT_TYPES,
  auditEventHref,
  extractDecision,
  payloadSummary,
  useAuditLogQuery,
  type LogEntry,
} from '../features/audit/logs'
import './AuditLogPage.css'

/** Display metadata per event type — label + chip variant for the table. */
const EVENT_META: Record<string, { label: string; chip: string; icon: string }> = {
  LLMCall: { label: 'LLM Call', chip: 'info', icon: '◈' },
  ToolCall: { label: 'Tool Call', chip: 'info', icon: '⚙' },
  FileOp: { label: 'File Op', chip: 'warn', icon: '▤' },
  NetworkCall: { label: 'Network', chip: '', icon: '⇥' },
  PolicyViolation: { label: 'Policy Violation', chip: 'danger', icon: '⚑' },
  ApprovalEvent: { label: 'Approval', chip: 'ok', icon: '✓' },
}

/** Chip variant + lowercased label for the decision verdict carried in the payload. */
const DECISION_META: Record<string, { chip: string; label: string }> = {
  ALLOW: { chip: 'ok', label: 'allow' },
  DENY: { chip: 'danger', label: 'deny' },
  PENDING: { chip: 'info', label: 'pending' },
  REDACT: { chip: 'warn', label: 'redact' },
  APPROVE: { chip: 'ok', label: 'approved' },
}

const MONO_SUMMARY_TYPES = new Set(['LLMCall', 'ToolCall', 'NetworkCall'])

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
 * Audit Log page (`/audit`, AAASM-3510) — the immutable governance trail across
 * all agents, per `design/v1/hi-fi/audit-log.jsx`. A filterable event table
 * (clickable type-stats strip, agent select, free-text search) over
 * `GET /api/v1/logs`, with an expandable per-row payload detail and a stable
 * `/audit/event/:seq` cross-link mirroring the IAM Access Log.
 *
 * Theme-token only — inverts under `:root[data-theme="dark"]` with no JS.
 */
export function AuditLogPage() {
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [agentFilter, setAgentFilter] = useState<string>('all')
  const [q, setQ] = useState('')
  const [expanded, setExpanded] = useState<number | null>(null)
  const navigate = useNavigate()

  // The type/agent filters are applied client-side so toggling them never
  // refetches; the server query stays broad and the stats strip can show live
  // per-type counts over the whole window.
  const { data, isLoading, isError, refetch } = useAuditLogQuery()
  const all = useMemo<LogEntry[]>(() => data ?? [], [data])

  const agents = useMemo(
    () => ['all', ...Array.from(new Set(all.map((e) => e.agent_id)))],
    [all],
  )

  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const e of all) c[e.event_type] = (c[e.event_type] ?? 0) + 1
    return c
  }, [all])

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return all.filter((e) => {
      if (typeFilter !== 'all' && e.event_type !== typeFilter) return false
      if (agentFilter !== 'all' && e.agent_id !== agentFilter) return false
      if (needle) {
        const hay =
          `${e.agent_id} ${e.event_type} ${payloadSummary(e.event_type, e.payload)} ${e.session_id}`.toLowerCase()
        if (!hay.includes(needle)) return false
      }
      return true
    })
  }, [all, typeFilter, agentFilter, q])

  const stats = [
    { key: 'all', label: 'Total', count: all.length },
    ...AUDIT_EVENT_TYPES.map((key) => ({
      key,
      label: EVENT_META[key].label,
      count: counts[key] ?? 0,
    })),
  ]

  return (
    <div className="audit-page" data-testid="audit-log-page">
      <header className="audit-head">
        <div>
          <h1 className="audit-head__title">Audit Log</h1>
          <p className="audit-head__sub">
            Immutable governance trail — LLM calls, tool invocations, file ops,
            network requests, policy verdicts, and approval decisions across all
            agents.
          </p>
        </div>
        <div className="audit-head__actions">
          <Link to="/audit/violations" className="audit-btn">
            Violations heatmap →
          </Link>
        </div>
      </header>

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
                  key === 'PolicyViolation' && !active ? ' audit-stat__count--danger' : ''
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
        <span className="audit-filter-label">agent</span>
        <select
          className="audit-select"
          aria-label="Filter by agent"
          value={agentFilter}
          onChange={(e) => setAgentFilter(e.target.value)}
          data-testid="audit-agent-filter"
        >
          {agents.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <span className="audit-count" data-testid="audit-count">
          {filtered.length} / {all.length}
        </span>
      </div>

      {isError ? (
        <div className="audit-state audit-state--error" data-testid="audit-error">
          <p>Failed to load audit log.</p>
          <button type="button" className="audit-btn" onClick={() => ignorePromise(refetch())}>
            Retry
          </button>
        </div>
      ) : isLoading ? (
        <div className="audit-state" data-testid="audit-loading">
          Loading…
        </div>
      ) : (
        <div className="audit-table-wrap">
          <table className="audit-table" data-testid="audit-table">
            <thead>
              <tr>
                <th style={{ width: 52 }}>seq</th>
                <th style={{ width: 100 }}>time</th>
                <th style={{ width: 150 }}>agent</th>
                <th style={{ width: 150 }}>event type</th>
                <th style={{ width: 84 }}>decision</th>
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
                  const meta = EVENT_META[e.event_type] ?? {
                    label: e.event_type,
                    chip: '',
                    icon: '·',
                  }
                  const decision = extractDecision(e.payload)
                  const dm = (decision && DECISION_META[decision]) || {
                    chip: '',
                    label: decision ? decision.toLowerCase() : '—',
                  }
                  const summary = payloadSummary(e.event_type, e.payload)
                  const isExp = expanded === e.seq
                  const isViolation = e.event_type === 'PolicyViolation'
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
                          <div className="audit-cell-time">{e.timestamp.slice(11, 19)}</div>
                          <div className="audit-cell-date">{e.timestamp.slice(0, 10)}</div>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="audit-agent-link"
                            data-testid={`audit-agent-link-${e.seq}`}
                            onClick={(ev) => {
                              ev.stopPropagation()
                              navigate(`/agents/${e.agent_id}`)
                            }}
                          >
                            {e.agent_id}
                          </button>
                        </td>
                        <td>
                          <span className={chipClass(meta.chip)}>
                            {meta.icon} {meta.label}
                          </span>
                        </td>
                        <td>
                          <span className={chipClass(dm.chip)}>{dm.label}</span>
                        </td>
                        <td>
                          <span
                            className={[
                              'audit-summary',
                              isViolation ? 'audit-summary--violation' : '',
                              MONO_SUMMARY_TYPES.has(e.event_type) ? 'audit-summary--mono' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                          >
                            {summary}
                          </span>
                        </td>
                        <td className="audit-session">{e.session_id}</td>
                        <td>
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
                                  <span className="audit-kv__k">session</span>
                                  <span className="audit-kv__v">{e.session_id}</span>
                                  <span className="audit-kv__k">decision</span>
                                  <span className="audit-kv__v">
                                    <span className={chipClass(dm.chip)}>{dm.label}</span>
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
      )}
    </div>
  )
}
