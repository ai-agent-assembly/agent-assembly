import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  useAccessLogQuery,
  type AccessLogEvent,
  type AccessLogEventType,
  type AccessLogFilter,
} from './accessLog'
import { useMembersQuery } from './api'
import { useApiKeysQuery } from './apiKeys'
import { AccessLogFilterBar } from './AccessLogFilterBar'
import './AccessLogPanel.css'

const PAGE_SIZE = 10

const EVENT_TYPE_LABELS: Record<AccessLogEventType, string> = {
  login: 'Login',
  logout: 'Logout',
  policy_change: 'Policy change',
  key_rotate: 'Key rotation',
  member_invite: 'Member invite',
  permission_grant: 'Permission grant',
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toISOString().slice(0, 16).replace('T', ' ')
}

function auditEventHref(eventId: string): string {
  // AAASM-1398 — verbatim path-segment from the AC. The /audit page is
  // currently a ComingSoon route; the link is intentionally stable so the
  // audit page (next sprint) can claim `/audit/event/:id` directly.
  return `/audit/event/${eventId}`
}

export function AccessLogPanel() {
  const [filter, setFilter] = useState<AccessLogFilter>({})
  const [page, setPage] = useState(0)
  const navigate = useNavigate()

  const { data: events, isLoading, isError, refetch } = useAccessLogQuery(filter)
  // Identity candidates feed the filter bar — union of member emails (page 1
  // with a generous page size so the demo seed shows up in full) and active
  // service-key labels. Service keys lacking a label fall back to prefix.
  const { data: membersPage } = useMembersQuery(1, 100)
  const { data: apiKeys } = useApiKeysQuery()
  const identities = useMemo<string[]>(() => {
    const memberEmails = membersPage?.items.map((m) => m.email) ?? []
    const keyLabels =
      apiKeys?.filter((k) => k.status === 'active').map((k) => k.label ?? k.prefix) ?? []
    return Array.from(new Set([...memberEmails, ...keyLabels])).sort()
  }, [membersPage, apiKeys])

  const rows = events ?? []
  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE))
  const safePage = Math.min(page, totalPages - 1)
  const pageRows = rows.slice(safePage * PAGE_SIZE, (safePage + 1) * PAGE_SIZE)

  function handleFilterChange(next: AccessLogFilter) {
    setFilter(next)
    // Reset to the first page when the filter changes — otherwise narrowing
    // a filter while on page 3 leaves the user looking at an empty window.
    setPage(0)
  }

  if (isError) {
    return (
      <section className="iam-access-log-panel" data-testid="iam-panel-access-log">
        <h2>Access Log</h2>
        <div className="iam-access-log-panel__error" data-testid="access-log-error">
          <span>Failed to load access log.</span>
          <button type="button" onClick={() => void refetch()}>
            Retry
          </button>
        </div>
      </section>
    )
  }

  return (
    <section className="iam-access-log-panel" data-testid="iam-panel-access-log">
      <h2>Access Log</h2>
      <p className="iam-access-log-panel__intro">
        Identity-scoped audit events. Each row links to the corresponding entry
        on the full audit log.
      </p>

      <AccessLogFilterBar
        identities={identities}
        value={filter}
        onChange={handleFilterChange}
      />

      {isLoading && (
        <div className="iam-access-log-panel__loading" data-testid="access-log-loading">
          Loading…
        </div>
      )}

      {!isLoading && rows.length === 0 && (
        <div className="iam-access-log-panel__empty" data-testid="access-log-empty">
          No access-log events match the current filter.
        </div>
      )}

      {!isLoading && rows.length > 0 && (
        <>
          <table className="iam-access-log-table" data-testid="access-log-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Identity</th>
                <th>Event type</th>
                <th>Target</th>
                <th>Result</th>
                <th>Source IP</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {pageRows.map((row: AccessLogEvent) => (
                <tr
                  key={row.id}
                  data-testid={`access-log-row-${row.id}`}
                  className="iam-access-log-table__row"
                  onClick={() => navigate(auditEventHref(row.id))}
                >
                  <td className="iam-access-log-table__mono">
                    {formatTimestamp(row.timestamp)}
                  </td>
                  <td>{row.identity}</td>
                  <td>{EVENT_TYPE_LABELS[row.event_type]}</td>
                  <td className="iam-access-log-table__mono">{row.target}</td>
                  <td>
                    <span
                      className={`iam-access-log-table__result iam-access-log-table__result--${row.result}`}
                    >
                      {row.result}
                    </span>
                  </td>
                  <td className="iam-access-log-table__mono">{row.source_ip}</td>
                  <td>
                    <Link
                      to={auditEventHref(row.id)}
                      className="iam-access-log-table__link"
                      data-testid={`access-log-row-link-${row.id}`}
                      // Don't double-fire navigate(): row onClick already
                      // routes; the Link is here so the href is discoverable
                      // to keyboard / screen-reader users and to the e2e
                      // assertion that the AC #11 cross-link path is stable.
                      onClick={(e) => e.stopPropagation()}
                    >
                      View →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <div className="iam-access-log-panel__pagination">
            <button
              type="button"
              data-testid="access-log-pagination-prev"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={safePage === 0}
            >
              ← Previous
            </button>
            <span data-testid="access-log-page-indicator">
              Page {safePage + 1} of {totalPages}
            </span>
            <button
              type="button"
              data-testid="access-log-pagination-next"
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={safePage >= totalPages - 1}
            >
              Next →
            </button>
          </div>
        </>
      )}
    </section>
  )
}
