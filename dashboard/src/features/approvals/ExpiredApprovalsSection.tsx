import { useState } from 'react'
import { ApprovalRoutingBadge } from '../../components/ApprovalRoutingBadge'
import type { Approval } from './api'

interface ExpiredApprovalsSectionProps {
  rows: Approval[]
}

export function ExpiredApprovalsSection({ rows }: ExpiredApprovalsSectionProps) {
  const [expanded, setExpanded] = useState(false)

  if (rows.length === 0) return null

  return (
    <section data-testid="expired-approvals-section" style={{ marginTop: '1rem' }}>
      <button
        data-testid="expired-toggle"
        aria-expanded={expanded}
        onClick={() => setExpanded((v) => !v)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          width: '100%',
          padding: '0.5rem 0.75rem',
          background: 'var(--paper-3)',
          border: '1px solid var(--line)',
          borderRadius: '0.375rem',
          cursor: 'pointer',
          fontSize: '0.875rem',
          color: 'var(--ink-2)',
          textAlign: 'left',
        }}
      >
        <span style={{ fontWeight: 600 }}>{expanded ? '▾' : '▸'} Expired</span>
        <span
          data-testid="expired-count-badge"
          style={{
            display: 'inline-block',
            padding: '0 0.5rem',
            background: 'var(--ink-4)',
            color: 'var(--paper-2)',
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: 600,
          }}
        >
          {rows.length}
        </span>
      </button>

      {expanded && (
        <table
          className="approvals-table"
          data-testid="expired-approvals-table"
          style={{ marginTop: '0.5rem', opacity: 0.65, color: 'var(--ink-3)' }}
        >
          <thead>
            <tr>
              <th>Agent</th>
              <th>Action</th>
              <th>Reason</th>
              <th>Routing</th>
              <th>Requested at</th>
              <th>Expired at</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} data-testid="expired-row">
                <td className="approvals-table__id">{row.agent_id}</td>
                <td>{row.action}</td>
                <td>{row.reason}</td>
                <td>
                  {row.routing_status
                    ? <ApprovalRoutingBadge routingStatus={row.routing_status} />
                    : <span className="approvals-table__unrouted">—</span>}
                </td>
                <td>{row.created_at}</td>
                <td>{row.expires_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  )
}
