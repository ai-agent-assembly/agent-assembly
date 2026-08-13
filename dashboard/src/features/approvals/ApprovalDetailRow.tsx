import { ApprovalRoutingBadge } from '../../components/ApprovalRoutingBadge'
import type { Approval } from './api'

export interface ApprovalDetailRowProps {
  approval: Approval
  colSpan: number
}

const FIELD_STYLE = {
  display: 'flex',
  gap: '0.5rem',
  fontSize: '0.875rem',
  color: 'var(--ink-2)',
} as const

const LABEL_STYLE = {
  width: '7rem',
  flexShrink: 0,
  color: 'var(--ink-3)',
  fontWeight: 500,
} as const

export function ApprovalDetailRow({ approval, colSpan }: Readonly<ApprovalDetailRowProps>) {
  return (
    <tr data-testid="approval-detail-row">
      <td
        colSpan={colSpan}
        style={{
          padding: '0.75rem 1.25rem',
          background: 'var(--paper)',
          borderBottom: '1px solid var(--line)',
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          <div style={FIELD_STYLE}>
            <span style={LABEL_STYLE}>Approval id</span>
            <code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{approval.id}</code>
          </div>
          <div style={FIELD_STYLE}>
            <span style={LABEL_STYLE}>Agent</span>
            <span>
              <code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{approval.agent_id}</code>
              {approval.team_id && (
                <>
                  {' · team '}
                  <code style={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{approval.team_id}</code>
                </>
              )}
            </span>
          </div>
          <div style={FIELD_STYLE}>
            <span style={LABEL_STYLE}>Action</span>
            <span>{approval.action}</span>
          </div>
          <div style={FIELD_STYLE}>
            <span style={LABEL_STYLE}>Reason</span>
            <span>{approval.reason}</span>
          </div>
          <div style={FIELD_STYLE}>
            <span style={LABEL_STYLE}>Requested at</span>
            <span>{approval.created_at}</span>
          </div>
          {approval.routing_status && (
            <div style={FIELD_STYLE}>
              <span style={LABEL_STYLE}>Routing</span>
              <ApprovalRoutingBadge routingStatus={approval.routing_status} />
            </div>
          )}
          {approval.routing_status && approval.routing_status.history.length > 0 && (
            <div style={FIELD_STYLE}>
              <span style={LABEL_STYLE}>Routing history</span>
              <div
                data-testid="approval-detail-routing-history"
                style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}
              >
                {approval.routing_status.history.map((entry, i) => (
                  <div
                    key={`${entry.at}-${entry.action}-${entry.to_role}-${i}`}
                    data-testid="approval-detail-routing-history-row"
                    style={{ display: 'flex', gap: '0.5rem', fontSize: '0.75rem' }}
                  >
                    <code style={{ fontFamily: 'monospace' }}>
                      {new Date(entry.at * 1000).toISOString()}
                    </code>
                    <span>
                      {entry.action}
                      {entry.from_role ? ` from ${entry.from_role}` : ''} → {entry.to_role}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div style={{ ...FIELD_STYLE, color: 'var(--ink-4)', fontStyle: 'italic' }}>
            <span style={LABEL_STYLE}>Payload</span>
            <span>Full action payload not available via the current API.</span>
          </div>
        </div>
      </td>
    </tr>
  )
}
