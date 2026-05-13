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

export function ApprovalDetailRow({ approval, colSpan }: ApprovalDetailRowProps) {
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
              <pre
                data-testid="approval-detail-routing"
                style={{
                  margin: 0,
                  fontSize: '0.75rem',
                  background: 'var(--paper-2)',
                  border: '1px solid var(--line)',
                  borderRadius: '0.25rem',
                  padding: '0.5rem',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {JSON.stringify(approval.routing_status, null, 2)}
              </pre>
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
