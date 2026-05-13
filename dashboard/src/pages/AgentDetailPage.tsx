import { useCallback } from 'react'
import { useParams, useNavigate, useLocation, Link } from 'react-router-dom'
import { useAgentQuery, useAgentEventsQuery } from '../features/agents/api'
import { Drawer } from '../components/Drawer'

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ marginBottom: '0.5rem' }}>
      <span style={{ fontWeight: 600, marginRight: '0.5rem' }}>{label}:</span>
      <span>{value ?? '—'}</span>
    </div>
  )
}

export function AgentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const location = useLocation()
  const { data: agent, isLoading: agentLoading, isError: agentError, refetch: refetchAgent } = useAgentQuery(id ?? '')
  const { data: events, isLoading: eventsLoading, isError: eventsError } = useAgentEventsQuery(id ?? '')

  const close = useCallback(() => {
    navigate({ pathname: '/agents', search: location.search })
  }, [navigate, location.search])

  return (
    <Drawer open onClose={close} ariaLabel={agent ? `Agent ${agent.name}` : 'Agent detail'}>
      {agentLoading && (
        <div style={{ padding: '1.5rem' }} data-testid="agent-detail-loading">
          <p>Loading agent…</p>
        </div>
      )}

      {!agentLoading && (agentError || !agent) && (
        <div style={{ padding: '1.5rem' }} data-testid="agent-detail-error">
          <p style={{ color: '#dc2626' }}>Failed to load agent.</p>
          <button onClick={() => void refetchAgent()}>Retry</button>
          <br />
          <Link to="/agents">← Back to agents</Link>
        </div>
      )}

      {!agentLoading && !agentError && agent && (
        <div data-testid="agent-detail" style={{ padding: '1.5rem' }}>
          <button
            type="button"
            onClick={close}
            data-testid="agent-detail-close"
            style={{ fontSize: '0.875rem', background: 'transparent', border: 0, cursor: 'pointer', color: 'var(--ink-3, #5a5a5a)' }}
          >
            ← Back to agents
          </button>
          <h1 style={{ margin: '0.75rem 0' }}>{agent.name}</h1>

          <section
            data-testid="agent-profile"
            style={{ background: '#f9fafb', border: '1px solid #e5e7eb', borderRadius: '8px', padding: '1rem', marginBottom: '1.5rem' }}
          >
            <h2 style={{ marginTop: 0 }}>Identity Profile</h2>
            <Field label="ID" value={<code style={{ fontSize: '0.8rem' }}>{agent.id}</code>} />
            <Field label="Framework" value={agent.framework} />
            <Field label="Version" value={agent.version} />
            <Field label="Status" value={agent.status} />
            <Field label="Governance layer" value={agent.layer} />
            <Field label="Sessions" value={agent.session_count} />
            <Field label="Policy violations" value={agent.policy_violations_count} />
            <Field label="Last seen" value={agent.last_event} />
            {agent.tool_names.length > 0 && (
              <Field label="Tools" value={agent.tool_names.join(', ')} />
            )}
          </section>

          <section data-testid="agent-events">
            <h2>Recent Events</h2>
            {eventsLoading && <p>Loading events…</p>}
            {eventsError && <p style={{ color: '#dc2626' }}>Failed to load events.</p>}
            {!eventsLoading && !eventsError && (!events || events.length === 0) && (
              <p>No events recorded for this agent.</p>
            )}
            {events && events.length > 0 && (
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid #e5e7eb' }}>Timestamp</th>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid #e5e7eb' }}>Type</th>
                    <th style={{ textAlign: 'left', padding: '0.4rem', borderBottom: '2px solid #e5e7eb' }}>Session</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map(ev => (
                    <tr key={`${ev.seq}-${ev.session_id}`} data-testid="event-row" style={{ borderBottom: '1px solid #f3f4f6' }}>
                      <td style={{ padding: '0.4rem' }}>{ev.timestamp}</td>
                      <td style={{ padding: '0.4rem' }}>{ev.event_type}</td>
                      <td style={{ padding: '0.4rem' }}>
                        <code style={{ fontSize: '0.75rem' }}>{ev.session_id.slice(0, 12)}…</code>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>
      )}
    </Drawer>
  )
}
