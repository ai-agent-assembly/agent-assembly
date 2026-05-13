import { Link, useParams } from 'react-router-dom'
import { useTraceQuery } from '../features/trace/api'

/**
 * Trace view page — header, status states (loading / error / empty / ready),
 * and a slot where the timeline component lands in AAASM-1067.
 */
export function TraceViewPage() {
  const { id = '', sessionId = '' } = useParams<{ id: string; sessionId: string }>()
  const { data, isLoading, isError, refetch } = useTraceQuery(id, sessionId)

  return (
    <main style={{ padding: '1.5rem' }} data-testid="trace-view">
      <Link to={`/agents/${id}`} style={{ fontSize: '0.875rem' }}>← Back to agent</Link>
      <h1 style={{ margin: '0.75rem 0' }}>
        Trace · <code style={{ fontSize: '1rem' }}>{id}</code> / <code style={{ fontSize: '1rem' }}>{sessionId}</code>
      </h1>

      {isLoading && (
        <div data-testid="trace-loading" style={{ marginTop: '1rem' }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              data-testid="trace-row-skeleton"
              style={{
                background: '#f3f4f6',
                height: '2.25rem',
                marginBottom: '0.5rem',
                borderRadius: '4px',
              }}
            />
          ))}
        </div>
      )}

      {isError && (
        <div data-testid="trace-error" style={{ marginTop: '1rem' }}>
          <p style={{ color: '#dc2626' }}>Failed to load trace.</p>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {!isLoading && !isError && data && data.length === 0 && (
        <div data-testid="trace-empty" style={{ marginTop: '1rem', color: 'var(--shell-text-muted)' }}>
          No events recorded for this session.
        </div>
      )}

      {!isLoading && !isError && data && data.length > 0 && (
        <div
          data-testid="trace-timeline-placeholder"
          style={{ color: 'var(--shell-text-muted)', marginTop: '1rem' }}
        >
          Loaded {data.length} event{data.length === 1 ? '' : 's'}. Timeline component lands in AAASM-1067.
        </div>
      )}
    </main>
  )
}
