import { Link, useParams } from 'react-router-dom'

/**
 * Trace view page — header + slot for the timeline component.
 *
 * Renders the placeholder shell registered at `/agents/:id/trace/:sessionId`.
 * The timeline lands in AAASM-1067, payload modal in AAASM-1069, JSON
 * export in AAASM-1071.
 */
export function TraceViewPage() {
  const { id = '', sessionId = '' } = useParams<{ id: string; sessionId: string }>()

  return (
    <main style={{ padding: '1.5rem' }} data-testid="trace-view">
      <Link to={`/agents/${id}`} style={{ fontSize: '0.875rem' }}>← Back to agent</Link>
      <h1 style={{ margin: '0.75rem 0' }}>
        Trace · <code style={{ fontSize: '1rem' }}>{id}</code> / <code style={{ fontSize: '1rem' }}>{sessionId}</code>
      </h1>
      <div
        data-testid="trace-timeline-placeholder"
        style={{ color: 'var(--shell-text-muted)', marginTop: '1rem' }}
      >
        Timeline component lands in AAASM-1067.
      </div>
    </main>
  )
}
