import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAgentQuery } from '../features/agents/api'
import { useTraceQuery } from '../features/trace/api'
import { TraceTimeline } from '../components/trace/TraceTimeline'
import { TraceTimelineFilter } from '../components/trace/TraceTimelineFilter'
import { ALL_ON, type SeverityFilter } from '../components/trace/severityFilter'
import { EmptyState } from '../components/states'
import type { TraceEvent } from '../features/trace/types'

function applyFilter(events: readonly TraceEvent[], filter: SeverityFilter): TraceEvent[] {
  return events.filter(event => {
    const key = event.severity ?? 'neutral'
    return filter[key]
  })
}

/**
 * Trace view page — header, status states (loading / error / empty / ready),
 * severity filter, and the trace timeline introduced in AAASM-1067.
 */
export function TraceViewPage() {
  const { id = '', sessionId = '' } = useParams<{ id: string; sessionId: string }>()
  const { data: agent } = useAgentQuery(id)
  const { data, isLoading, isError, refetch } = useTraceQuery(id, sessionId)
  const agentLabel = agent?.name ?? id
  const [filter, setFilter] = useState<SeverityFilter>(ALL_ON)
  const filteredEvents = useMemo(() => applyFilter(data ?? [], filter), [data, filter])

  return (
    <main style={{ padding: '1.5rem' }} data-testid="trace-view">
      <Link to={`/agents/${id}`} style={{ fontSize: '0.875rem' }}>← Back to agent</Link>
      <h1 style={{ margin: '0.75rem 0' }} data-testid="trace-header">
        Trace · <span data-testid="trace-agent-label">{agentLabel}</span> / <code style={{ fontSize: '1rem' }}>{sessionId}</code>
      </h1>

      {isLoading && (
        <div data-testid="trace-loading" style={{ marginTop: '1rem' }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              data-testid="trace-row-skeleton"
              style={{
                background: 'var(--paper-3)',
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
          <p style={{ color: 'var(--danger)' }}>Failed to load trace.</p>
          <button onClick={() => void refetch()}>Retry</button>
        </div>
      )}

      {!isLoading && !isError && data && data.length === 0 && (
        <EmptyState
          title="No events recorded for this session"
          description="The agent ran but produced no governed actions in this session."
        />
      )}

      {!isLoading && !isError && data && data.length > 0 && (
        <>
          <TraceTimelineFilter value={filter} onChange={setFilter} />
          {filteredEvents.length === 0 ? (
            <div data-testid="trace-filter-empty">
              <EmptyState
                title="All events hidden by filter"
                description="Re-enable a severity above (or press Esc) to see events again."
              />
            </div>
          ) : (
            <TraceTimeline events={filteredEvents} />
          )}
        </>
      )}
    </main>
  )
}
