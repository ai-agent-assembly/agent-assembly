import { useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAgentQuery } from '../features/agents/api'
import { useTraceQuery } from '../features/trace/api'
import { TraceTimeline } from '../components/trace/TraceTimeline'
import { TraceTimelineFilter } from '../components/trace/TraceTimelineFilter'
import { ALL_ON, type SeverityFilter } from '../components/trace/severityFilter'
import { PayloadModal } from '../components/trace/PayloadModal'
import { EmptyState } from '../components/states'
import { downloadTraceJson } from '../features/trace/export'
import type { TraceEvent } from '../features/trace/types'
import './TraceViewPage.css'

function applyFilter(events: readonly TraceEvent[], filter: SeverityFilter): TraceEvent[] {
  return events.filter(event => {
    const key = event.severity ?? 'neutral'
    return filter[key]
  })
}

export interface TraceViewPageProps {
  /** Override URL params — used when rendered inside the trace drawer (AAASM-1340). */
  readonly agentId?: string
  readonly sessionId?: string
}

/**
 * Trace view page — header, status states (loading / error / empty / ready),
 * severity filter, and the trace timeline introduced in AAASM-1067.
 *
 * Accepts optional `agentId` / `sessionId` props so the same component can
 * render at the routed `/agents/:id/trace/:sessionId` URL *or* be mounted
 * directly inside the shell-level trace drawer with no URL change.
 */
export function TraceViewPage({ agentId, sessionId: sessionIdProp }: TraceViewPageProps = {}) {
  const params = useParams<{ id: string; sessionId: string }>()
  const id = agentId ?? params.id ?? ''
  const sessionId = sessionIdProp ?? params.sessionId ?? ''
  const { data: agent } = useAgentQuery(id)
  const { data, isLoading, isError, refetch } = useTraceQuery(id, sessionId)
  const agentLabel = agent?.name ?? id
  const [filter, setFilter] = useState<SeverityFilter>(ALL_ON)
  const [selectedEvent, setSelectedEvent] = useState<TraceEvent | null>(null)
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
          <div className="trace-toolbar" data-testid="trace-toolbar">
            <button
              type="button"
              data-testid="export-trace"
              onClick={() => downloadTraceJson(id, sessionId, data)}
            >
              Export
            </button>
          </div>
          <TraceTimelineFilter value={filter} onChange={setFilter} />
          {filteredEvents.length === 0 ? (
            <div data-testid="trace-filter-empty">
              <EmptyState
                title="All events hidden by filter"
                description="Re-enable a severity above (or press Esc) to see events again."
              />
            </div>
          ) : (
            <TraceTimeline events={filteredEvents} onSelectEvent={setSelectedEvent} />
          )}
        </>
      )}

      <PayloadModal event={selectedEvent} onClose={() => setSelectedEvent(null)} />
    </main>
  )
}
