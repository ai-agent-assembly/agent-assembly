import type { TraceEvent, TraceSeverity } from '../../features/trace/types'

const ICON_BY_TYPE: Record<string, string> = {
  llm_call: '⌬',
  tool_call: '⌗',
  policy_violation: '⚠',
  credential_leak: '⚿',
}

function severityKey(event: TraceEvent): TraceSeverity | 'neutral' {
  return event.severity ?? 'neutral'
}

function formatTime(iso: string): string {
  return iso.replace('T', ' ').replace(/\.\d+Z$/, 'Z').replace(/Z$/, ' UTC')
}

export interface TraceTimelineProps {
  readonly events: readonly TraceEvent[]
}

export function TraceTimeline({ events }: TraceTimelineProps) {
  return (
    <ol className="trace-timeline" data-testid="trace-timeline">
      {events.map(event => {
        const sev = severityKey(event)
        const icon = ICON_BY_TYPE[event.type] ?? '·'
        return (
          <li
            key={event.id}
            className="trace-event"
            data-testid="trace-event"
            data-severity={sev}
            data-event-type={event.type}
          >
            <span className="trace-event__time">{formatTime(event.timestamp)}</span>
            <span className="trace-event__icon" aria-hidden="true">{icon}</span>
            <span className="trace-event__agent">{event.agent}</span>
            <span className="trace-event__preview">{event.payloadPreview}</span>
            <span className="trace-event__duration">{event.durationMs}&nbsp;ms</span>
          </li>
        )
      })}
    </ol>
  )
}
