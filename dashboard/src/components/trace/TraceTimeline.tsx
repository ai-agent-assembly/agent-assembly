import type { TraceEvent, TraceSeverity } from '../../features/trace/types'
import { Tooltip } from '../Tooltip'
import './TraceTimeline.css'

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

const MAX_PREVIEW_CHARS = 500

function truncatePreview(text: string): string {
  return text.length > MAX_PREVIEW_CHARS
    ? `${text.slice(0, MAX_PREVIEW_CHARS)}…`
    : text
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
        const tooltipReason =
          event.type === 'policy_violation' ? event.violationReason : undefined
        const iconNode = (
          <span className="trace-event__icon" aria-hidden="true">{icon}</span>
        )
        return (
          <li
            key={event.id}
            className="trace-event"
            data-testid="trace-event"
            data-severity={sev}
            data-event-type={event.type}
          >
            <span className="trace-event__time">{formatTime(event.timestamp)}</span>
            {tooltipReason ? (
              <Tooltip content={tooltipReason}>{iconNode}</Tooltip>
            ) : (
              iconNode
            )}
            <span className="trace-event__agent">{event.agent}</span>
            <span className="trace-event__preview">{truncatePreview(event.payloadPreview)}</span>
            <span className="trace-event__duration">{event.durationMs}&nbsp;ms</span>
          </li>
        )
      })}
    </ol>
  )
}
