import type React from 'react'
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
  readonly onSelectEvent?: (event: TraceEvent) => void
}

/**
 * Trace timeline rendered as a vertical sequence of step-cards
 * (AAASM-1391 — matches `design/v1/hi-fi/trace.jsx` `TraceStep`).
 *
 * Each step has a circular icon and a vertical connecting line on the
 * left (`.trace-event__rail`), and a 3-line body on the right
 * (`.trace-event__head` / `.__detail` / `.__meta`). The rail line is
 * omitted on the final event so the timeline visually terminates.
 */
export function TraceTimeline({ events, onSelectEvent }: TraceTimelineProps) {
  return (
    <ol className="trace-timeline" data-testid="trace-timeline">
      {events.map((event, index) => {
        const sev = severityKey(event)
        const icon = ICON_BY_TYPE[event.type] ?? '·'
        const tooltipReason =
          event.type === 'policy_violation' ? event.violationReason : undefined
        const iconNode = (
          <div className="trace-event__icon-circle" aria-hidden="true">{icon}</div>
        )
        const handleClick = onSelectEvent ? () => onSelectEvent(event) : undefined
        const handleKeyDown = onSelectEvent
          ? (e: React.KeyboardEvent<HTMLLIElement>) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onSelectEvent(event)
              }
            }
          : undefined
        const isLast = index === events.length - 1
        return (
          <li
            key={event.id}
            className={onSelectEvent ? 'trace-event trace-event--clickable' : 'trace-event'}
            data-testid="trace-event"
            data-severity={sev}
            data-event-type={event.type}
            role={onSelectEvent ? 'button' : undefined}
            tabIndex={onSelectEvent ? 0 : undefined}
            onClick={handleClick}
            onKeyDown={handleKeyDown}
          >
            <div className="trace-event__rail">
              {tooltipReason ? (
                <Tooltip content={tooltipReason}>{iconNode}</Tooltip>
              ) : (
                iconNode
              )}
              {!isLast && <div className="trace-event__rail-line" />}
            </div>
            <div className="trace-event__body">
              <div className="trace-event__head">
                <span className="trace-event__label">{event.type}</span>
                <span className="trace-event__time">{formatTime(event.timestamp)}</span>
                <span className="trace-event__duration">{event.durationMs}&nbsp;ms</span>
              </div>
              <div className="trace-event__detail">{truncatePreview(event.payloadPreview)}</div>
              <div className="trace-event__meta">{event.agent}</div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}
