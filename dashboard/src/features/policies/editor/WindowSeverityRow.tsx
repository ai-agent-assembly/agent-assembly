import { SEVERITY_OPTS, WINDOW_OPTS } from './constants'
import type { Severity, WindowKind } from './types'

interface WindowSeverityRowProps {
  window: WindowKind
  severity: Severity
  onWindowChange: (next: WindowKind) => void
  onSeverityChange: (next: Severity) => void
}

/**
 * Bottom row of each rule card: time window selector + severity pill group.
 */
export function WindowSeverityRow({
  window,
  severity,
  onWindowChange,
  onSeverityChange,
}: WindowSeverityRowProps) {
  return (
    <div className="editor__clause" data-testid="editor-window-severity">
      <span className="editor__clause-label">window</span>
      <select
        className="editor__select"
        aria-label="time window"
        value={window}
        onChange={(e) => onWindowChange(e.target.value as WindowKind)}
        data-testid="editor-window"
      >
        {WINDOW_OPTS.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>

      <span className="editor__clause-label">severity</span>
      <div className="editor__pill-group" role="radiogroup" aria-label="severity">
        {SEVERITY_OPTS.map((opt) => {
          const active = opt === severity
          return (
            <button
              key={opt}
              type="button"
              role="radio"
              aria-checked={active}
              className={
                active
                  ? `editor__pill editor__pill--${opt} editor__pill--active`
                  : `editor__pill editor__pill--${opt}`
              }
              data-testid={`editor-severity-${opt}`}
              onClick={() => onSeverityChange(opt)}
            >
              {opt}
            </button>
          )
        })}
      </div>
    </div>
  )
}
