import { useId } from 'react'
import './AutoScrollToggle.css'

interface AutoScrollToggleProps {
  /** When true, new ops pin to the top of the stream. */
  enabled: boolean
  /** Called with the next `enabled` value when the user flips the switch. */
  onEnabledChange: (next: boolean) => void
  /** Count of WS events buffered while the toggle was off. */
  pendingCount: number
  /** Flush the buffered events into the rendered stream. */
  onFlushPending: () => void
}

/**
 * Pure-presentation toggle for the Live Ops event-stream zone. When
 * `enabled` is true, the parent should pin incoming rows to the top
 * of the list; when false, the parent should buffer them into a
 * `pendingRows` array (kept off-screen) and surface the count here.
 *
 * Buffering + scroll-position preservation live on `LiveOpsPage`
 * (lands with the stream wiring in AAASM-1332); this component just
 * renders the control surface.
 */
export function AutoScrollToggle({
  enabled,
  onEnabledChange,
  pendingCount,
  onFlushPending,
}: AutoScrollToggleProps) {
  const inputId = useId()
  const showPending = !enabled && pendingCount > 0

  return (
    <div
      className="auto-scroll-toggle"
      data-testid="auto-scroll-toggle"
      data-enabled={enabled ? 'true' : 'false'}
    >
      <label className="auto-scroll-toggle__switch" htmlFor={inputId}>
        <input
          id={inputId}
          type="checkbox"
          className="auto-scroll-toggle__input"
          checked={enabled}
          onChange={(e) => onEnabledChange(e.target.checked)}
          data-testid="auto-scroll-toggle-input"
        />
        <span className="auto-scroll-toggle__track" aria-hidden="true">
          <span className="auto-scroll-toggle__thumb" />
        </span>
        <span className="auto-scroll-toggle__label">
          {enabled ? 'Auto-scroll' : 'Paused'}
        </span>
      </label>
      {showPending && (
        <button
          type="button"
          className="auto-scroll-toggle__pending"
          onClick={onFlushPending}
          data-testid="auto-scroll-flush"
        >
          {pendingCount} new {pendingCount === 1 ? 'op' : 'ops'} — flush
        </button>
      )}
    </div>
  )
}
