import type { ScrubPattern } from './types'
import './PatternDetail.css'

export interface PatternDetailProps {
  pattern: ScrubPattern
  collapsed: boolean
  onToggleCollapsed: () => void
}

export function PatternDetail({
  pattern,
  collapsed,
  onToggleCollapsed,
}: PatternDetailProps) {
  return (
    <section
      className="scrub-detail"
      aria-label="selected pattern detail"
      data-testid="scrub-detail"
      data-collapsed={collapsed}
    >
      <header className="scrub-detail-head">
        <div className="scrub-detail-headings">
          <div className="scrub-detail-eyebrow">selected pattern · {pattern.id}</div>
          <h3 className="scrub-detail-title">
            {pattern.name}
            <span
              className={`scrub-detail-sev scrub-detail-sev--${pattern.severity}`}
              data-testid="scrub-detail-sev"
            >
              ● {pattern.severity}
            </span>
          </h3>
        </div>
        <button
          type="button"
          className="scrub-detail-collapse-btn"
          onClick={onToggleCollapsed}
          aria-expanded={!collapsed}
          data-testid="scrub-detail-collapse"
        >
          {collapsed ? '+ expand' : '− collapse'}
        </button>
      </header>

      {!collapsed && (
        <div className="scrub-detail-grid" data-testid="scrub-detail-body">
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">regex</div>
            <code
              className="scrub-detail-code scrub-detail-code--regex"
              data-testid="scrub-detail-regex"
            >
              {pattern.regex}
            </code>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">example match</div>
            <code
              className="scrub-detail-code scrub-detail-code--example"
              data-testid="scrub-detail-example"
            >
              {pattern.example}
            </code>
          </div>
          <div className="scrub-detail-cell">
            <div className="scrub-detail-label">replaced with</div>
            <code
              className="scrub-detail-code scrub-detail-code--replace"
              data-testid="scrub-detail-replace"
            >
              {pattern.replace}
            </code>
          </div>
        </div>
      )}
    </section>
  )
}
