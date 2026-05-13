import type { ValidationIssue, ValidationSeverity } from './types'
import { countBySeverity } from './validation'

interface ValidationPanelProps {
  issues: ValidationIssue[]
}

const BADGE_GLYPH: Record<ValidationSeverity, string> = {
  error: '✕',
  warn: '!',
  info: 'i',
}

/**
 * Renders the editor's validation summary: a count chip pair (errors,
 * warnings) and per-issue rows. When no issues are present, shows a single
 * "policy is valid · ready to simulate" success row.
 */
export function ValidationPanel({ issues }: ValidationPanelProps) {
  const { errors, warns } = countBySeverity(issues)

  return (
    <section className="editor__validation" data-testid="editor-validation">
      <header className="editor__validation-head">
        <span>Validation</span>
        <span
          className={
            errors > 0
              ? 'editor__validation-count editor__validation-count--error'
              : 'editor__validation-count'
          }
          data-testid="editor-validation-error-count"
        >
          {errors} errors
        </span>
        <span
          className={
            warns > 0
              ? 'editor__validation-count editor__validation-count--warn'
              : 'editor__validation-count'
          }
          data-testid="editor-validation-warn-count"
        >
          {warns} warnings
        </span>
      </header>

      {issues.length === 0 ? (
        <div
          className="editor__validation-row editor__validation-row--ok"
          data-testid="editor-validation-ok"
        >
          <span className="editor__validation-badge">✓</span>
          <span>policy is valid · ready to simulate</span>
        </div>
      ) : (
        issues.map((issue, idx) => (
          <div
            key={`${issue.rule}-${idx}`}
            className={`editor__validation-row editor__validation-row--${issue.severity}`}
            data-testid={`editor-validation-row-${idx}`}
          >
            <span className="editor__validation-badge">{BADGE_GLYPH[issue.severity]}</span>
            <span className="editor__validation-rule">{issue.rule}</span>
            <span>{issue.message}</span>
          </div>
        ))
      )}
    </section>
  )
}
