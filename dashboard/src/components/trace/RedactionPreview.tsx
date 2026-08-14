import { useMemo, type ReactNode } from 'react'
import { isKnown, type Certain } from '../../lib/truthfulness'
import { AbsenceMarker } from '../truthfulness'
import { previewJson } from './previewJson'
import './RedactionPreview.css'

// Provably linear (no overlapping quantifiers): a single greedy `(.*)` to
// end-of-line absorbs the value, so there's no backtracking region. We never
// render the captured value for a redacted key — it is replaced with blocks —
// so the real value cannot leak. See typescript:S5852.
const KEY_LINE_RE = /^(\s*)"([^"]+)":(.*)$/

/** Block width is derived from the value length only (clamped), never its content. */
function blocksFor(rawValue: string): string {
  const trimmed = rawValue.trim().replace(/,$/, '').replace(/^"|"$/g, '')
  const width = Math.min(16, Math.max(6, trimmed.length))
  return '█'.repeat(width)
}

function renderLines(formatted: string, redactedSet: ReadonlySet<string>): ReactNode[] {
  return formatted.split('\n').map((line, i) => {
    const match = KEY_LINE_RE.exec(line)
    if (match && redactedSet.has(match[2])) {
      const [, indent, key, rawValue] = match
      const trailing = rawValue.trimEnd().endsWith(',') ? ',' : ''
      return (
        <div key={`${i}:${line}`} className="redaction-preview__line" data-testid="redaction-line">
          {indent}&quot;{key}&quot;:{' '}
          <span
            className="redaction-preview__block"
            data-testid="redaction-block"
            aria-label={`${key} redacted by policy`}
          >
            {blocksFor(rawValue)}
          </span>
          {trailing}
        </div>
      )
    }
    return (
      <div key={`${i}:${line}`} className="redaction-preview__line">
        {line}
      </div>
    )
  })
}

export interface RedactionPreviewProps {
  readonly payload: Certain<unknown>
  readonly redactedFields?: Certain<readonly string[]>
  /** Payload kind label shown in the section header (e.g. the event type). */
  readonly kind?: string
}

/**
 * Redaction-block payload preview (hi-fi `trace.jsx` `PayloadBlock`).
 *
 * Redacted field values render as `█` blocks (their real values are never
 * emitted to the DOM) and the redacted keys are listed as tags below;
 * non-redacted fields show their values so the preview is still a useful
 * payload view. ADR-0017 item 12 ratifies this *generic* block as authoritative
 * over the mock's per-type semantic templates — those would fabricate payload
 * content the backend does not emit — so the block stays type-agnostic.
 */
export function RedactionPreview({ payload, redactedFields, kind }: RedactionPreviewProps) {
  const redacted = useMemo(
    () => (redactedFields !== undefined && isKnown(redactedFields) ? redactedFields.value : []),
    [redactedFields],
  )
  const redactedSet = useMemo(() => new Set(redacted), [redacted])
  const formatted = useMemo(() => previewJson(payload), [payload])
  // Narrowed once, up front, so the absence branch keeps its `state` and
  // `detail` without a fallback that could never be reached.
  const absence = isKnown(formatted) ? null : formatted
  const lines = useMemo(
    () => (isKnown(formatted) ? renderLines(formatted.value, redactedSet) : null),
    [formatted, redactedSet],
  )

  return (
    <div className="redaction-preview" data-testid="redaction-preview">
      <div className="redaction-preview__eyebrow">
        payload preview{kind ? <span className="redaction-preview__kind"> · {kind}</span> : null}
      </div>
      {absence === null ? (
        <pre className="redaction-preview__body" data-testid="redaction-preview-body">
          {lines}
        </pre>
      ) : (
        <div
          className="redaction-preview__body redaction-preview__body--absent"
          data-testid="redaction-preview-body"
        >
          <AbsenceMarker
            state={absence.state}
            detail={absence.detail}
            showLabel
            testId="redaction-preview-absent"
          />
          <span className="redaction-preview__absent-caption">no payload recorded</span>
        </div>
      )}
      {redacted.length > 0 && (
        <div className="redaction-preview__tags" data-testid="redaction-tags">
          <span className="redaction-preview__tag redaction-preview__tag--label">redacted</span>
          {redacted.map(field => (
            <span key={field} className="redaction-preview__tag">
              {field}
            </span>
          ))}
        </div>
      )}
    </div>
  )
}
